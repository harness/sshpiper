package remotecall

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	UserAgent           = "User-Agent"
	UserAgentSSHGateway = "SSH-Gateway"
	Accept              = "Accept"
	ContentType         = "Content-Type"
	ApplicationJson     = "application/json"

	AuthTokenUserClusterMapping = "authToken"
	Authorization               = "Authorization"
	IdentitySSHGateway          = "SSH-gateway"
	JwtValidity                 = 5 * time.Second
)

type RemoteCall struct {
	userClusterNameURL     *url.URL
	userClusterToken       string
	userClusterURLIsSocket bool

	clusterNameToAuthenticatorURL map[string]*url.URL
	serviceJwtProvider            map[string]*ServiceJWTProvider

	// keeping it string since these won't have http
	clusterNameToUpstreamURL map[string]string

	mappingKeyFileData []byte

	httpClient       *http.Client
	socketHttpClient *http.Client
}

func InitRemoteCall(
	userClusterNameURL string,
	userClusterToken string,
	userClusterNameURLSocketPath string,
	clusterNameToAuthenticatorURL map[string]string,
	serviceJwtToken map[string]string,
	clusterNameToUpstreamURL map[string]string,
	mappingKeyPath string,
) (*RemoteCall, error) {
	userClusterNameURLParsed, err := url.Parse(userClusterNameURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing userClusterNameURL %q: %w", userClusterNameURL, err)
	}

	var socketHttpClient *http.Client
	userClusterURLIsSocket := false

	if userClusterNameURLSocketPath != "" {
		userClusterURLIsSocket = true
		socketHttpClient = createSocketHttpClient(userClusterNameURLSocketPath)
	}

	clusterNameToAuthenticatorURLParsed := make(map[string]*url.URL, len(clusterNameToAuthenticatorURL))

	for clusterName, clusterURL := range clusterNameToAuthenticatorURL {
		clusterURLParsed, err := url.Parse(clusterURL)
		if err != nil {
			return nil, fmt.Errorf("error parsing URL %q: %w", clusterURL, err)
		}
		clusterNameToAuthenticatorURLParsed[clusterName] = clusterURLParsed
	}

	jwtProviders := make(map[string]*ServiceJWTProvider, len(serviceJwtToken))
	for clusterName, secret := range serviceJwtToken {
		serviceJWTProvider, err := NewServiceJWTProvider(IdentitySSHGateway, []byte(secret), JwtValidity)
		if err != nil {
			return nil, fmt.Errorf("error creating jwt provider: %w", err)
		}
		jwtProviders[clusterName] = serviceJWTProvider
	}

	encodedData, err := os.ReadFile(mappingKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error reading mapping file: %w", err)
	}

	// Decode the base64 encoded data
	decodedData, err := base64.StdEncoding.DecodeString(string(encodedData))
	if err != nil {
		return nil, fmt.Errorf("error decoding base64: %w", err)
	}

	log.Debugf("mapping key file data %q", decodedData)

	return &RemoteCall{
		userClusterNameURL:            userClusterNameURLParsed,
		userClusterToken:              userClusterToken,
		userClusterURLIsSocket:        userClusterURLIsSocket,
		clusterNameToAuthenticatorURL: clusterNameToAuthenticatorURLParsed,
		serviceJwtProvider:            jwtProviders,
		httpClient:                    createHttpClient(),
		mappingKeyFileData:            decodedData,
		clusterNameToUpstreamURL:      clusterNameToUpstreamURL,
		socketHttpClient:              socketHttpClient,
	}, nil
}

func createHttpClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:    10,
			IdleConnTimeout: 30 * time.Second,
		},
	}
}

func createSocketHttpClient(socketPath string) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:    10,
			IdleConnTimeout: 30 * time.Second,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}
}

func (r *RemoteCall) GetClusterName(username string) (string, error) {
	if username == "" {
		return "", fmt.Errorf("empty username")
	}
	req, err := http.NewRequest("GET", r.userClusterNameURL.JoinPath(username).String(), nil)
	if err != nil {
		return "", fmt.Errorf("error creating request for getting cluster name with url: %q and username:"+
			" %q :%w", r.userClusterNameURL, username, err)
	}

	req.Header.Set(AuthTokenUserClusterMapping, r.userClusterToken)
	userClusterResponse := UserClusterResponse{}
	httpClient := r.httpClient
	if r.userClusterURLIsSocket == true {
		httpClient = r.socketHttpClient
	}
	err = r.performHttpRequest(req, httpClient, &userClusterResponse)
	if err != nil {
		return "", fmt.Errorf("error doing http call for GetClusterName: %w", err)
	}
	return userClusterResponse.ClusterName, nil
}

func (r *RemoteCall) performHttpRequest(req *http.Request, httpClient *http.Client, response any) error {
	// Set custom headers if needed
	req.Header.Set(UserAgent, UserAgentSSHGateway)
	req.Header.Set(Accept, ApplicationJson)
	req.Header.Set(ContentType, ApplicationJson)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error making request: %w", err)
	}
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("error reading response body : %w", err)
		}
		return fmt.Errorf("error: status code for url: %s, error: %q: %d", req.URL.String(), bodyBytes,
			resp.StatusCode)
	}
	err = json.NewDecoder(resp.Body).Decode(response)
	if err != nil {
		return fmt.Errorf("error reading response body for GetClusterName: %w", err)
	}

	return nil
}

// todo: refactor once we have user info in directory svc

func (r *RemoteCall) AuthenticateKey(
	key []byte,
	_ string,
	clusterURL string,
	clusterName string,
	accountId string,
) (*UserKeyAuthResponse, error) {
	token, err := r.getUpstreamAuthenticatorAuthToken(clusterName)
	if err != nil {
		return nil, fmt.Errorf("error getting authenticator token from cluster name: %w", err)
	}

	// Parse the SSH wire format public key
	pubKey, err := ssh.ParsePublicKey(key)
	if err != nil {
		log.Fatalf("Failed to parse public key: %v", err)
		return nil, fmt.Errorf("error parsing public key: %w", err)
	}

	// Convert it to OpenSSH format
	plainKey := ssh.MarshalAuthorizedKey(pubKey)

	k := strings.Split(string(plainKey), " ")
	if len(k) != 2 {
		return nil, fmt.Errorf("error parsing public key")
	}

	auth := userKeyAuthRequest{
		AccountId: accountId,
		SshKeyObject: sshKeyObject{
			Key:       strings.TrimSuffix(k[1], "\n"),
			Algorithm: k[0],
		},
	}

	body, err := json.Marshal(auth)
	if err != nil {
		return nil, fmt.Errorf("error marshalling auth: %v", auth)
	}

	req, err := http.NewRequest("POST", clusterURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("error creating request for auth: %w", err)
	}

	req.Header.Set(Authorization, token)
	authResponse := &UserKeyAuthResponse{}

	err = r.performHttpRequest(req, r.httpClient, &authResponse)
	if err != nil {
		return nil, fmt.Errorf("error performing http request for AuthenticateKey: %w", err)
	}

	return authResponse, nil
}

func (r *RemoteCall) MapKey() []byte {
	return r.mappingKeyFileData
}

func (r *RemoteCall) GetUpstreamAuthenticatorURL(clusterName string) (string, error) {
	clusterURL, ok := r.clusterNameToAuthenticatorURL[clusterName]
	if !ok {
		return "", fmt.Errorf("unknown cluster %q", clusterName)
	}
	return clusterURL.String(), nil
}

func (r *RemoteCall) getUpstreamAuthenticatorAuthToken(clusterName string) (string, error) {
	jwtProvider, ok := r.serviceJwtProvider[clusterName]
	if !ok {
		return "", fmt.Errorf("unknown cluster for jwt token %q", clusterName)
	}
	jwt, err := jwtProvider.GetJWT()
	if err != nil {
		return "", fmt.Errorf("error getting jwt token for cluster %q: %w", clusterName, err)
	}
	return jwt, nil
}

func (r *RemoteCall) GetUpstreamSvcURL(clusterName string) (string, error) {
	clusterURL, ok := r.clusterNameToUpstreamURL[clusterName]
	if !ok {
		return "", fmt.Errorf("unknown upstream cluster %q", clusterName)
	}
	return clusterURL, nil
}
