package remotecall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	UserAgentKey        = "User-Agent"
	UserAgentSSHGateway = "SSH-gateway"
	AcceptKey           = "Accept"
	ContentType         = "Content-Type"
	ApplicationJson     = "application/json"

	AuthTokenUserClusterMapping = "authToken"
	AuthKeyAuthenticator        = "Authorization"
	IdentitySSHGateway          = "SSH-gateway"
	JwtValidity                 = 5 * time.Second
)

type RemoteCall struct {
	userClusterNameURL *url.URL
	userClusterToken   string

	clusterNameInClusterAuthenticatorURL map[string]*url.URL
	serviceJwtProvider                   map[string]*ServiceJWTProvider

	// keeping it string since these won't have http
	clusterNameInClusterServiceClusterURL map[string]string

	mappingKeyFile []byte

	httpClient *http.Client
}

func InitRemoteCall(
	userClusterNameURL string,
	userClusterToken string,
	clusterNameInClusterAuthenticatorURL map[string]string,
	serviceJwtToken map[string]string,
	clusterNameInClusterServiceClusterURL map[string]string,
	mappingKeyPath string,
) (*RemoteCall, error) {
	userClusterNameURLParsed, err := url.Parse(userClusterNameURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing userClusterNameURL %q: %w", userClusterNameURL, err)
	}

	clusterNameInClusterAuthenticatorURLParsed := make(map[string]*url.URL, len(clusterNameInClusterAuthenticatorURL))

	for clusterName, clusterURL := range clusterNameInClusterAuthenticatorURL {
		clusterURLParsed, err := url.Parse(clusterURL)
		if err != nil {
			return nil, fmt.Errorf("error parsing URL %q: %w", clusterURL, err)
		}
		clusterNameInClusterAuthenticatorURLParsed[clusterName] = clusterURLParsed
	}

	jwtProviders := make(map[string]*ServiceJWTProvider, len(serviceJwtToken))
	for clusterName, secret := range serviceJwtToken {
		serviceJWTProvider, err := NewServiceJWTProvider(IdentitySSHGateway, []byte(secret), JwtValidity)
		if err != nil {
			return nil, fmt.Errorf("error creating jwt provider: %w", err)
		}
		jwtProviders[clusterName] = serviceJWTProvider
	}

	key, err := os.ReadFile(mappingKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error reading mapping key: %w", err)
	}

	return &RemoteCall{
		userClusterNameURL:                    userClusterNameURLParsed,
		userClusterToken:                      userClusterToken,
		clusterNameInClusterAuthenticatorURL:  clusterNameInClusterAuthenticatorURLParsed,
		serviceJwtProvider:                    jwtProviders,
		httpClient:                            createHttpClient(),
		mappingKeyFile:                        key,
		clusterNameInClusterServiceClusterURL: clusterNameInClusterServiceClusterURL,
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

func (r *RemoteCall) GetClusterName(username string) (string, error) {
	if username == "" {
		return "", fmt.Errorf("empty username")
	}
	req, err := http.NewRequest("GET", r.userClusterNameURL.JoinPath(username).String(), nil)
	if err != nil {
		return "", fmt.Errorf("error creating request for getting cluster name with url: %q and username:"+
			" %q :%w", r.userClusterNameURL, username, err)
	}

	// Set custom headers if needed
	req.Header.Set(UserAgentKey, UserAgentSSHGateway)
	req.Header.Set(AcceptKey, ApplicationJson)
	req.Header.Set(ContentType, ApplicationJson)
	req.Header.Set(AuthTokenUserClusterMapping, r.userClusterToken)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making request: %w", err)
	}
	if resp != nil && resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Error reading response body:", err)
			return "", fmt.Errorf("error reading response body during GetClusterName: %w", err)
		}
		return "", fmt.Errorf("error: status code for url: %s, error: %q: %d", req.URL.String(), bodyBytes,
			resp.StatusCode)
	}

	userClusterResponse := UserClusterResponse{}
	err = json.NewDecoder(resp.Body).Decode(&userClusterResponse)
	if err != nil {
		return "", fmt.Errorf("error reading response body for GetClusterName: %w", err)
	}

	return userClusterResponse.ClusterName, nil
}

// todo: refactor once we have user info in directory svc

func (r *RemoteCall) AuthenticateKey(
	key []byte,
	keyType string,
	clusterURL string,
	token string,
	accountId string,
) (*UserKeyAuthResponse, error) {
	auth := userKeyAuthRequest{Key: key, KeyType: keyType, AccountId: accountId}
	body, err := json.Marshal(auth)
	if err != nil {
		return nil, fmt.Errorf("error marshalling auth: %v", auth)
	}

	req, err := http.NewRequest("POST", clusterURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("error creating request for auth: %w", err)
	}

	req.Header.Set(UserAgentKey, UserAgentSSHGateway)
	req.Header.Set(AcceptKey, ApplicationJson)
	req.Header.Set(ContentType, ApplicationJson)
	req.Header.Set(AuthKeyAuthenticator, token)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request for url: %s: %w", req.URL.String(), err)
	}
	if resp != nil && resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Error reading response body:", err)
			return nil, fmt.Errorf("error reading response body during authentication: %w", err)
		}
		return nil, fmt.Errorf("error: status code: %d: body: %q", resp.StatusCode, bodyBytes)
	}

	authResponse := &UserKeyAuthResponse{}
	err = json.NewDecoder(resp.Body).Decode(authResponse)
	if err != nil {
		return nil, fmt.Errorf("error marshalling response body: %w", err)
	}

	return authResponse, nil
}

func (r *RemoteCall) MapKey() []byte {
	return r.mappingKeyFile
}

func (r *RemoteCall) GetUpstreamAuthenticatorURL(clusterName string) (string, error) {
	clusterURL, ok := r.clusterNameInClusterAuthenticatorURL[clusterName]
	if !ok {
		return "", fmt.Errorf("unknown cluster %q", clusterName)
	}
	return clusterURL.String(), nil
}

func (r *RemoteCall) GetUpstreamAuthenticatorAuthToken(clusterName string) (string, error) {
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
	clusterURL, ok := r.clusterNameInClusterServiceClusterURL[clusterName]
	if !ok {
		return "", fmt.Errorf("unknown upstream cluster %q", clusterName)
	}
	return clusterURL, nil
}
