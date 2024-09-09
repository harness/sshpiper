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
	UserAgentKey          = "User-Agent"
	UserAgentSSHGateway   = "SSH-gateway"
	AcceptKey             = "Accept"
	AcceptApplicationJson = "application/json"
)

type RemoteCall struct {
	userClusterNameURL                    string
	clusterNameInClusterAuthenticatorURL  map[string]*url.URL
	clusterNameInClusterServiceClusterURL map[string]*url.URL

	mappingKeyFile []byte

	httpClient *http.Client
}

func InitRemoteCall(
	userClusterNameURL string,
	clusterNameInClusterAuthenticatorURL map[string]string,
	clusterNameInClusterServiceClusterURL map[string]string,
	mappingKeyPath string,
) (*RemoteCall, error) {
	clusterNameInClusterAuthenticatorURLParsed := make(map[string]*url.URL, len(clusterNameInClusterAuthenticatorURL))

	for clusterName, clusterURL := range clusterNameInClusterAuthenticatorURL {
		clusterURLParsed, err := url.Parse(clusterURL)
		if err != nil {
			return nil, fmt.Errorf("error parsing URL %q: %w", clusterURL, err)
		}
		clusterNameInClusterAuthenticatorURLParsed[clusterName] = clusterURLParsed
	}

	clusterNameInClusterServiceURLParsed := make(map[string]*url.URL, len(clusterNameInClusterServiceClusterURL))

	for clusterName, inServiceURL := range clusterNameInClusterServiceClusterURL {
		clusterURLParsed, err := url.Parse(inServiceURL)
		if err != nil {
			return nil, fmt.Errorf("error parsing in cluster service URL %q: %w", inServiceURL, err)
		}
		clusterNameInClusterServiceURLParsed[clusterName] = clusterURLParsed
	}

	key, err := os.ReadFile(mappingKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error reading mapping key: %w", err)
	}

	return &RemoteCall{
		userClusterNameURL:                    userClusterNameURL,
		clusterNameInClusterAuthenticatorURL:  clusterNameInClusterAuthenticatorURLParsed,
		httpClient:                            createHttpClient(),
		mappingKeyFile:                        key,
		clusterNameInClusterServiceClusterURL: clusterNameInClusterServiceURLParsed,
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
	req, err := http.NewRequest("GET", fmt.Sprintf(r.userClusterNameURL, username), nil)
	if err != nil {
		return "", fmt.Errorf("error creating request: %w", err)
	}

	// Set custom headers if needed
	req.Header.Set(UserAgentKey, UserAgentSSHGateway)
	req.Header.Set(AcceptKey, AcceptApplicationJson)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making request: %w", err)
	}
	if resp != nil && resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error: status code: %d", resp.StatusCode)
	}

	clusterName, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %w", err)
	}

	// json parsing
	return string(clusterName), nil
}

// todo: refactor once we have user info in directory svc

func (r *RemoteCall) AuthenticateKey(key []byte, clusterURL string) (*UserKeyAuthResponse, error) {
	auth := userKeyAuthRequest{Key: key}
	body, err := json.Marshal(auth)
	if err != nil {
		return nil, fmt.Errorf("error marshalling auth: %v", auth)
	}

	req, err := http.NewRequest("GET", clusterURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set(UserAgentKey, UserAgentSSHGateway)
	req.Header.Set(AcceptKey, AcceptApplicationJson)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	if resp != nil && resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error: status code: %d", resp.StatusCode)
	}

	authResponse := UserKeyAuthResponse{}
	err = json.NewDecoder(resp.Body).Decode(&authResponse)
	if err != nil {
		return nil, fmt.Errorf("error marshalling response body: %w", err)
	}

	return &authResponse, nil
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

func (r *RemoteCall) GetUpstreamSvcURL(clusterName string) (string, error) {
	clusterURL, ok := r.clusterNameInClusterServiceClusterURL[clusterName]
	if !ok {
		return "", fmt.Errorf("unknown upstream cluster %q", clusterName)
	}
	return clusterURL.String(), nil
}
