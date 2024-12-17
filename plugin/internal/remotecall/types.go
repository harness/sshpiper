package remotecall

import "github.com/golang-jwt/jwt"

type userKeyAuthRequest struct {
	AccountId    string       `json:"accountIdentifier"`
	SshKeyObject sshKeyObject `json:"sshKeyObject"`
}

type sshKeyObject struct {
	Key       []byte `json:"key"`
	Algorithm string `json:"algorithm"`
}

type PrincipalType string

const PrincipalTypeService PrincipalType = "SERVICE"

type UserKeyAuthResponse struct {
	Data   Data   `json:"data"`
	Status string `json:"status"`
}

type Data struct {
	UUID string `json:"uuid"`
}

type UserClusterResponse struct {
	ClusterName string `json:"clusterName"`
}

type JWTClaims struct {
	jwt.StandardClaims

	// Common claims
	Type PrincipalType `json:"type,omitempty"`
	Name string        `json:"name,omitempty"`

	// Used only by user / service account
	Email     string `json:"email,omitempty"`
	UserName  string `json:"username,omitempty"`
	AccountID string `json:"accountId,omitempty"`
}
