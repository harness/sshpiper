package remotecall

type userKeyAuthRequest struct {
	Key       []byte `json:"key"`
	AccountId string `json:"accountIdentifier"`
}

type PrincipalType string

type UserKeyAuthResponse struct {
	UUID string `json:"uuid"`
}
