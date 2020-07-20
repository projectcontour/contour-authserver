package store

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
)

type OidcState struct {
	Status       int    `json:"status"`
	AccessToken  string `json:"access-token"`
	IDToken      string `json:"id-token"`
	RefreshToken string `json:"refresh-token"`

	RequestID   string `json:"req-id"`
	RequestPath string `json:"req-path"`
	OAuthState  string `json:"oauth-state"`
}

const (
	statusNeedToken  = iota
	statusTokenReady = iota
)

// NewState .... create new state to store token for OIDC
func NewState() *OidcState {

	state := &OidcState{
		Status: statusNeedToken,
	}

	return state
}

func ConvertToByte(s *OidcState) []byte {
	b, _ := json.Marshal(s)
	return b
}

func ConvertToType(value []byte) *OidcState {
	state := &OidcState{}
	json.Unmarshal(value, &state)

	return state
}

func (s *OidcState) IsNewToken() bool {
	return (s.Status == statusNeedToken)
}

func (s *OidcState) IsTokenReady() bool {
	return (s.Status == statusTokenReady)
}

// Generate new Oauth State
func (s *OidcState) GenerateOauthState() string {

	b := make([]byte, 32)
	rand.Read(b)
	newState := base64.StdEncoding.EncodeToString(b)
	s.OAuthState = newState

	return newState
}
