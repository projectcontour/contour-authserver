package store

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
)

type OIDCState struct {
	Status       int    `json:"status"`
	AccessToken  string `json:"access-token"`
	IDToken      string `json:"id-token"`
	RefreshToken string `json:"refresh-token"`

	RequestID   string `json:"req-id"`
	RequestPath string `json:"req-path"`
	OAuthState  string `json:"oauth-state"`
	Scheme      string `json:"scheme"`
}

// Iota token
const (
	StatusNeedToken = iota
	StatusTokenReady
)

// NewState .... create new state to store token for OIDC
func NewState() *OIDCState {

	state := &OIDCState{
		Status: StatusNeedToken,
	}

	return state
}

// ConvertToByte ... Convert State to Byte
func ConvertToByte(s *OIDCState) []byte {
	b, _ := json.Marshal(s)
	return b
}

// ConvertToType ... Convert Byte to State
func ConvertToType(value []byte) *OIDCState {
	state := &OIDCState{}
	json.Unmarshal(value, &state)

	return state
}

// IsNewToken ...
func (s *OIDCState) IsNewToken() bool {
	return (s.Status == StatusNeedToken)
}

// IsTokenReady ...
func (s *OIDCState) IsTokenReady() bool {
	return (s.Status == StatusTokenReady)
}

// GenerateOauthState ... Generate new Oauth State
func (s *OIDCState) GenerateOauthState() string {

	b := make([]byte, 32)
	rand.Read(b)
	newState := base64.URLEncoding.EncodeToString(b)
	s.OAuthState = newState

	return newState
}
