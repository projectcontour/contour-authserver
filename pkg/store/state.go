// Copyright Project Contour Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package store

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// OIDCState defines the values kept in state.
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

// Iota token.
const (
	StatusNeedToken = iota
	StatusTokenReady
)

// NewState  create new state to store token for OIDC.
func NewState() *OIDCState {
	state := &OIDCState{
		Status: StatusNeedToken,
	}

	return state
}

// ConvertToByte  Convert State to Byte.
func ConvertToByte(s *OIDCState) []byte {
	b, _ := json.Marshal(s)
	return b
}

// ConvertToType Convert Byte to State.
func ConvertToType(value []byte) *OIDCState {
	state := &OIDCState{}
	if err := json.Unmarshal(value, &state); err != nil {
		fmt.Println(fmt.Errorf("could not unmarshal %v: ", err))
	}

	return state
}

// IsNewToken check if current state is new and token from idp is needed.
func (s *OIDCState) IsNewToken() bool {
	return s.Status == StatusNeedToken
}

// IsTokenReady check if token is ready.
func (s *OIDCState) IsTokenReady() bool {
	return s.Status == StatusTokenReady
}

// GenerateOauthState generates a new Oauth State from random bytes. The state define a unique request
// from a particular user and used to identity user during callback or subsequent calls.
func (s *OIDCState) GenerateOauthState() string {
	b := make([]byte, 32)

	_, err := rand.Read(b)
	if err != nil {
		fmt.Println(fmt.Errorf("error reading random bytes generating OauthState: %v", err))
	}

	newState := base64.URLEncoding.EncodeToString(b)
	s.OAuthState = newState

	return newState
}
