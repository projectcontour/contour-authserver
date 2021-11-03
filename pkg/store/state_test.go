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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHtpasswdAuth(t *testing.T) {
	state := NewState()
	// test binary generation

	// Make sure AuthState is empty
	assert.Equal(t, false, len(state.OAuthState) > 0)

	state.GenerateOauthState()
	assert.Equal(t, true, len(state.OAuthState) > 0)
	assert.Equal(t, true, state.IsNewToken())

	state.Status = StatusTokenReady
	assert.Equal(t, true, state.IsTokenReady())
}
