package store

import (
	"testing"

	"gotest.tools/assert"
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
