package auth

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func TestHtpasswdAuth(t *testing.T) {
	client := fake.NewFakeClient(
		&v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "example1",
				Namespace: metav1.NamespaceDefault,
				Labels: map[string]string{
					LabelAuthType:  "basic",
					LabelAuthRealm: "*",
				},
			},
			Type: v1.SecretTypeOpaque,
			Data: map[string][]byte{
				// user=example1, pass=example1
				"auth": []byte("example1:$apr1$WBCC5B.w$fUu8qiKG/rLdMs3OTy9gc0"),
			},
		},

		&v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "example2",
				Namespace: metav1.NamespaceDefault,
				Labels: map[string]string{
					LabelAuthType:  "basic",
					LabelAuthRealm: "*",
				},
			},
			Type: v1.SecretTypeOpaque,
			Data: map[string][]byte{
				// user=example2, pass=example2
				"auth": []byte("example2:$apr1$tVsjy2r7$67D.nLwdd6EKKQR5z3lJS0"),
			},
		},
		&v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "example3",
				Namespace: metav1.NamespaceDefault,
				Labels: map[string]string{
					LabelAuthType:  "basic",
					LabelAuthRealm: "example3",
				},
			},
			Type: v1.SecretTypeOpaque,
			Data: map[string][]byte{
				// user=example3, pass=example3
				"auth": []byte("example3:$apr1$.J8./QLE$ZMhl6Sla1NIdu.32RZSOC/"),
			},
		},
	)

	auth := Htpasswd{
		Log:       log.NullLogger{},
		Realm:     "default",
		Client:    client,
		Passwords: nil,
	}

	_, err := auth.Reconcile(ctrl.Request{})
	assert.NoError(t, err, "reconciliation should not have failed")
	assert.NotNil(t, auth.Passwords, "reconciliation should have set a htpasswd file")
	assert.True(t, auth.Match("example1", "example1"), "auth for example1:example1 should have succeeded")
	assert.True(t, auth.Match("example2", "example2"), "auth for example2:example2 should have succeeded")
	assert.False(t, auth.Match("example3", "example3"), "auth for example3:example3 should have failed (wrong realm)")

	// Check an unauthorized response.
	response, err := auth.Check(context.TODO(), &Request{
		Request: http.Request{
			Header: http.Header{},
			URL:    &url.URL{},
		},
	})
	require.NoError(t, err, "check should not have failed")
	assert.Equal(t, http.StatusUnauthorized, response.Response.StatusCode)
	// Note that this isn't canonical as per CanonicalMIMEHeaderKey :-(
	assert.NotEmpty(t, response.Response.Header["WWW-Authenticate"]) //nolint(staticcheck)

	// Check an authorized response.
	response, err = auth.Check(context.TODO(), &Request{
		Request: http.Request{
			Header: http.Header{
				"Authorization": {"Basic ZXhhbXBsZTE6ZXhhbXBsZTE="},
			},
			URL: &url.URL{},
		},
		Context: map[string]string{
			"key1": "value1",
		},
	})
	require.NoError(t, err, "check should not have failed")
	assert.Equal(t, http.StatusOK, response.Response.StatusCode)
	assert.Equal(t, "example1", response.Response.Header.Get("Auth-Username"))
	assert.Equal(t, "default", response.Response.Header.Get("Auth-Realm"))
	assert.Equal(t, "value1", response.Response.Header.Get("Auth-Context-Key1"))
}
