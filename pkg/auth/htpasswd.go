package auth

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/go-logr/logr"
	"github.com/tg123/go-htpasswd"
	v1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// LabelAuthType labels Secrets that can be used for basic Auth.
	LabelAuthType = "projectcontour.io/auth-type"
	// LabelAuthRealm labels Secrets that match our authentication realm
	LabelAuthRealm = "projectcontour.io/auth-realm"
)

// Htpasswd watches Secrets for htpasswd files and uses them for HTTP Basic Authentication.
type Htpasswd struct {
	Log       logr.Logger
	Realm     string
	Client    client.Client
	Passwords *htpasswd.File

	Lock sync.Mutex
}

var _ Checker = &Htpasswd{}

// Set set the htpasswd file to use.
func (h *Htpasswd) Set(passwd *htpasswd.File) {
	h.Lock.Lock()
	defer h.Lock.Unlock()

	h.Passwords = passwd
}

// Match authenticates the credential against the htpasswd file.
func (h *Htpasswd) Match(user string, pass string) bool {
	var passwd *htpasswd.File

	// Arguably, getting and setting the pointer is atomic, but
	// Go doesn't make any guarantees.
	h.Lock.Lock()
	passwd = h.Passwords
	h.Lock.Unlock()

	if passwd != nil {
		// htpasswd.File locks internally, so all Match
		// calls will be serialized.
		return passwd.Match(user, pass)
	}

	return false
}

// Check ...
func (h *Htpasswd) Check(ctx context.Context, request *Request) (*Response, error) {
	h.Log.Info("checking request",
		"host", request.Request.Host,
		"path", request.Request.URL.Path,
		"id", request.ID,
	)

	user, pass, ok := request.Request.BasicAuth()

	// If there's an "Authorization" header and we can verify
	// it, succeed and inject some headers to tell the origin
	//what  we did.
	if ok && h.Match(user, pass) {
		// TODO(jpeach) inject context attributes into the headers.
		authorized := http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Auth-Handler":  {"htpasswd"},
				"Auth-Username": {user},
				"Auth-Realm":    {h.Realm},
			},
		}

		// Reflect the authorization check context into the response headers.
		for k, v := range request.Context {
			key := fmt.Sprintf("Auth-Context-%s", k)
			key = http.CanonicalHeaderKey(key) // XXX(jpeach) this will not transform invalid characters

			authorized.Header.Add(key, v)
		}

		return &Response{
			Allow:    true,
			Response: authorized,
		}, nil
	}

	// If there's no "Authorization" header, or the authentication
	// failed, send an authenticate request.
	return &Response{
		Allow: false,
		Response: http.Response{
			StatusCode: http.StatusUnauthorized,
			Header: http.Header{
				"WWW-Authenticate": {fmt.Sprintf(`Basic realm="%s", charset="UTF-8"`, h.Realm)},
			},
		},
	}, nil
}

// Reconcile ...
func (h *Htpasswd) Reconcile(ctrl.Request) (ctrl.Result, error) {
	// First, find all the basic auth secrets for this realm.
	secrets := &v1.SecretList{}
	if err := h.Client.List(context.Background(), secrets,
		client.MatchingLabels{LabelAuthType: "basic"},
		client.HasLabels{LabelAuthRealm}); err != nil {
		return ctrl.Result{}, err
	}

	passwdData := bytes.Buffer{}

	for _, s := range secrets.Items {
		if s.Labels[LabelAuthRealm] != h.Realm &&
			s.Labels[LabelAuthRealm] != "*" {
			continue
		}

		// Check for the "auth" key, which is the format used by ingress-nginx.
		authData, ok := s.Data["auth"]
		if !ok {
			h.Log.Info("skipping Secret without \"auth\" key",
				"name", s.Name, "namespace", s.Namespace)
			continue
		}

		// Do a pre-parse so that we can accept or reject whole Secrets.
		hasBadLine := false

		if _, err := htpasswd.NewFromReader(
			bytes.NewBuffer(authData),
			htpasswd.DefaultSystems,
			htpasswd.BadLineHandler(func(err error) {
				hasBadLine = true
				h.Log.Error(err, "skipping malformed Secret",
					"name", s.Name, "namespace", s.Namespace)
			}),
		); err != nil {
			h.Log.Error(err, "skipping malformed Secret",
				"name", s.Name, "namespace", s.Namespace)
		}

		if hasBadLine {
			continue
		}

		// This Secret seems OK, so accumulate it's content.
		passwdData.WriteByte('\n')
		passwdData.Write(authData)
	}

	newPasswd, err := htpasswd.NewFromReader(&passwdData, htpasswd.DefaultSystems,
		htpasswd.BadLineHandler(func(err error) {
			panic(fmt.Sprintf("failed to parse valid htpasswd: %s", err))
		}))
	if err != nil {
		h.Log.Error(err, "generated malformed htpasswd data")
		return ctrl.Result{}, nil
	}

	h.Set(newPasswd)

	return ctrl.Result{}, nil
}

// RegisterWithManager ...
func (h *Htpasswd) RegisterWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.Secret{}).
		Complete(h)
}
