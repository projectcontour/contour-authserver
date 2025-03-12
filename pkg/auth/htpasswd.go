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

package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	"github.com/tg123/go-htpasswd"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// AnnotationAuthType labels Secrets that can be used for basic Auth.
	AnnotationAuthType = "projectcontour.io/auth-type"
	// AnnotationAuthRealm labels Secrets that match our authentication realm.
	AnnotationAuthRealm = "projectcontour.io/auth-realm"
)

// Htpasswd watches Secrets for htpasswd files and uses them for HTTP Basic Authentication.
type Htpasswd struct {
	Log       logr.Logger
	Realm     string
	Client    client.Client
	Passwords *htpasswd.File
	Selector  labels.Selector
	LoginPath string
	Lock      sync.Mutex
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

	h.Log.Info("request", "request", request.Request)
	user, pass, ok := request.Request.BasicAuth()

	if !ok {
		h.Log.Info("no basic auth header")
		// Try to get credentials from cookie if basic auth header not present
		if cookie, err := request.Request.Cookie("basic-auth"); err == nil {
			h.Log.Info("cookie", "cookie", cookie)
			if decoded, err := base64.StdEncoding.DecodeString(cookie.Value); err == nil {
				parts := strings.Split(string(decoded), ":")
				if len(parts) == 2 {
					user = parts[0]
					pass = parts[1]
					ok = true
				}
			}
		}
	}
	h.Log.Info("user", "user", user)
	h.Log.Info("pass", "pass", pass)
	h.Log.Info("ok", "ok", ok)
	// If there's an "Authorization" header and we can verify
	// it, succeed and inject some headers to tell the origin
	//what  we did.
	if ok && h.Match(user, pass) {
		h.Log.Info("match")
		// TODO(jpeach) inject context attributes into the headers.
		authorized := http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Auth-Handler":  {"htpasswd"},
				"Auth-Username": {user},
				"Auth-Realm":    {h.Realm},
			},
		}
		h.Log.Info("authorized", "authorized", authorized)

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

	url := parseURL(request)
	h.Log.Info("url", "url", url)
	h.Log.Info("login path", "login path", h.LoginPath, "url path", url.Path)
	// Check if the current request matches the callback path.
	if url.Path == h.LoginPath {
		h.Log.Info("login path")
		return h.loginHandler()
	}
	h.Log.Info("not login path")

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

func (h *Htpasswd) loginHandler() (*Response, error) {
	h.Log.Info("loginHandler")
	// Return HTML with JavaScript for login modal
	loginHTML := `
<!DOCTYPE html>
<html>
<head>
<style>
.modal { 
    display: block;
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    background: white;
    padding: 20px;
    border-radius: 5px;
    box-shadow: 0 0 10px rgba(0,0,0,0.3);
}
.modal input {
    display: block;
    margin: 10px 0;
    padding: 5px;
    width: 200px;
}
.modal button {
    background: #4CAF50;
    color: white;
    padding: 10px 15px;
    border: none;
    border-radius: 3px;
    cursor: pointer;
}
</style>
</head>
<body>
<div class="modal">
    <h2>Login</h2>
    <input type="text" id="username" placeholder="Username">
    <input type="password" id="password" placeholder="Password">
    <button onclick="login()">Login</button>
</div>

<script>
function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    // Create base64 encoded credentials
    const credentials = btoa(username + ':' + password);
    
    // Set cookie
    document.cookie = 'basic-auth=' + credentials + '; Path=/; HttpOnly; Secure; SameSite=Lax';
    
    // Redirect back to original URL
    window.location.href = '/';
}
</script>
</body>
</html>`

	return &Response{
		Allow: false,
		Response: http.Response{
			StatusCode: http.StatusUnauthorized,
			Header: http.Header{
				"Content-Type": {"text/html"},
			},
			Body: io.NopCloser(strings.NewReader(loginHTML)),
		},
	}, nil
}

// Reconcile ...
func (h *Htpasswd) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var opts []client.ListOption

	if h.Selector != nil {
		opts = append(opts, client.MatchingLabelsSelector{Selector: h.Selector})
	}

	// First, find all the auth secrets for this realm.
	secrets := &v1.SecretList{}
	if err := h.Client.List(ctx, secrets, opts...); err != nil {
		return ctrl.Result{}, err
	}

	passwdData := bytes.Buffer{}

	for _, s := range secrets.Items {
		// Only look at basic auth secrets.
		if s.Annotations[AnnotationAuthType] != "basic" {
			continue
		}

		// Accept the secret if it is for our realm or for any realm.
		if realm := s.Annotations[AnnotationAuthRealm]; realm != "" {
			if realm != h.Realm && realm != "*" {
				continue
			}
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
