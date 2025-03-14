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
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-logr/logr"
)

// Httoken watches Secrets for httoken files and uses them for HTTP Basic Authentication.
type Httoken struct {
	Log         logr.Logger
	StaticToken string
}

var _ Checker = &Httoken{}

// Check ...
func (h *Httoken) Check(ctx context.Context, request *Request) (*Response, error) {
	h.Log.Info("checking request",
		"host", request.Request.Host,
		"path", request.Request.URL.Path,
		"id", request.ID,
	)

	h.Log.Info("request", "request", request.Request)

	// Check for Bearer token
	auth := request.Request.Header.Get("Authorization")
	var token string

	if strings.HasPrefix(auth, "Bearer ") {
		// Extract token
		token = strings.TrimPrefix(auth, "Bearer ")
	}

	// If there's an "Authorization" header and we can verify
	// it, succeed and inject some headers to tell the origin
	//what  we did.
	if token == h.StaticToken {
		// TODO(jpeach) inject context attributes into the headers.
		authorized := http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Auth-Handler": {"httoken"},
				"X-Auth-token": {token},
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

	return &Response{
		Allow: false,
		Response: http.Response{
			StatusCode: http.StatusUnauthorized,
			Header: http.Header{
				"WWW-Authenticate": {`Bearer realm="token", charset="UTF-8"`},
			},
		},
	}, nil
}

func (h *Httoken) loginHandler() (*Response, error) {
	h.Log.Info("loginHandler")

	// Script JavaScript avec prompt() natif
	loginHTML := `
<!DOCTYPE html>
<html>
<body>
<script>
    const token = prompt("Entrez votre token d'authentification:", "");
    if (token) {
        // Set cookie
        document.cookie = 'token-auth=' + token + '; Path=/; HttpOnly; Secure; SameSite=Lax';
        // Redirect back
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
