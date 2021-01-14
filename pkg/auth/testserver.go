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
	"net/http"
	"strings"

	"github.com/go-logr/logr"
)

// Testserver is a no-op implementation of the Checker interface. For testing only.
type Testserver struct {
	Log logr.Logger
}

var _ Checker = &Testserver{}

// Check ...
func (t *Testserver) Check(xts context.Context, request *Request) (*Response, error) {
	t.Log.Info("checking request",
		"host", request.Request.Host,
		"path", request.Request.URL.Path,
		"id", request.ID,
	)

	response := Response{
		Response: http.Response{
			// Status is ignored if the response is authorized.
			StatusCode: http.StatusUnauthorized,
			Header: http.Header{
				"Auth-Handler": {"testserver"},
			},
		},
	}
	// Requests are allowed if the path contains "allow".
	if strings.Contains(request.Request.URL.Path, "allow") {
		response.Allow = true
	}

	// Reflect the authorization check context into the response headers.
	for k, v := range request.Context {
		key := fmt.Sprintf("Auth-Context-%s", k)
		key = http.CanonicalHeaderKey(key) // XXX(jpeach) this will not transform invalid characters

		response.Response.Header.Add(key, v)
	}

	return &response, nil
}
