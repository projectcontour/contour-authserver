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
