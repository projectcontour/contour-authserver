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
	"net/http"
	"net/url"
	"sort"
	"testing"

	envoy_api_v2_core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/stretchr/testify/assert"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
)

func testConvertedRequest(t *testing.T, actual *Request) {
	t.Helper()

	expected := Request{
		ID:      "100",
		Context: map[string]string{"k1": "v1", "k2": "v2"},
		Request: http.Request{
			Header: http.Header{"User-Agent": {"Foo"}, "Authorization": {"Basic anBlYWNoOmZvbw=="}},
			Method: "GET",
			Proto:  "HTTP/1.1",
			URL: &url.URL{
				Scheme:   "https",
				Host:     "example.com",
				Path:     "example",
				RawQuery: "query",
				Fragment: "fragment",
			},
		},
	}

	assert.Equal(t, &expected, actual)

	_, _, ok := actual.Request.BasicAuth()
	assert.True(t, ok, "expected.BasicAuth() should return true")
}

// stableV2 sorts the headers slice so that test equality is deterministic.
func stableV2(c *CheckResponseV2) *CheckResponseV2 {
	if d := c.GetDeniedResponse(); d != nil {
		sort.Slice(d.Headers, func(i, j int) bool {
			return d.Headers[i].GetHeader().GetKey() < d.Headers[j].GetHeader().GetKey()
		})
	}

	if o := c.GetOkResponse(); o != nil {
		sort.Slice(o.Headers, func(i, j int) bool {
			return o.Headers[i].GetHeader().GetKey() < o.Headers[j].GetHeader().GetKey()
		})
	}

	return c
}

// stableV3 sorts the headers slice so that test equality is deterministic.
func stableV3(c *CheckResponseV3) *CheckResponseV3 {
	if d := c.GetDeniedResponse(); d != nil {
		sort.Slice(d.Headers, func(i, j int) bool {
			return d.Headers[i].GetHeader().GetKey() < d.Headers[j].GetHeader().GetKey()
		})
	}

	if o := c.GetOkResponse(); o != nil {
		sort.Slice(o.Headers, func(i, j int) bool {
			return o.Headers[i].GetHeader().GetKey() < o.Headers[j].GetHeader().GetKey()
		})
	}

	return c
}

func TestConvertRequestV2(t *testing.T) {
	in := CheckRequestV2{
		Attributes: &envoy_service_auth_v2.AttributeContext{
			Request: &envoy_service_auth_v2.AttributeContext_Request{
				Http: &envoy_service_auth_v2.AttributeContext_HttpRequest{
					Id:     "100",
					Method: "GET",
					Headers: map[string]string{
						"user-agent":    "Foo",
						"authorization": "Basic anBlYWNoOmZvbw==",
					},
					Path:     "example",
					Host:     "example.com",
					Scheme:   "https",
					Query:    "query",
					Fragment: "fragment",
					Size:     0,
					Protocol: "HTTP/1.1",
				},
			},
			ContextExtensions: map[string]string{
				"k1": "v1",
				"k2": "v2",
			},
		},
	}

	actual := Request{}
	testConvertedRequest(t, actual.FromV2(&in))
}

func TestConvertRequestV3(t *testing.T) {
	in := CheckRequestV3{
		Attributes: &envoy_service_auth_v3.AttributeContext{
			Request: &envoy_service_auth_v3.AttributeContext_Request{
				Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
					Id:     "100",
					Method: "GET",
					Headers: map[string]string{
						"user-agent":    "Foo",
						"authorization": "Basic anBlYWNoOmZvbw==",
					},
					Path:     "example",
					Host:     "example.com",
					Scheme:   "https",
					Query:    "query",
					Fragment: "fragment",
					Size:     0,
					Protocol: "HTTP/1.1",
				},
			},
			ContextExtensions: map[string]string{
				"k1": "v1",
				"k2": "v2",
			},
		},
	}

	actual := Request{}
	testConvertedRequest(t, actual.FromV3(&in))
}

func TestConvertDenied(t *testing.T) {
	response := Response{
		Allow: false,
		Response: http.Response{
			StatusCode: 415,
			Header: http.Header{
				"k1": {"v1"},
				"k2": {"v2"},
			},
		},
	}

	assert.Equal(t, stableV2(response.AsV2()),
		&CheckResponseV2{
			Status: &status.Status{
				Code: int32(codes.PermissionDenied),
			},
			HttpResponse: &envoy_service_auth_v2.CheckResponse_DeniedResponse{
				DeniedResponse: &envoy_service_auth_v2.DeniedHttpResponse{
					Status: &envoy_type.HttpStatus{
						Code: envoy_type.StatusCode(415),
					},
					Headers: []*envoy_api_v2_core.HeaderValueOption{
						{
							Header: &envoy_api_v2_core.HeaderValue{
								Key: "k1", Value: "v1",
							},
						},
						{
							Header: &envoy_api_v2_core.HeaderValue{
								Key: "k2", Value: "v2",
							},
						},
					},
				},
			},
		},
	)

	assert.Equal(t, stableV3(response.AsV3()),
		&CheckResponseV3{
			Status: &status.Status{
				Code: int32(codes.PermissionDenied),
			},
			HttpResponse: &envoy_service_auth_v3.CheckResponse_DeniedResponse{
				DeniedResponse: &envoy_service_auth_v3.DeniedHttpResponse{
					Status: &envoy_type_v3.HttpStatus{
						Code: envoy_type_v3.StatusCode(415),
					},
					Headers: []*envoy_config_core_v3.HeaderValueOption{
						{
							Header: &envoy_config_core_v3.HeaderValue{
								Key: "k1", Value: "v1",
							},
						},
						{
							Header: &envoy_config_core_v3.HeaderValue{
								Key: "k2", Value: "v2",
							},
						},
					},
				},
			},
		},
	)
}

func TestConvertAllowed(t *testing.T) {
	response := Response{
		Allow: true,
		Response: http.Response{
			StatusCode: 415,
			Header: http.Header{
				"k1": {"v1"},
				"k2": {"v2"},
			},
		},
	}

	assert.Equal(t, stableV2(response.AsV2()),
		&CheckResponseV2{
			Status: &status.Status{
				Code: int32(codes.OK),
			},
			HttpResponse: &envoy_service_auth_v2.CheckResponse_OkResponse{
				OkResponse: &envoy_service_auth_v2.OkHttpResponse{
					Headers: []*envoy_api_v2_core.HeaderValueOption{
						{
							Header: &envoy_api_v2_core.HeaderValue{
								Key: "k1", Value: "v1",
							},
						},
						{
							Header: &envoy_api_v2_core.HeaderValue{
								Key: "k2", Value: "v2",
							},
						},
					},
				},
			},
		},
	)

	assert.Equal(t, stableV3(response.AsV3()),
		&CheckResponseV3{
			Status: &status.Status{
				Code: int32(codes.OK),
			},
			HttpResponse: &envoy_service_auth_v3.CheckResponse_OkResponse{
				OkResponse: &envoy_service_auth_v3.OkHttpResponse{
					Headers: []*envoy_config_core_v3.HeaderValueOption{
						{
							Header: &envoy_config_core_v3.HeaderValue{
								Key: "k1", Value: "v1",
							},
						},
						{
							Header: &envoy_config_core_v3.HeaderValue{
								Key: "k2", Value: "v2",
							},
						},
					},
				},
			},
		},
	)
}
