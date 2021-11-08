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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/allegro/bigcache"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-logr/logr"
	"github.com/projectcontour/contour-authserver/pkg/config"
	"github.com/projectcontour/contour-authserver/pkg/store"
	"golang.org/x/oauth2"
)

const (
	stateQueryParamName = "conauth"
	oauthTokenName      = "contourtoken"
)

// OIDCConnect defines parameters for an OIDC auth provider.
type OIDCConnect struct {
	Log        logr.Logger
	OidcConfig *config.OIDCConfig
	Cache      *bigcache.BigCache
	HTTPClient *http.Client
	provider   *oidc.Provider
}

// Implement interface.
var _ Checker = &OIDCConnect{}

// Check entry point for authentication. it accepts incoming request and redirects un-authenticated requests to
// IDP. Otherwise, it will route user to the intended url.
func (o *OIDCConnect) Check(ctx context.Context, req *Request) (*Response, error) {
	o.Log.Info("checking request",
		"host", req.Request.Host,
		"path", req.Request.URL.Path,
		"id", req.ID,
	)

	if o.provider == nil {
		o.provider, _ = o.initProvider(ctx)
	}

	url := parseURL(req)

	// Check if the current request matches the callback path.
	if url.Path == o.OidcConfig.RedirectPath {
		resp, err := o.callbackHandler(ctx, url)
		return &resp, err
	}

	// Validate the state.
	resp, valid, err := o.isValidState(ctx, req, url)
	if err != nil {
		return &resp, err
	}

	// If state is invalid, redirect to login handler.
	if !valid {
		resp = o.loginHandler(url)
		return &resp, nil
	}

	return &resp, nil
}

// isValidState checks the user token and state validity for subsequent calls.
func (o *OIDCConnect) isValidState(ctx context.Context, req *Request, url *url.URL) (Response, bool, error) {
	// Do we have stateid stored in querystring
	var state *store.OIDCState

	stateToken := url.Query().Get(stateQueryParamName)

	stateByte, err := o.Cache.Get(stateToken)
	if err == nil {
		state = store.ConvertToType(stateByte)
	}

	// State not found, try to retrieve from cookies.
	if state == nil {
		state, _ = o.getStateFromCookie(req)
	}

	// State exists, proceed with token validation.
	if state != nil {
		// Re-initialize provider to refresh the context, this seems like bugs with coreos go-oidc module.
		provider, err := o.initProvider(ctx)
		if err != nil {
			o.Log.Error(err, "fail to initialize provider")
			return createResponse(http.StatusInternalServerError), false, err
		}

		if o.isValidStateToken(ctx, state, provider) {
			stateJSON, _ := json.Marshal(state)
			// Restore cookies.
			resp := createResponse(http.StatusOK)

			resp.Response.Header.Add(oauthTokenName, string(stateJSON))

			if err := o.Cache.Delete(state.OAuthState); err != nil {
				o.Log.Error(err, "error deleting state")
			}

			return resp, true, nil
		}
	}

	// return empty response, will direct to loginHandler
	return Response{}, false, nil
}

// loginHandler takes a url returning a Response with a new state that is required by oauth during initial user login.
func (o *OIDCConnect) loginHandler(u *url.URL) Response {
	state := store.NewState()
	state.GenerateOauthState()
	state.RequestPath = path.Join(u.Host, u.Path)
	state.Scheme = u.Scheme

	authCodeURL := o.oauth2Config().AuthCodeURL(state.OAuthState)

	byteState := store.ConvertToByte(state)
	if err := o.Cache.Set(state.OAuthState, byteState); err != nil {
		o.Log.Error(err, "error setting cache state")
	}

	resp := createResponse(http.StatusFound)
	resp.Response.Header.Add(oauthTokenName, "")
	resp.Response.Header.Add("Location", authCodeURL)

	return resp
}

// callbackHandler takes an url validating the state, code and token validity. Returns a response redirect
// to their intended destination.
func (o *OIDCConnect) callbackHandler(ctx context.Context, u *url.URL) (Response, error) {
	// 1. Get all variable needed.
	oauthState := u.Query().Get("state")
	code := u.Query().Get("code")

	// 2 Check state and code validity.
	if code == "" || oauthState == "" {
		// 2.1 Code and State is empty, return Bad Request
		err := fmt.Errorf("Code and State is not available")
		return createResponse(http.StatusBadRequest), err
	}

	stateByte, err := o.Cache.Get(oauthState)
	if err != nil {
		// 2.2 State invalid , return  Bad Request
		o.Log.Error(err, "Invalid state, expected oAuthState not found", "oauthState", oauthState)
		return createResponse(http.StatusBadRequest), err
	}

	// Retrieve token. and check token validity
	context := oidc.ClientContext(ctx, o.HTTPClient)

	token, err := o.oauth2Config().Exchange(context, code)
	if err != nil {
		// 2.3.1 Token invalid, return Internal Server Error
		o.Log.Error(err, "Token exchange error")
		return createResponse(http.StatusInternalServerError), err
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		// 2.3.2 Token invalid, return Internal Server Error
		return createResponse(http.StatusInternalServerError), fmt.Errorf("Invalid token id")
	}

	//Store token.
	state := store.ConvertToType(stateByte)
	state.IDToken = rawIDToken
	state.AccessToken = token.AccessToken
	state.RefreshToken = token.RefreshToken
	stateByte = store.ConvertToByte(state)

	if err := o.Cache.Set(state.OAuthState, stateByte); err != nil {
		o.Log.Error(err, "error setting cache state")
	}

	// Set  redirection.
	resp := createResponse(http.StatusTemporaryRedirect)
	resp.Response.Header.Add(stateQueryParamName, state.OAuthState)

	// TODO(robinfoe) #18 : OIDC support should propagate any claims back to the request
	resp.Response.Header.Add("Location",
		fmt.Sprintf("%s://%s?%s=%s", state.Scheme, state.RequestPath, stateQueryParamName, state.OAuthState))

	return resp, nil
}

// isValidStateToken verify token and signature.
func (o *OIDCConnect) isValidStateToken(ctx context.Context, state *store.OIDCState, provider *oidc.Provider) bool {
	if state == nil {
		return false
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID:        o.OidcConfig.ClientID,
		SkipIssuerCheck: o.OidcConfig.SkipIssuerCheck,
	})

	// Verify token and signature.
	idToken, err := verifier.Verify(ctx, state.IDToken)
	if err != nil {
		o.Log.Info(fmt.Sprintf("failed to verify ID token: %v", err))
		return false
	}

	// TODO(robinfoe) #18 : OIDC support should propagate any claims back to the request
	// Try to claim.
	var claims json.RawMessage
	if err := idToken.Claims(&claims); err != nil {
		o.Log.Error(err, "error decoding ID token")
		return false
	}

	return true
}

//getStateFromCookie retrieve state token from cookie header and return the value as OIDCState.
func (o *OIDCConnect) getStateFromCookie(req *Request) (*store.OIDCState, error) {
	var state *store.OIDCState

	cookieVal := req.Request.Header.Get("cookie")

	// Check through and get the right cookies
	if len(cookieVal) > 0 {
		cookies := strings.Split(cookieVal, ";")

		for _, c := range cookies {
			c = strings.TrimSpace(c)
			if strings.HasPrefix(c, oauthTokenName) {
				cookieJSON := c[len(oauthTokenName)+1:]
				if len(cookieJSON) > 0 {
					state = store.ConvertToType([]byte(cookieJSON))
					return state, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("no %q cookie", oauthTokenName)
}

//initProvider initialize oidc provide with ths given issuer URL. return oidc.Provider.
func (o *OIDCConnect) initProvider(ctx context.Context) (*oidc.Provider, error) {
	provider, err := oidc.NewProvider(ctx, o.OidcConfig.IssuerURL)
	if err != nil {
		o.Log.Error(err, "Unable to initialize provider", "issuerUrl", o.OidcConfig.IssuerURL)
		return nil, err
	}

	return provider, nil
}

// oauth2Config factory method to oauth2Config.
func (o *OIDCConnect) oauth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     o.OidcConfig.ClientID,
		ClientSecret: o.OidcConfig.ClientSecret,
		Endpoint:     o.provider.Endpoint(),
		Scopes:       o.OidcConfig.Scopes,
		RedirectURL:  o.OidcConfig.RedirectURL + o.OidcConfig.RedirectPath,
	}
}

// createResponse helper class to create response. Accept status code and return Response.
func createResponse(status int) Response {
	allow := status == http.StatusOK

	return Response{
		Response: http.Response{
			StatusCode: status, // defaulted to unauthorized
			Header:     http.Header{},
		},
		Allow: allow,
	}
}

func parseURL(req *Request) *url.URL {
	plainURL, _ := url.QueryUnescape(req.Request.URL.String())
	u, err := url.Parse(plainURL)

	if err != nil {
		return nil
	}

	if s, ok := req.Request.Header["X-Forwarded-Proto"]; ok {
		u.Scheme = s[0]
	} else {
		u.Scheme = "http"
	}

	return u
}
