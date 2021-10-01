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
	"github.com/coreos/go-oidc"
	"github.com/go-logr/logr"
	"github.com/projectcontour/contour-authserver/pkg/config"
	"github.com/projectcontour/contour-authserver/pkg/store"
	"golang.org/x/oauth2"
)

const (
	stateQueryParamName = "conauth"
	oauthTokenName      = "contourtoken"
)

// OIDCConnect .
type OIDCConnect struct {
	Log        logr.Logger
	OidcConfig *config.OIDCConfig
	Cache      *bigcache.BigCache
	HTTPClient *http.Client
	provider   *oidc.Provider
}

// Implement interface.
var _ Checker = &OIDCConnect{}

/*
	Check Entry point for authentication. it accept incoming request and redirect un-authenticated user to
	IDP. Otherwise it will route user to the intended url
*/
func (h *OIDCConnect) Check(ctx context.Context, req *Request) (*Response, error) {

	h.Log.Info("checking request",
		"host", req.Request.Host,
		"path", req.Request.URL.Path,
		"id", req.ID,
	)

	if h.provider == nil {
		h.provider, _ = h.initProvider(ctx)
	}

	// h.Log.Info(formatRequest(req))
	url := parseURL(req)

	// 1. Callback Request ?
	if url.Path == h.OidcConfig.RedirectPath {
		resp, err := h.callbackHandler(ctx, req, url)
		return &resp, err
	}

	// 2. Check state validity
	resp, valid, err := h.isValidState(ctx, req, url)

	if err != nil {
		return &resp, err
	}

	// 3. invalid state, redirect to login handler
	if !valid {
		resp = h.loginHandler(req, url)
		return &resp, nil
	}

	return &resp, nil

}

//isValidState  check user token and state validity	for subsequent calls
func (h *OIDCConnect) isValidState(ctx context.Context, req *Request, url *url.URL) (Response, bool, error) {

	// 1. Check do we have stateid stored in querystring ?
	var state *store.OIDCState

	stateToken := url.Query().Get(stateQueryParamName)
	stateByte, err := h.Cache.Get(stateToken)
	if err == nil {
		state = store.ConvertToType(stateByte)
	}

	// 1.1 State not found, try to retrieve from cookies.
	if state == nil {
		state, _ = h.getStateFromCookie(ctx, req)
	}

	//1.2 State exist, proceed with token validation.
	if state != nil {

		// Re-initialize provider to refresh the context, this seems like bugs with coreos go-oidc module.
		provider, err := h.initProvider(ctx)
		if err != nil {
			h.Log.Error(err, "fail to initialize provider")
			return createResponse(http.StatusInternalServerError), false, err
		}

		if h.isValidStateToken(ctx, state, provider) {

			stateJSON, _ := json.Marshal(state)
			// Restore cookies.
			resp := createResponse(http.StatusOK)
			resp.Response.Header.Add(oauthTokenName, string(stateJSON))
			h.Cache.Delete(state.OAuthState)

			return resp, true, nil
		}
	}

	// return empty response, will direct to loginHandler
	return Response{}, false, nil
}

/**
	loginHandler
	Accept request and url,
	Return Response
	LoginHandler help to generate new state that is required by oauth during initial user login.
**/
func (h *OIDCConnect) loginHandler(req *Request, u *url.URL) Response {

	state := store.NewState()
	state.GenerateOauthState()
	state.RequestPath = path.Join(u.Host, u.Path)
	state.Scheme = u.Scheme

	authCodeURL := h.oauth2Config().AuthCodeURL(state.OAuthState)
	byteState := store.ConvertToByte(state)
	h.Cache.Set(state.OAuthState, byteState)

	resp := createResponse(http.StatusFound)
	resp.Response.Header.Add(oauthTokenName, "")
	resp.Response.Header.Add("Location", authCodeURL)

	return resp
}

/**
	callbackHandler
	Accept request and url,
	Return Response
	callback handler check state, code and token validity. Ensure everything is in order before redirect user to their intended destination.
	TODO :: currently missing query parameters propagation features.
**/
func (h *OIDCConnect) callbackHandler(ctx context.Context, req *Request, u *url.URL) (Response, error) {

	// resp := createDefaultResponse()

	// 1. Get all variable needed.
	oauthState := u.Query().Get("state")
	code := u.Query().Get("code")

	// 2 Check state and code validity.
	if code == "" || oauthState == "" {

		// 2.1 Code and State is empty, return Bad Request
		err := fmt.Errorf("Code and State is not available")
		return createResponse(http.StatusBadRequest), err
	}

	stateByte, err := h.Cache.Get(oauthState)
	if err != nil {

		// 2.2 State invalid , return  Bad Request
		h.Log.Error(err, "Invalid state, expected oAuthState not found", "oauthState", oauthState)
		return createResponse(http.StatusBadRequest), err
	}

	// Retrieve token. and check token validity
	context := oidc.ClientContext(ctx, h.HTTPClient)
	token, err := h.oauth2Config().Exchange(context, code)
	if err != nil {

		// 2.3.1 Token invalid, return Internal Server Error
		h.Log.Error(err, "Token exchange error")
		return createResponse(http.StatusInternalServerError), err
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		// 2.3.2 Token invalid, return Internal Server Error
		return createResponse(http.StatusInternalServerError), fmt.Errorf("Invalid token id")

	}

	// 3. success case, allow proceed.

	//Store token.
	state := store.ConvertToType(stateByte)
	state.IDToken = rawIDToken
	state.AccessToken = token.AccessToken
	state.RefreshToken = token.RefreshToken
	stateByte = store.ConvertToByte(state)
	h.Cache.Set(state.OAuthState, stateByte)

	// Set  redirection.
	resp := createResponse(http.StatusTemporaryRedirect)
	resp.Response.Header.Add(stateQueryParamName, state.OAuthState)

	// TODO .. may need to rebuild this, in case user could have other query parameters
	resp.Response.Header.Add("Location", fmt.Sprintf("%s://%s?%s=%s", state.Scheme, state.RequestPath, stateQueryParamName, state.OAuthState))

	return resp, nil
}

//isValidStateToken verify token and signature
func (h *OIDCConnect) isValidStateToken(ctx context.Context, state *store.OIDCState, provider *oidc.Provider) bool {

	if state == nil {
		return false
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID:        h.OidcConfig.ClientID,
		SkipIssuerCheck: h.OidcConfig.SkipIssuerCheck,
	})

	// Verify token and signature.
	idToken, err := verifier.Verify(ctx, state.IDToken)
	if err != nil {
		h.Log.Info(fmt.Sprintf("failed to verify ID token: %v", err))
		return false
	}

	// TODO :: enhancement on claim propagations
	// Try to claim.
	var claims json.RawMessage
	if err := idToken.Claims(&claims); err != nil {
		h.Log.Error(err, "error decoding ID token")
		return false
	}

	return true
}

//getStateFromCookie retrive state token from cookie header and return the value as OIDCState
func (h *OIDCConnect) getStateFromCookie(ctx context.Context, req *Request) (*store.OIDCState, error) {

	cookieVal := req.Request.Header.Get("cookie")
	var state *store.OIDCState
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

//initProvider intialize oidc provide with ths given issuer URL. return oidc.Provider
func (h *OIDCConnect) initProvider(ctx context.Context) (*oidc.Provider, error) {
	provider, err := oidc.NewProvider(ctx, h.OidcConfig.IssuerURL)
	if err != nil {
		h.Log.Error(err, "Unable to initialize provider", "issuerUrl", h.OidcConfig.IssuerURL)
		return nil, err
	}
	return provider, nil
}

//oauth2Config factory method to oauth2Config
func (h *OIDCConnect) oauth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     h.OidcConfig.ClientID,
		ClientSecret: h.OidcConfig.ClientSecret,
		Endpoint:     h.provider.Endpoint(),
		Scopes:       h.OidcConfig.Scopes,
		RedirectURL:  h.OidcConfig.RedirectURL + h.OidcConfig.RedirectPath,
	}
}

//createResponseDefault helper class for default response
func createResponseDefault() Response {
	return createResponse(http.StatusUnauthorized)
}

//createResponse helper class to create response. Accept status code and return Response
func createResponse(status int) Response {

	allow := (status == http.StatusOK)

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

//  formatRequest safe to ignore only use during debugging
func formatRequest(r *Request) string {

	// Create return string
	var request []string
	// Add the request string

	u := fmt.Sprintf("%v %v %v %v", r.Request.Method, r.Request.URL, r.Request.RequestURI, r.Request.Proto)
	request = append(request, u)
	// Add the host
	request = append(request, fmt.Sprintf("Host: %v", r.Request.Host))
	// Loop through headers
	for name, headers := range r.Request.Header {
		//name = strings.ToLower(name)
		for _, h := range headers {
			request = append(request, fmt.Sprintf("%v: %v", name, h))
		}
	}

	// If this is a POST, add post data
	if r.Request.Method == "POST" {
		r.Request.ParseForm()
		request = append(request, "\n")
		request = append(request, r.Request.Form.Encode())
	}
	// Return the request as a string
	return strings.Join(request, "\n")
}
