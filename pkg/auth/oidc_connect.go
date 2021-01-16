package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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

//Check ...
func (h *OIDCConnect) Check(ctx context.Context, req *Request) (*Response, error) {

	h.Log.Info("checking....")
	h.Log.Info("checking request",
		"host", req.Request.Host,
		"path", req.Request.URL.Path,
		"id", req.ID,
	)

	if h.provider == nil {
		h.provider, _ = h.initProvider(ctx)
	}

	// Generate response object.
	resp := Response{
		Response: http.Response{
			StatusCode: http.StatusUnauthorized,
			Header:     http.Header{},
		},
	}

	h.Log.Info(formatRequest(req))
	url := parseURL(req)
	h.verifyRequestHandler(ctx, req, &resp, url)

	return &resp, nil
}

func (h *OIDCConnect) verifyRequestHandler(ctx context.Context, req *Request, resp *Response, url *url.URL) {

	//Request verification handler ...

	// 1. Are you coming from IDP callback ?
	if url.Path == h.OidcConfig.RedirectPath {
		h.callbackHandler(ctx, req, resp, url)
		return
	}

	// 2. Check do we have stateid stored in querystring ?
	var state *store.OIDCState
	validState := false

	stateToken := url.Query().Get(stateQueryParamName)
	stateByte, err := h.Cache.Get(stateToken)
	if err == nil {
		state = store.ConvertToType(stateByte)
	}

	// 2.1 State not found, try to retrieve from cookies.
	if state == nil {
		state, _ = h.getStateFromCookie(ctx, req)
	}

	//2.2 State exist, proceed with token validation.
	if state != nil {
		// Re-initialize provider to refresh the context, this seems like bugs with coreos go-oidc module.
		provider, err := h.initProvider(ctx)
		if err != nil {
			h.Log.Info(fmt.Sprintf("fail to initialize provider: %v", err))
			return
		}
		validState = h.isStateValid(ctx, state, provider)

	}

	if validState {
		stateJSON, _ := json.Marshal(state)
		// Restore cookies.
		resp.Response.Header.Add(oauthTokenName, string(stateJSON))
		h.Cache.Delete(state.OAuthState)
		resp.Allow = true

	} else {
		// 2.3 Route to login handler.
		h.loginHandler(req, resp, url)
	}

}

func (h *OIDCConnect) loginHandler(req *Request, resp *Response, u *url.URL) {

	state := store.NewState()
	state.GenerateOauthState()
	state.RequestPath = u.Host + u.Path

	resp.Response.Header.Add(oauthTokenName, "")

	authCodeURL := h.oauth2Config().AuthCodeURL(state.OAuthState)
	byteState := store.ConvertToByte(state)

	h.Cache.Set(state.OAuthState, byteState)
	resp.Response.StatusCode = http.StatusFound
	resp.Response.Header.Add("Location", authCodeURL)
}

func (h *OIDCConnect) callbackHandler(ctx context.Context, req *Request, resp *Response, u *url.URL) {

	// 1. Get all variable needed.
	oauthState := u.Query().Get("state")
	code := u.Query().Get("code")

	// Check state and code validity.
	if code == "" || oauthState == "" {
		resp.Response.StatusCode = http.StatusBadRequest
		resp.Allow = false
		return
	}

	stateByte, err := h.Cache.Get(oauthState)
	if err != nil {
		h.Log.Info("Invalid state, expected " + oauthState + " not found ")
		resp.Response.StatusCode = http.StatusBadRequest
		resp.Allow = false
		return
	}

	// Retrieve token.
	context := oidc.ClientContext(ctx, h.HTTPClient)
	token, err := h.oauth2Config().Exchange(context, code)
	if err != nil {
		h.Log.Info(err.Error())
	}

	rawIDToken, ok := token.Extra("id_token").(string)

	if !ok {
		resp.Response.StatusCode = http.StatusInternalServerError
		resp.Allow = false
		return
	}

	//Store token.
	state := store.ConvertToType(stateByte)
	state.IDToken = rawIDToken
	state.AccessToken = token.AccessToken
	state.RefreshToken = token.RefreshToken
	stateByte = store.ConvertToByte(state)
	h.Cache.Set(state.OAuthState, stateByte)

	// Set  redirection.
	resp.Response.StatusCode = http.StatusTemporaryRedirect
	resp.Response.Header.Add(stateQueryParamName, state.OAuthState)

	// TODO .. may need to rebuild this, in case user could have other query parameters
	resp.Response.Header.Add("Location", fmt.Sprintf("http://%s?%s=%s", state.RequestPath, stateQueryParamName, state.OAuthState))
}

func (h *OIDCConnect) isStateValid(ctx context.Context, state *store.OIDCState, provider *oidc.Provider) bool {

	if state == nil {
		return false
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: h.OidcConfig.ClientID, SkipIssuerCheck: true})

	// Verify token and signature.
	idToken, err := verifier.Verify(ctx, state.IDToken)
	if err != nil {
		h.Log.Info(fmt.Sprintf("failed to verify ID token: %v", err))
		return false
	}

	// Try to claim.
	var claims json.RawMessage
	if err := idToken.Claims(&claims); err != nil {
		h.Log.Info(fmt.Sprintf("error decoding ID token claims: %v", err))
		return false
	}

	return true
}

func (h *OIDCConnect) getStateFromCookie(ctx context.Context, req *Request) (*store.OIDCState, error) {

	// Do you have cookies stored ?
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

	return nil, errors.New("No Cookies available")
}

func (h *OIDCConnect) initProvider(ctx context.Context) (*oidc.Provider, error) {
	provider, err := oidc.NewProvider(ctx, h.OidcConfig.IssuerURL)
	if err != nil {
		h.Log.Info(fmt.Sprintf("Unable to initialize provider %s", err))
		return nil, err
	}
	return provider, nil
}

func (h *OIDCConnect) oauth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     h.OidcConfig.ClientID,
		ClientSecret: h.OidcConfig.ClientSecret,
		Endpoint:     h.provider.Endpoint(),
		Scopes:       h.OidcConfig.Scopes,
		RedirectURL:  h.OidcConfig.RedirectURL + h.OidcConfig.RedirectPath,
	}
}

func parseURL(req *Request) *url.URL {

	plainURL, _ := url.QueryUnescape(req.Request.URL.String())
	u, err := url.Parse(plainURL)
	if err != nil {
		return nil
	}

	return u
}

// TODO :: safe to ignore
func formatRequest(r *Request) string {

	// Create return string
	var request []string
	// Add the request string

	fmt.Println("============= START =================")

	u := fmt.Sprintf("%v %v %v %v", r.Request.Method, r.Request.URL, r.Request.RequestURI, r.Request.Proto)
	request = append(request, u)
	// Add the host
	request = append(request, fmt.Sprintf("Host: %v", r.Request.Host))
	// Loop through headers
	for name, headers := range r.Request.Header {
		name = strings.ToLower(name)
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
