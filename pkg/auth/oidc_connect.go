package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	netUrl "net/url"
	"strings"

	"github.com/allegro/bigcache"
	"github.com/go-logr/logr"
	"github.com/projectcontour/contour-authserver/pkg/config"
	"github.com/projectcontour/contour-authserver/pkg/store"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

const (
	contourAuth  = "conauth"
	contourToken = "contourtoken"
)

// OidcConnect ...
type OidcConnect struct {
	Log        logr.Logger
	OidcConfig *config.OidcConfig
	Cache      *bigcache.BigCache
	HTTPClient *http.Client
	provider   *oidc.Provider
}

// implementing interface
var _ Checker = &OidcConnect{}

//Check ...
func (h *OidcConnect) Check(ctx context.Context, req *Request) (*Response, error) {

	if h.provider == nil {
		h.provider, _ = h.initProvider(ctx)
	}

	// generate response object
	resp := Response{
		Response: http.Response{
			StatusCode: http.StatusUnauthorized,
			Header:     http.Header{},
		},
	}

	// h.Log.Info(formatRequest(request))
	url := parseURL(req)
	h.verifyRequestHandler(ctx, req, &resp, url)

	return &resp, nil
}

func (h *OidcConnect) verifyRequestHandler(ctx context.Context, req *Request, resp *Response, url *netUrl.URL) {

	//request verification handler ...
	// 1. are you coming from IDP callback ?
	if url.Path == h.OidcConfig.RedirectPath {
		// callback method.. request come from IDP
		h.callbackHandler(ctx, req, resp, url)
		return
	}

	// 2. check do we have stateid stored in querystring ?
	var state *store.OidcState
	var validState bool

	stateToken := url.Query().Get(contourAuth)
	stateByte, err := h.Cache.Get(stateToken)
	if err == nil {
		state = store.ConvertToType(stateByte)
	}

	// 2.1 if its available, lets check and make sure this is a valid state
	//re-initialize provider to refresh the context, this seems like bugs with coreos go-oidc module
	provider, err := h.initProvider(ctx)
	if err != nil {
		h.Log.Info(fmt.Sprintf("fail to initialize provider: %v", err))
		return
	}

	validState = h.isStateValid(ctx, state, provider)

	// not a valid state from querystring, thus we check state from cookie
	if !validState {
		state, _ = h.getStateFromCookie(ctx, req)
		validState = h.isStateValid(ctx, state, provider)
	}

	if !validState {
		h.loginHandler(req, resp, url)
		return
	}

	stateJSON, _ := json.Marshal(state)
	// restore cookies
	resp.Response.Header.Add(contourToken, string(stateJSON))
	h.Cache.Delete(state.OAuthState)

	resp.Allow = true
}

func (h *OidcConnect) loginHandler(req *Request, resp *Response, url *netUrl.URL) {

	h.Log.Info("========  loginHandler")
	// create new state
	state := store.NewState()
	state.GenerateOauthState()
	state.RequestPath = url.Host + url.Path

	resp.Response.Header.Add(contourToken, "")

	authCodeURL := h.oauth2Config().AuthCodeURL(state.OAuthState)
	byteState := store.ConvertToByte(state)

	h.Cache.Set(state.OAuthState, byteState)
	resp.Response.StatusCode = http.StatusFound
	resp.Response.Header.Add("Location", authCodeURL)
}

func (h *OidcConnect) callbackHandler(ctx context.Context, req *Request, resp *Response, url *netUrl.URL) {
	h.Log.Info("========  callbackHandler")

	// 1. get all variable needed
	oauthState := url.Query().Get("state")
	code := url.Query().Get("code")

	// check state and code validity
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

	// retrieve token
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

	//store token
	state := store.ConvertToType(stateByte)
	state.IDToken = rawIDToken
	state.AccessToken = token.AccessToken
	state.RefreshToken = token.RefreshToken
	stateByte = store.ConvertToByte(state)
	h.Cache.Set(state.OAuthState, stateByte)

	// set  redirection
	resp.Response.StatusCode = http.StatusTemporaryRedirect
	resp.Response.Header.Add(contourAuth, state.OAuthState)

	// TODO .. may need to rebuild this, in case user could have other query parameters
	resp.Response.Header.Add("Location", fmt.Sprintf("http://%s?%s=%s", state.RequestPath, contourAuth, state.OAuthState))
}

func (h *OidcConnect) isStateValid(ctx context.Context, state *store.OidcState, provider *oidc.Provider) bool {

	if state == nil {
		return false
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: h.OidcConfig.ClientID, SkipIssuerCheck: true})

	//verify token and signature
	idToken, err := verifier.Verify(ctx, state.IDToken)
	if err != nil {
		h.Log.Info(fmt.Sprintf("failed to verify ID token: %v", err))
		return false
	}

	//try to claim
	var claims json.RawMessage
	if err := idToken.Claims(&claims); err != nil {
		h.Log.Info(fmt.Sprintf("error decoding ID token claims: %v", err))
		return false
	}

	return true
}

func (h *OidcConnect) getStateFromCookie(ctx context.Context, req *Request) (*store.OidcState, error) {

	// do you have cookies stored ?
	cookieVal := req.Request.Header.Get("cookie")
	var state *store.OidcState
	// check through and validate cookies
	if len(cookieVal) > 0 {
		cookies := strings.Split(cookieVal, ";")

		for _, c := range cookies {
			c = strings.TrimSpace(c)
			if strings.HasPrefix(c, contourToken) {
				cookieJSON := c[len(contourToken)+1:]
				if len(cookieJSON) > 0 {
					state = store.ConvertToType([]byte(cookieJSON))
					return state, nil
				}

			}
		}
	}

	return nil, errors.New("No Cookies available")
}

func (h *OidcConnect) initProvider(ctx context.Context) (*oidc.Provider, error) {
	provider, err := oidc.NewProvider(ctx, h.OidcConfig.IssuerURL)
	if err != nil {
		h.Log.Info(fmt.Sprintf("Unable to initialize provider %s", err))
		return nil, err
	}
	return provider, nil
}

func (h *OidcConnect) oauth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     h.OidcConfig.ClientID,
		ClientSecret: h.OidcConfig.ClientSecret,
		Endpoint:     h.provider.Endpoint(),
		Scopes:       h.OidcConfig.Scopes,
		RedirectURL:  h.OidcConfig.RedirectURL + h.OidcConfig.RedirectPath,
	}
}

func parseURL(req *Request) *netUrl.URL {

	plainURL, _ := netUrl.QueryUnescape(req.Request.URL.String())
	url, err := netUrl.Parse(plainURL)
	if err != nil {
		return nil
	}

	return url
}

// TODO :: safe to ignore
func formatRequest(r *Request) string {

	// Create return string
	var request []string
	// Add the request string

	fmt.Println("============= START =================")

	url := fmt.Sprintf("%v %v %v %v", r.Request.Method, r.Request.URL, r.Request.RequestURI, r.Request.Proto)
	request = append(request, url)
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
