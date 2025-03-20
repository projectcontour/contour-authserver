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
	"regexp"
	"strings"

	"github.com/allegro/bigcache"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v5"
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
	// RenewedTokenCache stores user authentication information (idtoken and accesstoken)
	// for 5 minutes when tokens are renewed. This avoids having to do a refresh token
	// on every user request, since we cannot update user cookies during token renewal.
	RenewedTokenCache *bigcache.BigCache
}

type UserInfo struct {
	Username      string
	Email         string
	EmailVerified bool
	GivenName     string
	FamilyName    string
	Nickname      string
	Roles         []string
	Groups        []string
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
	// check redirect url
	if o.OidcConfig.RedirectURL == "" && len(o.OidcConfig.AuthorizedRedirectDomains) == 0 {
		o.Log.Info("no redirectURL or AuthorizedRedirectDomains specified")
		return &Response{}, fmt.Errorf("no redirectURL or AuthorizedRedirectDomains specified")
	} else if len(o.OidcConfig.AuthorizedRedirectDomains) != 0 {
		authorized := false
		for _, domain := range o.OidcConfig.AuthorizedRedirectDomains {
			domain = strings.TrimPrefix(domain, "*.")
			if strings.HasSuffix(url.Host, domain) || domain == "*" {
				authorized = true
				break
			}
		}
		if !authorized {
			o.Log.Info("redirectURL does not match", "url", url.Host, "authorizedRedirectDomains", o.OidcConfig.AuthorizedRedirectDomains)
			return &Response{}, fmt.Errorf("redirectURL does not match")
		}
		o.OidcConfig.RedirectURL = fmt.Sprintf("%s://%s", url.Scheme, url.Host)

	}
	// Check if the current request matches the callback path.
	if url.Path == o.OidcConfig.RedirectPath {
		resp, err := o.callbackHandler(ctx, url)
		return &resp, err
	}
	// Do we have stateid stored in querystring
	state := o.GetState(ctx, req, url)
	// Validate the state.
	resp, valid, err := o.isValidState(ctx, state)
	if err != nil {
		o.Log.Error(err, "error validating state")
		return &resp, err
	}

	// If state is invalid, redirect to login handler.
	if !valid {
		resp = o.loginHandler(url)
		return &resp, nil
	}

	userInfo, resp, err := o.GetUserInfo(ctx, state)
	if err != nil {
		return &resp, err
	}

	// Validate the authorization.
	resp, authorized, err := o.isAuthorized(req, &resp, url, userInfo)
	if !authorized {
		return &resp, err
	}

	return &resp, nil
}

// isValidState checks the user token and state validity for subsequent calls.
func (o *OIDCConnect) isValidState(ctx context.Context, state *store.OIDCState) (Response, bool, error) {
	// State exists, proceed with token validation.
	if state != nil {
		// Re-initialize provider to refresh the context, this seems like bugs with coreos go-oidc module.
		provider, err := o.initProvider(ctx)
		if err != nil {
			o.Log.Error(err, "fail to initialize provider")
			return createResponse(http.StatusInternalServerError), false, err
		}

		if !o.isValidStateToken(ctx, state, provider) {
			if err := o.refreshTokens(ctx, state, provider); err != nil {
				o.Log.Error(err, "fail to refresh tokens")
				return Response{}, false, nil
			}
		}

		stateJSON, _ := json.Marshal(state)
		// Restore cookies.
		resp := createResponse(http.StatusOK)

		resp.Response.Header.Add(oauthTokenName, string(stateJSON))

		if err := o.Cache.Delete(state.OAuthState); err != nil && err != bigcache.ErrEntryNotFound {
			o.Log.Error(err, "error deleting state")
		}

		return resp, true, nil
	}

	// return empty response, will direct to loginHandler
	return Response{}, false, nil
}

// refreshTokens refreshes the access and ID tokens using the refresh token.
func (o *OIDCConnect) refreshTokens(ctx context.Context, state *store.OIDCState, provider *oidc.Provider) error {
	o.Log.Info("refreshing tokens...")
	tokenSource := o.oauth2Config().TokenSource(ctx, &oauth2.Token{
		RefreshToken: state.RefreshToken,
	})

	newToken, err := tokenSource.Token()
	if err != nil {
		o.Log.Error(err, "failed to refresh token")
		return err
	}

	// Get new ID token from the token response
	rawIDToken, ok := newToken.Extra("id_token").(string)
	if !ok {
		return fmt.Errorf("no id_token in token response")
	}

	// Verify the new ID token
	verifier := provider.Verifier(&oidc.Config{
		ClientID:        o.OidcConfig.ClientID,
		SkipIssuerCheck: o.OidcConfig.SkipIssuerCheck,
	})

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		o.Log.Error(err, "failed to verify refreshed ID token")
		return err
	}
	// Try to claim.
	var claims json.RawMessage
	if err := idToken.Claims(&claims); err != nil {
		o.Log.Error(err, "error decoding ID token")
		return err
	}

	// Update state with new id and access tokens
	state.IDToken = rawIDToken
	state.AccessToken = newToken.AccessToken

	// Only cache the ID token and access token since those are the only values
	// that change during token refresh
	stateToStore := store.NewState()
	stateToStore.IDToken = rawIDToken
	stateToStore.AccessToken = newToken.AccessToken
	err = o.RenewedTokenCache.Set(state.OAuthState, store.ConvertToByte(stateToStore))
	if err != nil {
		o.Log.Error(err, "error setting cache state")
	}

	return nil
}

func (o *OIDCConnect) GetState(ctx context.Context, req *Request, requestUrl *url.URL) *store.OIDCState {
	var state *store.OIDCState

	// Check Authorization header
	authHeader := req.Request.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		state = store.NewState()
		state.AccessToken = strings.TrimPrefix(authHeader, "Bearer ")
		return state
	}

	stateToken, err := url.QueryUnescape(requestUrl.Query().Get(stateQueryParamName))
	if err != nil {
		o.Log.Error(err, "error unescaping state token")
		return nil
	}

	stateByte, err := o.Cache.Get(stateToken)
	if err == nil {
		state = store.ConvertToType(stateByte)
	} else {
		// State not found, try to retrieve from cookies.
		state, _ = o.getStateFromCookie(req)
	}

	// Check if state has been updated and stored in RenewedTokenCache
	if state != nil && state.OAuthState != "" {

		data, err := o.RenewedTokenCache.Get(state.OAuthState)
		if err == nil {
			cachedState := store.ConvertToType(data)
			if cachedState != nil {
				state.IDToken = cachedState.IDToken
				state.AccessToken = cachedState.AccessToken
				return state
			}
		}

	}

	return state
}

// getStateFromCookie retrieve state token from cookie header and return the value as OIDCState.
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

// loginHandler takes a url returning a Response with a new state that is required by oauth during initial user login.
func (o *OIDCConnect) loginHandler(u *url.URL) Response {
	state := store.NewState()
	state.GenerateOauthState()
	state.RequestPath = path.Join(u.Host, u.Path)
	state.Scheme = u.Scheme

	authCodeURL := o.oauth2Config().AuthCodeURL(state.OAuthState)

	o.Log.Info("Redirecting to", "authCodeURL", authCodeURL)

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

	stateJSON, _ := json.Marshal(state)
	resp.Response.Header.Add("Set-Cookie",
		fmt.Sprintf("%s=%s; Path=/; HttpOnly; Secure; SameSite=Lax", oauthTokenName, string(stateJSON)))

	return resp, nil
}

// isValidStateToken verify token and signature.
func (o *OIDCConnect) isValidStateToken(ctx context.Context, state *store.OIDCState, provider *oidc.Provider) bool {
	if state == nil {
		return false
	}

	// Si on a un ID Token, on le vérifie
	if state.IDToken != "" {
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

	// Si on a un Access Token, on vérifie via UserInfo
	if state.AccessToken != "" {
		_, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: state.AccessToken,
		}))
		if err != nil {
			o.Log.Info(fmt.Sprintf("failed to verify Access token: %v", err))
			return false
		}

		return true
	}

	// Aucun token valide
	return false
}

// isAuthorized checks the user role and groups against the authorized
// roles and groups from the Auth-Context-%s headers.
func (o *OIDCConnect) isAuthorized(
	req *Request,
	resp *Response,
	url *url.URL,
	userInfo *UserInfo,
) (Response, bool, error) {
	for rule, requiredPrivileges := range req.Context {
		o.Log.Info("context", "rule", rule, "requiredPrivileges", requiredPrivileges)
		if o.isRuleApplicableToMethodAndPath(rule, req.Request.Method, url.Path) {
			o.Log.Info("rule applicable", "rule", rule, "requiredPrivileges", requiredPrivileges)
			if !o.hasRequiredPermissions(rule, requiredPrivileges, url.Path, userInfo) {
				o.Log.Info("rule not allowed", "rule", rule, "requiredPrivileges", requiredPrivileges, "userInfo", userInfo)
				return createResponse(http.StatusUnauthorized), false, nil
			}
			o.Log.Info("rule allowed", "rule", rule, "requiredPrivileges", requiredPrivileges, "userInfo", userInfo)
		}
	}

	// Propagate the user info to the response headers.
	o.PropagateUserInfo(resp, userInfo)

	return *resp, true, nil
}

func (o *OIDCConnect) isRuleApplicableToMethodAndPath(rule, method, path string) bool {
	parts := strings.Split(rule, ";")
	if len(parts) > 3 {
		return false
	} else if len(parts) < 2 {
		return true
	}

	if len(parts) == 3 && !o.isMethodMarched(parts[0], method) {
		return false
	}

	if !o.isPathMatched(parts[1], path) {
		return false
	}

	return true
}

func (o *OIDCConnect) isMethodMarched(methodsPart, method string) bool {
	methods := strings.Split(methodsPart, "|")
	return contains(methods, method)
}

func (o *OIDCConnect) isPathMatched(pathsPart, path string) bool {
	paths := strings.Split(pathsPart, "|")
	for _, p := range paths {
		if _, ok := o.matchPatternWithVars(p, path); ok {
			return true
		}
	}
	return false
}

func (o *OIDCConnect) hasRequiredPermissions(
	rule, requiredPrivileges string,
	path string,
	userInfo *UserInfo,
) bool {
	parts := strings.Split(rule, ";")
	privilegesType := parts[len(parts)-1]
	userPrivileges := o.getUserPrivileges(privilegesType, userInfo)

	o.Log.Info("hasRequiredPermissions", "rule", rule, "requiredPrivileges", requiredPrivileges, "userPrivileges", userPrivileges)

	if len(parts) < 2 || len(parts) > 3 {
		for _, requiredPrivilege := range strings.Split(requiredPrivileges, "|") {
			if contains(userPrivileges, requiredPrivilege) {
				return true
			}
		}
		return false
	}

	for _, requiredPrivilege := range strings.Split(requiredPrivileges, "|") {
		pattern := parts[1]
		if variables, ok := o.matchPatternWithVars(pattern, path); ok {
			if o.isPrivilegeMatched(requiredPrivilege, userPrivileges, variables) {
				return true
			}
		}
	}

	return false
}

func (o *OIDCConnect) isPrivilegeMatched(requiredPrivilege string, userPrivileges []string, variables map[string]string) bool {
	for _, privilege := range userPrivileges {
		if o.matchPrivilege(requiredPrivilege, privilege, variables) {
			return true
		}
	}
	return false
}

func (o *OIDCConnect) getUserPrivileges(privilegesType string, userInfo *UserInfo) []string {
	if privilegesType == "roles" || privilegesType == "required_roles" || privilegesType == "required_role" {
		return userInfo.Roles
	} else if privilegesType == "groups" || privilegesType == "required_groups" || privilegesType == "required_group" {
		return userInfo.Groups
	}
	return []string{}
}

// PropagateUserInfo propagates the user info to the response headers.
func (o *OIDCConnect) PropagateUserInfo(resp *Response, userInfo *UserInfo) {
	if userInfo == nil {
		return
	}

	resp.Response.Header.Add("Auth-Handler", "oidc")
	resp.Response.Header.Add("X-Auth-User-Username", userInfo.Username)
	resp.Response.Header.Add("X-Auth-User-Email", userInfo.Email)
	resp.Response.Header.Add("X-Auth-User-Email-Verified", fmt.Sprintf("%v", userInfo.EmailVerified))
	resp.Response.Header.Add("X-Auth-User-Given-Name", userInfo.GivenName)
	resp.Response.Header.Add("X-Auth-User-Family-Name", userInfo.FamilyName)
	resp.Response.Header.Add("X-Auth-User-Nickname", userInfo.Nickname)
	resp.Response.Header.Add("X-Auth-User-Roles", strings.Join(userInfo.Roles, ","))
	resp.Response.Header.Add("X-Auth-User-Groups", strings.Join(userInfo.Groups, ","))
}

func (o *OIDCConnect) GetUserInfoDeprecated(ctx context.Context, state *store.OIDCState) (*UserInfo, Response, error) {
	if state == nil {
		return nil, createResponse(http.StatusUnauthorized), fmt.Errorf("state is nil")
	}

	verifier := o.provider.Verifier(&oidc.Config{
		ClientID:        o.OidcConfig.ClientID,
		SkipIssuerCheck: o.OidcConfig.SkipIssuerCheck,
	})

	// Verify token and signature.
	idToken, err := verifier.Verify(ctx, state.IDToken)
	if err != nil {
		o.Log.Info(fmt.Sprintf("failed to verify ID token: %v", err))
		return nil, createResponse(http.StatusUnauthorized), err
	}

	claims, err := o.extractClaims(idToken)
	if err != nil {
		return nil, createResponse(http.StatusUnauthorized), err
	}

	userInfo, err := o.populateUserInfo(claims)
	if err != nil {
		return nil, createResponse(http.StatusUnauthorized), err
	}

	if err := o.verifyAccessToken(idToken, state.AccessToken); err != nil {
		return nil, createResponse(http.StatusUnauthorized), err
	}

	roles, groups, err := o.extractRolesAndGroups(state.AccessToken)
	if err != nil {
		return nil, createResponse(http.StatusUnauthorized), err
	}

	userInfo.Roles = roles
	userInfo.Groups = groups

	return &userInfo, createResponse(http.StatusOK), nil
}

func (o *OIDCConnect) GetUserInfo(ctx context.Context, state *store.OIDCState) (*UserInfo, Response, error) {
	if state == nil {
		return nil, createResponse(http.StatusUnauthorized), fmt.Errorf("state is nil")
	}

	info, err := o.provider.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: state.AccessToken,
	}))
	if err != nil {
		return nil, createResponse(http.StatusUnauthorized), err
	}

	var userInfo UserInfo
	if err := info.Claims(&userInfo); err != nil {
		return nil, createResponse(http.StatusUnauthorized), err
	}

	return &userInfo, createResponse(http.StatusOK), nil
}

func (o *OIDCConnect) extractClaims(idToken *oidc.IDToken) (map[string]interface{}, error) {
	var claims json.RawMessage
	if err := idToken.Claims(&claims); err != nil {
		o.Log.Error(err, "error decoding ID token")
		return nil, err
	}

	var claimsMap map[string]interface{}
	if err := json.Unmarshal(claims, &claimsMap); err != nil {
		o.Log.Error(err, "error unmarshaling claims")
		return nil, err
	}

	return claimsMap, nil
}

func (o *OIDCConnect) populateUserInfo(claims map[string]interface{}) (UserInfo, error) {
	userInfo := UserInfo{}

	for k, v := range claims {
		switch k {
		case "username":
			userInfo.Username = v.(string)
		case "email":
			userInfo.Email = v.(string)
		case "email_verified":
			userInfo.EmailVerified = v.(bool)
		case "given_name":
			userInfo.GivenName = v.(string)
		case "family_name":
			userInfo.FamilyName = v.(string)
		case "nickname":
			userInfo.Nickname = v.(string)
		}
	}

	return userInfo, nil
}

func (o *OIDCConnect) verifyAccessToken(idToken *oidc.IDToken, accessToken string) error {
	if accessToken != "" {
		if err := idToken.VerifyAccessToken(accessToken); err != nil {
			o.Log.Error(err, "access token not verified")
			return err
		}
	}
	return nil
}

func (o *OIDCConnect) extractRolesAndGroups(accessToken string) ([]string, []string, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(accessToken, jwt.MapClaims{})
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing token: %v", err)
	}

	roles := []string{}
	groups := []string{}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		o.Log.Info("get user infos", "claims", claims)
		for k, v := range claims {
			switch k {
			case "realm_access":
				realmAccess := v.(map[string]interface{})
				if rolesList, ok := realmAccess["roles"].([]interface{}); ok {
					for _, role := range rolesList {
						roles = append(roles, role.(string))
					}
				}
			case "groups":
				for _, group := range v.([]interface{}) {
					groups = append(groups, group.(string))
				}
			}
		}
	}

	return roles, groups, nil
}

// initProvider initialize oidc provide with ths given issuer URL. return oidc.Provider.
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

		RedirectURL: o.OidcConfig.RedirectURL + o.OidcConfig.RedirectPath,
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

// contains checks if a string is present in a slice of strings.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

// matchRole checks if the user's role matches the required role.
func (o *OIDCConnect) matchPrivilege(requiredPrivilege, userPrivilege string, variables map[string]string) bool {
	// Replace variables in the required role with extracted values
	o.Log.Info("matchPrivilege", "requiredPrivilege", requiredPrivilege, "userPrivilege", userPrivilege, "variables", variables)
	for key, value := range variables {
		requiredPrivilege = strings.ReplaceAll(requiredPrivilege, "$"+key, value)
	}
	o.Log.Info("aftermatchPrivilege", "requiredPrivilege", requiredPrivilege, "userPrivilege", userPrivilege, "variables", variables)

	return requiredPrivilege == userPrivilege
}

// matchPatternWithVars checks if the path matches the pattern and extracts variables.
func (o *OIDCConnect) matchPatternWithVars(pattern, path string) (map[string]string, bool) {
	o.Log.Info("matchPatternWithVars 0", "pattern", pattern, "path", path)
	// Replace variables in the pattern with regular expressions
	re := regexp.MustCompile(`\$(\w+)`)
	patternRegex := re.ReplaceAllStringFunc(pattern, func(s string) string {
		return `(?P<` + s[1:] + `>[^/]+)`
	})

	// Replace * with [^/]* to match zero or more characters that are not /
	patternRegex = strings.ReplaceAll(patternRegex, "*", "[^/]*")

	// Ensure that /[^/]*/ is replaced with /[^/]+/ to avoid empty segments
	patternRegex = strings.ReplaceAll(patternRegex, "/[^/]*/", "/[^/]+/")

	// Handle trailing /* by allowing an optional segment
	if strings.HasSuffix(pattern, "/*") {
		patternRegex = strings.TrimSuffix(patternRegex, "/[^/]*") + "(/[^/]+)?"
	}

	// Allow an optional trailing slash
	patternRegex = patternRegex + "/?"

	// Check if the path matches the pattern
	re = regexp.MustCompile("^" + patternRegex + "$")
	match := re.FindStringSubmatch(path)
	if match == nil {
		o.Log.Info("matchPatternWithVars 1", "pattern", pattern, "path", path, "match", match)
		return nil, false
	}

	o.Log.Info("matchPatternWithVars okkk", "pattern", pattern, "path", path, "match", match)
	// Extract variables
	variables := make(map[string]string)
	for i, name := range re.SubexpNames() {
		if i != 0 && name != "" {
			variables[name] = match[i]
		}
	}

	return variables, true
}
