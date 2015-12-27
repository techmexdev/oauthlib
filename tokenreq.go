package oauthlib

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

// GrantType are the OAuth param options for `grant_type`
type GrantType string

func (gt GrantType) String() string {
	return string(gt)
}

const (
	// AuthorizationCodeGrant is the authorization_code grant type.
	AuthorizationCodeGrant GrantType = "authorization_code"

	// RefreshTokenGrant is the refresh_token grant type.
	RefreshTokenGrant GrantType = "refresh_token"

	// PasswordGrant is the password grant type.
	PasswordGrant GrantType = "password"

	// ClientCredentialsGrant is the client_credentials grant type.
	ClientCredentialsGrant GrantType = "client_credentials"

	// AssertionGrant is the assertion grant type.
	AssertionGrant GrantType = "assertion"

	// ImplicitGrant is the __implicit grant type.
	ImplicitGrant GrantType = "__implicit"
)

// TokenReq is a request for access tokens.
type TokenReq struct {
	// GrantType is the requested grant type.
	GrantType GrantType

	// Code is the request code.
	Code string

	// Client information.
	Client Client

	// AuthorizeData is the authorize data.
	AuthorizeData *AuthorizeData

	// AccessGrant is the provided access grant.
	AccessGrant *AccessGrant

	// ForceAccessGrant if provided forces finish to use this access data, to
	// allow access data reuse.
	ForceAccessGrant *AccessGrant

	// RedirectURI is the request redirect uri.
	RedirectURI string

	// Scope is the requested scope.
	Scope string

	// Username is the provided username in the request.
	Username string

	// Password is the provided password in the request.
	Password string

	// AssertionType is the provided assertion type in the request.
	AssertionType string

	// Assertion is the provided assertion in the request.
	Assertion string

	// Authorized toggles if request is authorized.
	Authorized bool

	// Expiration is the token expiration in seconds.
	Expiration int32

	// Set if a refresh token should be generated
	GenerateRefresh bool

	// Data to be passed to storage. Not used by the library.
	UserData interface{}
}

// AccessGrant represents an access grant (tokens, expiration, client, etc)
type AccessGrant struct {
	// Client information
	Client Client

	// Authorize data, for authorization code
	AuthorizeData *AuthorizeData

	// Previous access data, for refresh token
	AccessGrant *AccessGrant

	// Access token
	AccessToken string

	// Refresh Token. Can be blank
	RefreshToken string

	// Token expiration in seconds
	ExpiresIn int32

	// Requested scope
	Scope string

	// Redirect URI from request
	RedirectURI string

	// Date created
	CreatedAt time.Time

	// Data to be passed to storage. Not used by the library.
	UserData interface{}
}

// IsExpired returns true if access expired
func (d *AccessGrant) IsExpired() bool {
	return d.IsExpiredAt(time.Now())
}

// IsExpiredAt returns true if access expires at time 't'
func (d *AccessGrant) IsExpiredAt(t time.Time) bool {
	return d.ExpireAt().Before(t)
}

// ExpireAt returns the expiration date
func (d *AccessGrant) ExpireAt() time.Time {
	return d.CreatedAt.Add(time.Duration(d.ExpiresIn) * time.Second)
}

// AccessTokenGen generates access tokens
type AccessTokenGen interface {
	GenerateAccessToken(data *AccessGrant, generaterefresh bool) (accesstoken string, refreshtoken string, err error)
}

// HandleTokenReq is the http.HandlerFunc for handling access token requests
func (s *Server) HandleTokenReq(w *Response, r *http.Request) *TokenReq {
	if r.Method != "POST" {
		w.SetError(ErrInvalidRequest)
		w.InternalError = errors.New("request must be POST")
		return nil
	}

	err := r.ParseForm()
	if err != nil {
		w.SetError(ErrInvalidRequest)
		w.InternalError = err
		return nil
	}

	grantType := GrantType(r.Form.Get("grant_type"))
	if !s.Config.isGrantTypeAllowed(grantType) {
		w.SetError(ErrUnsupportedGrantType)
		return nil
	}

	switch grantType {
	case AuthorizationCodeGrant:
		return s.handleAuthorizationCodeRequest(w, r)
	case RefreshTokenGrant:
		return s.handleRefreshTokenRequest(w, r)
	case PasswordGrant:
		return s.handlePasswordRequest(w, r)
	case ClientCredentialsGrant:
		return s.handleClientCredentialsRequest(w, r)
	case AssertionGrant:
		return s.handleAssertionRequest(w, r)
	}

	w.SetError(ErrUnsupportedGrantType)
	return nil
}

func (s *Server) handleAuthorizationCodeRequest(w *Response, r *http.Request) *TokenReq {
	// get client authentication
	auth := s.getClientAuth(w, r)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &TokenReq{
		GrantType:       AuthorizationCodeGrant,
		Code:            r.Form.Get("code"),
		RedirectURI:     r.Form.Get("redirect_uri"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
		//HttpRequest:     r,
	}

	// "code" is required
	if ret.Code == "" {
		w.SetError(ErrInvalidGrant)
		return nil
	}

	// must have a valid client
	if ret.Client = getClient(auth, w.Storage, w); ret.Client == nil {
		return nil
	}

	// must be a valid authorization code
	var err error
	ret.AuthorizeData, err = w.Storage.LoadAuthorizeData(ret.Code)
	if err != nil {
		w.SetError(ErrInvalidGrant)
		w.InternalError = err
		return nil
	}
	if ret.AuthorizeData == nil {
		w.SetError(ErrUnauthorizedClient)
		return nil
	}
	if ret.AuthorizeData.Client == nil {
		w.SetError(ErrUnauthorizedClient)
		return nil
	}
	if ret.AuthorizeData.Client.GetRedirectURI() == "" {
		w.SetError(ErrUnauthorizedClient)
		return nil
	}
	if ret.AuthorizeData.IsExpiredAt(s.Now()) {
		w.SetError(ErrInvalidGrant)
		return nil
	}

	// code must be from the client
	if ret.AuthorizeData.Client.GetID() != ret.Client.GetID() {
		w.SetError(ErrInvalidGrant)
		return nil
	}

	// check redirect uri
	if ret.RedirectURI == "" {
		ret.RedirectURI = firstURI(ret.Client.GetRedirectURI(), s.Config.RedirectURISeparator)
	}
	if err = validateURIList(ret.Client.GetRedirectURI(), ret.RedirectURI, s.Config.RedirectURISeparator); err != nil {
		w.SetError(ErrInvalidRequest)
		w.InternalError = err
		return nil
	}
	if ret.AuthorizeData.RedirectURI != ret.RedirectURI {
		w.SetError(ErrInvalidRequest)
		w.InternalError = errors.New("redirect uri is different")
		return nil
	}

	// set rest of data
	ret.Scope = ret.AuthorizeData.Scope
	ret.UserData = ret.AuthorizeData.UserData

	return ret
}

func extraScopes(accessScopes, refreshScopes string) bool {
	accessScopesList := strings.Split(accessScopes, ",")
	refreshScopesList := strings.Split(refreshScopes, ",")

	accessMap := make(map[string]int)

	for _, scope := range accessScopesList {
		if scope == "" {
			continue
		}
		accessMap[scope] = 1
	}

	for _, scope := range refreshScopesList {
		if scope == "" {
			continue
		}
		if _, ok := accessMap[scope]; !ok {
			return true
		}
	}
	return false
}

func (s *Server) handleRefreshTokenRequest(w *Response, r *http.Request) *TokenReq {
	// get client authentication
	auth := s.getClientAuth(w, r)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &TokenReq{
		GrantType:       RefreshTokenGrant,
		Code:            r.Form.Get("refresh_token"),
		Scope:           r.Form.Get("scope"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
	}

	// "refresh_token" is required
	if ret.Code == "" {
		w.SetError(ErrInvalidGrant)
		return nil
	}

	// must have a valid client
	if ret.Client = getClient(auth, w.Storage, w); ret.Client == nil {
		return nil
	}

	// must be a valid refresh code
	var err error
	ret.AccessGrant, err = w.Storage.LoadRefreshGrant(ret.Code)
	if err != nil {
		w.SetError(ErrInvalidGrant)
		w.InternalError = err
		return nil
	}
	if ret.AccessGrant == nil {
		w.SetError(ErrUnauthorizedClient)
		return nil
	}
	if ret.AccessGrant.Client == nil {
		w.SetError(ErrUnauthorizedClient)
		return nil
	}
	if ret.AccessGrant.Client.GetRedirectURI() == "" {
		w.SetError(ErrUnauthorizedClient)
		return nil
	}

	// client must be the same as the previous token
	if ret.AccessGrant.Client.GetID() != ret.Client.GetID() {
		w.SetError(ErrInvalidClient)
		w.InternalError = errors.New("client id must be the same from previous token")
		return nil

	}

	// set rest of data
	ret.RedirectURI = ret.AccessGrant.RedirectURI
	ret.UserData = ret.AccessGrant.UserData
	if ret.Scope == "" {
		ret.Scope = ret.AccessGrant.Scope
	}

	if extraScopes(ret.AccessGrant.Scope, ret.Scope) {
		w.SetError(ErrAccessDenied)
		w.InternalError = errors.New("the requested scope must not include any scope not originally granted by the resource owner")
		return nil
	}

	return ret
}

// getClientAuth retrieves the BasicAuth from the http.Request headers.
func (s *Server) getClientAuth(w *Response, r *http.Request) *BasicAuth {
	auth, err := s.checkBasicAuth(r)
	if err != nil {
		w.SetError(ErrInvalidRequest)
		w.InternalError = err
		return nil
	}

	if auth == nil {
		w.SetError(ErrInvalidRequest)
		w.InternalError = errors.New("client authentication not sent")
		return nil
	}

	return auth
}

func (s *Server) handlePasswordRequest(w *Response, r *http.Request) *TokenReq {
	// get client auth
	auth := s.getClientAuth(w, r)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &TokenReq{
		GrantType:       PasswordGrant,
		Username:        r.Form.Get("username"),
		Password:        r.Form.Get("password"),
		Scope:           r.Form.Get("scope"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
		//HttpRequest:     r,
	}

	// "username" and "password" is required
	if ret.Username == "" || ret.Password == "" {
		w.SetError(ErrInvalidGrant)
		return nil
	}

	// must have a valid client
	if ret.Client = getClient(auth, w.Storage, w); ret.Client == nil {
		return nil
	}

	// set redirect uri
	ret.RedirectURI = firstURI(ret.Client.GetRedirectURI(), s.Config.RedirectURISeparator)

	return ret
}

func (s *Server) handleClientCredentialsRequest(w *Response, r *http.Request) *TokenReq {
	// get client authentication
	auth := s.getClientAuth(w, r)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &TokenReq{
		GrantType:       ClientCredentialsGrant,
		Scope:           r.Form.Get("scope"),
		GenerateRefresh: false,
		Expiration:      s.Config.AccessExpiration,
		//HttpRequest:     r,
	}

	// must have a valid client
	if ret.Client = getClient(auth, w.Storage, w); ret.Client == nil {
		return nil
	}

	// set redirect uri
	ret.RedirectURI = firstURI(ret.Client.GetRedirectURI(), s.Config.RedirectURISeparator)

	return ret
}

func (s *Server) handleAssertionRequest(w *Response, r *http.Request) *TokenReq {
	// get client authentication
	auth := s.getClientAuth(w, r)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &TokenReq{
		GrantType:       AssertionGrant,
		Scope:           r.Form.Get("scope"),
		AssertionType:   r.Form.Get("assertion_type"),
		Assertion:       r.Form.Get("assertion"),
		GenerateRefresh: false, // assertion should NOT generate a refresh token, per the RFC
		Expiration:      s.Config.AccessExpiration,
		//HttpRequest:     r,
	}

	// "assertion_type" and "assertion" is required
	if ret.AssertionType == "" || ret.Assertion == "" {
		w.SetError(ErrInvalidGrant)
		return nil
	}

	// must have a valid client
	if ret.Client = getClient(auth, w.Storage, w); ret.Client == nil {
		return nil
	}

	// set redirect uri
	ret.RedirectURI = firstURI(ret.Client.GetRedirectURI(), s.Config.RedirectURISeparator)

	return ret
}

// FinishTokenReq will finish the access request.
func (s *Server) FinishTokenReq(w *Response, r *http.Request, ar *TokenReq) {
	// don't process if is already an error
	if w.IsError {
		return
	}
	redirectURI := r.Form.Get("redirect_uri")
	// Get redirect uri from TokenReq if it's there (e.g., refresh token request)
	if ar.RedirectURI != "" {
		redirectURI = ar.RedirectURI
	}
	if ar.Authorized {
		var ret *AccessGrant
		var err error

		if ar.ForceAccessGrant == nil {
			// generate access token
			ret = &AccessGrant{
				Client:        ar.Client,
				AuthorizeData: ar.AuthorizeData,
				AccessGrant:   ar.AccessGrant,
				RedirectURI:   redirectURI,
				CreatedAt:     s.Now(),
				ExpiresIn:     ar.Expiration,
				UserData:      ar.UserData,
				Scope:         ar.Scope,
			}

			// generate access token
			ret.AccessToken, ret.RefreshToken, err = s.AccessTokenGen.GenerateAccessToken(ret, ar.GenerateRefresh)
			if err != nil {
				w.SetError(ErrServerError)
				w.InternalError = err
				return
			}
		} else {
			ret = ar.ForceAccessGrant
		}

		// save access token
		if err = w.Storage.SaveAccessGrant(ret); err != nil {
			w.SetError(ErrServerError)
			w.InternalError = err
			return
		}

		// remove authorization token
		if ret.AuthorizeData != nil {
			err := w.Storage.RemoveAuthorizeData(ret.AuthorizeData.Code)
			if err != nil {
				w.SetError(ErrServerError)
				return
			}
		}

		// remove previous access token
		if ret.AccessGrant != nil {
			if ret.AccessGrant.RefreshToken != "" {
				err := w.Storage.RemoveRefreshGrant(ret.AccessGrant.RefreshToken)
				if err != nil {
					w.SetError(ErrServerError)
					return
				}
			}
			err := w.Storage.RemoveAccessGrant(ret.AccessGrant.AccessToken)
			if err != nil {
				w.SetError(ErrServerError)
				return
			}
		}

		// output data
		w.Output["access_token"] = ret.AccessToken
		w.Output["token_type"] = s.Config.TokenType
		w.Output["expires_in"] = ret.ExpiresIn
		if ret.RefreshToken != "" {
			w.Output["refresh_token"] = ret.RefreshToken
		}
		if ar.Scope != "" {
			w.Output["scope"] = ar.Scope
		}
	} else {
		w.SetError(ErrAccessDenied)
	}
}

// Helper Functions

// getClient looks up and authenticates the basic auth using the given
// storage. Sets an error on the response if auth fails or a server error occurs.
func getClient(auth *BasicAuth, storage Storage, w *Response) Client {
	client, err := storage.GetClient(auth.Username)
	if err != nil {
		w.SetError(ErrServerError)
		w.InternalError = err
		return nil
	}
	if client == nil {
		w.SetError(ErrUnauthorizedClient)
		return nil
	}

	switch client := client.(type) {
	case ClientSecretMatcher:
		// Prefer the more secure method of giving the secret to the client for comparison
		if !client.ClientSecretMatches(auth.Password) {
			w.SetError(ErrUnauthorizedClient)
			return nil
		}
	default:
		// Fallback to the less secure method of extracting the plain text secret from the client for comparison
		if client.GetSecret() != auth.Password {
			w.SetError(ErrUnauthorizedClient)
			return nil
		}
	}

	if client.GetRedirectURI() == "" {
		w.SetError(ErrUnauthorizedClient)
		return nil
	}
	return client
}
