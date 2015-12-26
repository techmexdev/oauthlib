package oauthlib

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

// GrantType is the type for OAuth param `grant_type`
type GrantType string

func (gt GrantType) String() string {
	return string(gt)
}

const (
	AuthorizationCodeGrant GrantType = "authorization_code"
	RefreshTokenGrant      GrantType = "refresh_token"
	PasswordGrant          GrantType = "password"
	ClientCredentialsGrant GrantType = "client_credentials"
	AssertionGrant         GrantType = "assertion"
	ImplicitGrant          GrantType = "__implicit"
)

// AccessRequest is a request for access tokens
type AccessRequest struct {
	GrantType     GrantType
	Code          string
	Client        Client
	AuthorizeData *AuthorizeData
	AccessGrant   *AccessGrant

	// Force finish to use this access data, to allow access data reuse
	ForceAccessGrant *AccessGrant
	RedirectURI      string
	Scope            string
	Username         string
	Password         string
	AssertionType    string
	Assertion        string

	// Set if request is authorized
	Authorized bool

	// Token expiration in seconds. Change if different from default
	Expiration int32

	// Set if a refresh token should be generated
	GenerateRefresh bool

	// Data to be passed to storage. Not used by the library.
	UserData interface{}

	// HttpRequest *http.Request for special use
	//HttpRequest *http.Request
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

	// Redirect Uri from request
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

// HandleAccessRequest is the http.HandlerFunc for handling access token requests
func (s *Server) HandleAccessRequest(w *Response, r *http.Request) *AccessRequest {
	// Only allow GET or POST
	if r.Method == "GET" {
		if !s.Config.AllowGetAccessRequest {
			w.SetError(ErrInvalidRequest)
			w.InternalError = errors.New("Request must be POST")
			return nil
		}
	} else if r.Method != "POST" {
		w.SetError(ErrInvalidRequest)
		w.InternalError = errors.New("Request must be POST")
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

func (s *Server) handleAuthorizationCodeRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
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
	if ret.AuthorizeData.Client.GetId() != ret.Client.GetId() {
		w.SetError(ErrInvalidGrant)
		return nil
	}

	// check redirect uri
	if ret.RedirectURI == "" {
		ret.RedirectURI = FirstUri(ret.Client.GetRedirectURI(), s.Config.RedirectURISeparator)
	}
	if err = ValidateUriList(ret.Client.GetRedirectURI(), ret.RedirectURI, s.Config.RedirectURISeparator); err != nil {
		w.SetError(ErrInvalidRequest)
		w.InternalError = err
		return nil
	}
	if ret.AuthorizeData.RedirectURI != ret.RedirectURI {
		w.SetError(ErrInvalidRequest)
		w.InternalError = errors.New("Redirect uri is different")
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

func (s *Server) handleRefreshTokenRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		GrantType:       RefreshTokenGrant,
		Code:            r.Form.Get("refresh_token"),
		Scope:           r.Form.Get("scope"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
		//HttpRequest:     r,
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
	if ret.AccessGrant.Client.GetId() != ret.Client.GetId() {
		w.SetError(ErrInvalidClient)
		w.InternalError = errors.New("Client id must be the same from previous token")
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

func (s *Server) handlePasswordRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
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
	ret.RedirectURI = FirstUri(ret.Client.GetRedirectURI(), s.Config.RedirectURISeparator)

	return ret
}

func (s *Server) handleClientCredentialsRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
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
	ret.RedirectURI = FirstUri(ret.Client.GetRedirectURI(), s.Config.RedirectURISeparator)

	return ret
}

func (s *Server) handleAssertionRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
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
	ret.RedirectURI = FirstUri(ret.Client.GetRedirectURI(), s.Config.RedirectURISeparator)

	return ret
}

func (s *Server) FinishAccessRequest(w *Response, r *http.Request, ar *AccessRequest) {
	// don't process if is already an error
	if w.IsError {
		return
	}
	redirectURI := r.Form.Get("redirect_uri")
	// Get redirect uri from AccessRequest if it's there (e.g., refresh token request)
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
			w.Storage.RemoveAuthorizeData(ret.AuthorizeData.Code)
		}

		// remove previous access token
		if ret.AccessGrant != nil {
			if ret.AccessGrant.RefreshToken != "" {
				w.Storage.RemoveRefreshGrant(ret.AccessGrant.RefreshToken)
			}
			w.Storage.RemoveAccessGrant(ret.AccessGrant.AccessToken)
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
