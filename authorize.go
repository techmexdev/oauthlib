package oauthlib

import (
	"net/http"
	"net/url"
	"time"
)

// AuthorizeRequest represents the authorize request information.
type AuthorizeRequest struct {
	// Type is the type of the authorize request.
	Type string

	// Client is the client information.
	Client Client

	// Scope is the request scope.
	Scope string

	// RedirectURI is the redirect uri for the request.
	RedirectURI string

	// State is the passed state in the request.
	State string

	// Authorized toggles if request is authorized
	Authorized bool

	// Expiration is the token expiration in seconds. Change if different from
	// default. If type = "token", this expiration will be for the ACCESS
	// token.
	Expiration int32

	// Data to be passed to storage. Not used by the library.
	UserData interface{}

	// HttpRequest *http.Request for special use
	HttpRequest *http.Request
}

// AuthorizeData is the authorization data.
type AuthorizeData struct {
	// Client information.
	Client Client

	// Code is the authorization code.
	Code string

	// ExpiresIn is the token expiration in seconds.
	ExpiresIn int32

	// Scope is the requested scope.
	Scope string

	// RedirectURI is the redirect uri from request.
	RedirectURI string

	// State is the passed state from request.
	State string

	// CreatedAt is the creation time.
	CreatedAt time.Time

	// Data to be passed to storage. Not used by the library.
	UserData interface{}
}

// IsExpired is true if authorization expired.
func (d *AuthorizeData) IsExpired() bool {
	return d.IsExpiredAt(time.Now())
}

// IsExpiredAt is true if authorization expires at time 't'
func (d *AuthorizeData) IsExpiredAt(t time.Time) bool {
	return d.ExpireAt().Before(t)
}

// ExpireAt returns the expiration date.
func (d *AuthorizeData) ExpireAt() time.Time {
	return d.CreatedAt.Add(time.Duration(d.ExpiresIn) * time.Second)
}

// AuthorizeTokenGen is the token generator interface.
type AuthorizeTokenGen interface {
	GenerateAuthorizeToken(data *AuthorizeData) (string, error)
}

// HandleAuthorizeRequest is the main http.HandlerFunc for handling
// authorization requests.
func (s *Server) HandleAuthorizeRequest(w *Response, r *http.Request) *AuthorizeRequest {
	err := r.ParseForm()
	if err != nil {
		w.SetError(ErrInvalidRequest)
		w.InternalError = err
		return nil
	}

	// create the authorization request
	unescapedURI, err := url.QueryUnescape(r.Form.Get("redirect_uri"))
	if err != nil {
		w.SetError(ErrInvalidRequest)
		w.InternalError = err
		return nil
	}

	ret := &AuthorizeRequest{
		State:       r.Form.Get("state"),
		Scope:       r.Form.Get("scope"),
		RedirectURI: unescapedURI,
		Authorized:  false,
		HttpRequest: r,
	}

	// must have a valid client
	ret.Client, err = w.Storage.GetClient(r.Form.Get("client_id"))
	if err != nil {
		w.SetError(ErrServerError, ret.State)
		w.InternalError = err
		return nil
	}
	if ret.Client == nil {
		w.SetError(ErrUnauthorizedClient, ret.State)
		return nil
	}
	if ret.Client.GetRedirectURI() == "" {
		w.SetError(ErrUnauthorizedClient, ret.State)
		return nil
	}

	// check redirect uri, if there are multiple client redirect uri's
	// don't set the uri
	if ret.RedirectURI == "" && firstURI(ret.Client.GetRedirectURI(), s.Config.RedirectURISeparator) == ret.Client.GetRedirectURI() {
		ret.RedirectURI = firstURI(ret.Client.GetRedirectURI(), s.Config.RedirectURISeparator)
	}

	if err = ValidateURIList(ret.Client.GetRedirectURI(), ret.RedirectURI, s.Config.RedirectURISeparator); err != nil {
		w.SetError(ErrInvalidRequest, ret.State)
		w.InternalError = err
		return nil
	}

	w.SetRedirect(ret.RedirectURI)

	responseType := r.Form.Get("response_type")
	if s.Config.isAuthorizeRequestTypeAllowed(responseType) {
		switch responseType {
		case "code":
			ret.Type = "code"
			ret.Expiration = s.Config.AuthorizationExpiration
		case "token":
			ret.Type = "token"
			ret.Expiration = s.Config.AccessExpiration
		default:
			// FIXME -- this should be an error!
		}
		return ret
	}

	w.SetError(ErrUnsupportedResponseType, ret.State)
	return nil
}

// FinishAuthorizeRequest finishes the authorize request.
func (s *Server) FinishAuthorizeRequest(w *Response, r *http.Request, ar *AuthorizeRequest) {
	// don't process if is already an error
	if w.IsError {
		return
	}

	// force redirect response
	w.SetRedirect(ar.RedirectURI)

	if ar.Authorized {
		if ar.Type == "token" {
			w.SetRedirectFragment(true)

			// generate token directly
			ret := &AccessRequest{
				GrantType:       ImplicitGrant,
				Code:            "",
				Client:          ar.Client,
				RedirectURI:     ar.RedirectURI,
				Scope:           ar.Scope,
				GenerateRefresh: false, // per the RFC, should NOT generate a refresh token in this case
				Authorized:      true,
				Expiration:      ar.Expiration,
				UserData:        ar.UserData,
			}

			s.FinishAccessRequest(w, r, ret)
			if ar.State != "" && w.InternalError == nil {
				w.Output["state"] = ar.State
			}
		} else {
			// generate authorization token
			ret := &AuthorizeData{
				Client:      ar.Client,
				CreatedAt:   s.Now(),
				ExpiresIn:   ar.Expiration,
				RedirectURI: ar.RedirectURI,
				State:       ar.State,
				Scope:       ar.Scope,
				UserData:    ar.UserData,
			}

			// generate token code
			code, err := s.AuthorizeTokenGen.GenerateAuthorizeToken(ret)
			if err != nil {
				w.SetError(ErrServerError, ar.State)
				w.InternalError = err
				return
			}
			ret.Code = code

			// save authorization token
			if err = w.Storage.SaveAuthorizeData(ret); err != nil {
				w.SetError(ErrServerError, ar.State)
				w.InternalError = err
				return
			}

			// redirect with code
			w.Output["code"] = ret.Code
			w.Output["state"] = ret.State
		}
	} else {
		// redirect with error
		w.SetError(ErrAccessDenied, ar.State)
	}
}
