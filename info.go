package oauthlib

import (
	"net/http"
	"time"
)

// InfoRequest is a request for information about some AccessGrant
type InfoRequest struct {
	Code        string       // Code to look up
	AccessGrant *AccessGrant // AccessGrant associated with Code
}

// HandleInfoRequest is an http.HandlerFunc for server information
// NOT an RFC specification.
func (s *Server) HandleInfoRequest(w *Response, r *http.Request) *InfoRequest {
	err := r.ParseForm()
	if err != nil {
		w.SetError(ErrInvalidRequest)
		w.InternalError = err
		return nil
	}

	bearer := checkBearerAuth(r)
	if bearer == nil {
		w.SetError(ErrInvalidRequest)
		return nil
	}

	// generate info request
	ret := &InfoRequest{
		Code: bearer.Code,
	}

	if ret.Code == "" {
		w.SetError(ErrInvalidRequest)
		return nil
	}

	// load access data
	ret.AccessGrant, err = w.Storage.LoadAccessGrant(ret.Code)
	if err != nil {
		w.SetError(ErrInvalidRequest)
		w.InternalError = err
		return nil
	}
	if ret.AccessGrant == nil {
		w.SetError(ErrInvalidRequest)
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
	if ret.AccessGrant.IsExpiredAt(s.Now()) {
		w.SetError(ErrInvalidGrant)
		return nil
	}

	return ret
}

// FinishInfoRequest finalizes the request handled by HandleInfoRequest
func (s *Server) FinishInfoRequest(w *Response, r *http.Request, ir *InfoRequest) {
	// don't process if is already an error
	if w.IsError {
		return
	}

	// output data
	w.Output["client_id"] = ir.AccessGrant.Client.GetId()
	w.Output["access_token"] = ir.AccessGrant.AccessToken
	w.Output["token_type"] = s.Config.TokenType
	w.Output["expires_in"] = ir.AccessGrant.CreatedAt.Add(time.Duration(ir.AccessGrant.ExpiresIn)*time.Second).Sub(s.Now()) / time.Second
	if ir.AccessGrant.RefreshToken != "" {
		w.Output["refresh_token"] = ir.AccessGrant.RefreshToken
	}
	if ir.AccessGrant.Scope != "" {
		w.Output["scope"] = ir.AccessGrant.Scope
	}
}
