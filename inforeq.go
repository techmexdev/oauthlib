package oauthlib

import (
	"net/http"
	"time"
)

// InfoReq is a request for information about some AccessGrant
type InfoReq struct {
	Code        string       // Code to look up
	AccessGrant *AccessGrant // AccessGrant associated with Code
}

// HandleInfoReq is an http.HandlerFunc for server information
// NOT an RFC specification.
func (s *Server) HandleInfoReq(w *Response, r *http.Request) *InfoReq {
	err := r.ParseForm()
	if err != nil {
		w.SetError(ErrInvalidRequest)
		w.InternalError = err
		return nil
	}

	bearer := s.checkBearerAuth(r)
	if bearer == nil {
		w.SetError(ErrInvalidRequest)
		return nil
	}

	// generate info request
	ret := &InfoReq{
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

// FinishInfoReq finalizes the request handled by HandleInfoReq
func (s *Server) FinishInfoReq(w *Response, r *http.Request, ir *InfoReq) {
	// don't process if is already an error
	if w.IsError {
		return
	}

	// output data
	w.Output["client_id"] = ir.AccessGrant.Client.GetID()
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
