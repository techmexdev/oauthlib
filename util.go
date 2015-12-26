package oauthlib

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// BasicAuth represent the basic authentication header.
type BasicAuth struct {
	Username string
	Password string
}

// BearerAuth represents the bearer authentication header.
type BearerAuth struct {
	Code string
}

// CheckBasicAuth checks the authorization header data for correct basic auth.
func CheckBasicAuth(r *http.Request) (*BasicAuth, error) {
	if r.Header.Get("Authorization") == "" {
		return nil, nil
	}

	s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 || s[0] != "Basic" {
		return nil, errors.New("Invalid authorization header")
	}

	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return nil, err
	}
	pair := strings.SplitN(string(b), ":", 2)
	if len(pair) != 2 {
		return nil, errors.New("Invalid authorization message")
	}

	return &BasicAuth{Username: pair[0], Password: pair[1]}, nil
}

// CheckBearerAuth checks the bearer auth.
//
// Return "Bearer" token from request. The header has precedence over query
// string.
func CheckBearerAuth(r *http.Request) *BearerAuth {
	authHeader := r.Header.Get("Authorization")
	authForm := r.Form.Get("code")
	if authHeader == "" && authForm == "" {
		return nil
	}

	token := authForm
	if authHeader != "" {
		s := strings.SplitN(authHeader, " ", 2)
		if (len(s) != 2 || s[0] != "Bearer") && token == "" {
			return nil
		}
		token = s[1]
	}
	return &BearerAuth{Code: token}
}

// getClientAuth checks client basic authentication in params if allowed,
// otherwise gets it from the header. Sets an error on the response if no auth
// is present or a server error occurs.
func getClientAuth(w *Response, r *http.Request, allowQueryParams bool) *BasicAuth {

	if allowQueryParams {
		// Allow for auth without password
		if _, hasSecret := r.Form["client_secret"]; hasSecret {
			auth := &BasicAuth{
				Username: r.Form.Get("client_id"),
				Password: r.Form.Get("client_secret"),
			}
			if auth.Username != "" {
				return auth
			}
		}
	}

	auth, err := CheckBasicAuth(r)
	if err != nil {
		w.SetError(ErrInvalidRequest)
		w.InternalError = err
		return nil
	}
	if auth == nil {
		w.SetError(ErrInvalidRequest)
		w.InternalError = errors.New("Client authentication not sent")
		return nil
	}
	return auth
}

// WriteJSON encodes the Response to JSON and writes to the http.ResponseWriter
func WriteJSON(w http.ResponseWriter, rs *Response) error {
	// Add headers
	for i, k := range rs.Headers {
		for _, v := range k {
			w.Header().Add(i, v)
		}
	}

	if rs.ResponseType == REDIRECT {
		// Output redirect with parameters
		u, err := rs.GetRedirectURL()
		if err != nil {
			return err
		}
		w.Header().Add("Location", u)
		w.WriteHeader(302)
	} else {
		// set content type if the response doesn't already have one associated with it
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(rs.StatusCode)

		encoder := json.NewEncoder(w)
		err := encoder.Encode(rs.Output)
		if err != nil {
			return err
		}
	}

	return nil
}
