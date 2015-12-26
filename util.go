package oauthlib

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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

// checkBasicAuth checks the authorization header data for correct basic auth.
func checkBasicAuth(r *http.Request) (*BasicAuth, error) {
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

// checkBearerAuth checks the bearer auth.
//
// Return "Bearer" token from request. The header has precedence over query
// string.
func checkBearerAuth(r *http.Request) *BearerAuth {
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

	auth, err := checkBasicAuth(r)
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

// URIValidationError is the error returned when the passed uri does not pass
// validation.
type URIValidationError string

// Error satisfies the error interface.
func (e URIValidationError) Error() string {
	return string(e)
}

// newURIValidationError does something
func newURIValidationError(msg string, base string, redirect string) URIValidationError {
	return URIValidationError(fmt.Sprintf("%s: %s / %s", msg, base, redirect))
}

// validateURIList validates that redirectURI is contained in baseURI.
// baseURIList may be a string separated by separator.
// If separator is blank, validate only 1 URI.
func validateURIList(baseURI string, redirectURI string, separator string) error {
	// make a list of uris
	var slist []string
	if separator != "" {
		slist = strings.Split(baseURI, separator)
	} else {
		slist = make([]string, 0)
		slist = append(slist, baseURI)
	}

	for _, sitem := range slist {
		err := validateURI(sitem, redirectURI)
		// validated, return no error
		if err == nil {
			return nil
		}

		// if there was an error that is not a validation error, return it
		if _, iok := err.(URIValidationError); !iok {
			return err
		}
	}

	return newURIValidationError("urls don't validate", baseURI, redirectURI)
}

// validateURI validates that redirectURI is contained in baseURI
func validateURI(baseURI string, redirectURI string) error {
	if baseURI == "" || redirectURI == "" {
		return errors.New("urls cannot be blank")
	}

	// parse base url
	base, err := url.Parse(baseURI)
	if err != nil {
		return err
	}

	// parse passed url
	redirect, err := url.Parse(redirectURI)
	if err != nil {
		return err
	}

	// must not have fragment
	if base.Fragment != "" || redirect.Fragment != "" {
		return errors.New("url must not include fragment")
	}

	// check if urls match
	if base.Scheme != redirect.Scheme {
		return newURIValidationError("scheme mismatch", baseURI, redirectURI)
	}
	if base.Host != redirect.Host {
		return newURIValidationError("host mismatch", baseURI, redirectURI)
	}

	// allow exact path matches
	if base.Path == redirect.Path {
		return nil
	}

	// ensure prefix matches are actually subpaths
	requiredPrefix := strings.TrimRight(base.Path, "/") + "/"
	if !strings.HasPrefix(redirect.Path, requiredPrefix) {
		return newURIValidationError("path is not a subpath", baseURI, redirectURI)
	}

	// ensure prefix matches don't contain path traversals
	for _, s := range strings.Split(strings.TrimPrefix(redirect.Path, requiredPrefix), "/") {
		if s == ".." {
			return newURIValidationError("subpath cannot contain path traversal", baseURI, redirectURI)
		}
	}

	return nil
}

// firstURI returns the first uri from an uri list.
func firstURI(baseURI string, sep string) string {
	if sep == "" {
		return baseURI
	}

	return strings.Split(baseURI, sep)[0]
}
