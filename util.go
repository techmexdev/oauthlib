package oauthlib

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

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
func validateURIList(baseURI string, redirectURI string, sep string) error {
	// make a list of uris
	slist := []string{baseURI}
	if sep != "" {
		slist = strings.Split(baseURI, sep)
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
