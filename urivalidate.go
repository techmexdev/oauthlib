package oauthlib

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// error returned when validation don't match
type UriValidationError string

func (e UriValidationError) Error() string {
	return string(e)
}

func newUriValidationError(msg string, base string, redirect string) UriValidationError {
	return UriValidationError(fmt.Sprintf("%s: %s / %s", msg, base, redirect))
}

// ValidateUriList validates that redirectURI is contained in baseUriList.
// baseUriList may be a string separated by separator.
// If separator is blank, validate only 1 URI.
func ValidateUriList(baseUriList string, redirectURI string, separator string) error {
	// make a list of uris
	var slist []string
	if separator != "" {
		slist = strings.Split(baseUriList, separator)
	} else {
		slist = make([]string, 0)
		slist = append(slist, baseUriList)
	}

	for _, sitem := range slist {
		err := ValidateUri(sitem, redirectURI)
		// validated, return no error
		if err == nil {
			return nil
		}

		// if there was an error that is not a validation error, return it
		if _, iok := err.(UriValidationError); !iok {
			return err
		}
	}

	return newUriValidationError("urls don't validate", baseUriList, redirectURI)
}

// ValidateUri validates that redirectURI is contained in baseUri
func ValidateUri(baseUri string, redirectURI string) error {
	if baseUri == "" || redirectURI == "" {
		return errors.New("urls cannot be blank.")
	}

	// parse base url
	base, err := url.Parse(baseUri)
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
		return errors.New("url must not include fragment.")
	}

	// check if urls match
	if base.Scheme != redirect.Scheme {
		return newUriValidationError("scheme mismatch", baseUri, redirectURI)
	}
	if base.Host != redirect.Host {
		return newUriValidationError("host mismatch", baseUri, redirectURI)
	}

	// allow exact path matches
	if base.Path == redirect.Path {
		return nil
	}

	// ensure prefix matches are actually subpaths
	requiredPrefix := strings.TrimRight(base.Path, "/") + "/"
	if !strings.HasPrefix(redirect.Path, requiredPrefix) {
		return newUriValidationError("path is not a subpath", baseUri, redirectURI)
	}

	// ensure prefix matches don't contain path traversals
	for _, s := range strings.Split(strings.TrimPrefix(redirect.Path, requiredPrefix), "/") {
		if s == ".." {
			return newUriValidationError("subpath cannot contain path traversal", baseUri, redirectURI)
		}
	}

	return nil
}

// Returns the first uri from an uri list
func FirstUri(baseUriList string, separator string) string {
	if separator != "" {
		slist := strings.Split(baseUriList, separator)
		if len(slist) > 0 {
			return slist[0]
		}
	} else {
		return baseUriList
	}

	return ""
}
