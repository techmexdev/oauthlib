package oauthlib

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// A ResponseError is returned when a request to the server is invalid.
type ResponseError struct {
	Code  int    `json:"-"`
	Type  string `json:"error"`
	Title string `json:"-"`
	Desc  string `json:"error_description"`
}

// Error returns a string representation of the error.
func (e *ResponseError) Error() string {
	return fmt.Sprintf("error: %s", strings.ToLower(e.Title))
}

// JSON returns the json encoded representation of the error.
func (e *ResponseError) JSON() []byte {
	val, _ := json.Marshal(e)
	return val
}

// Request errors, see:
// http://tools.ietf.org/html/rfc6749#section-4.1.2.1
// http://tools.ietf.org/html/rfc6749#section-4.2.2.1
// http://tools.ietf.org/html/rfc6749#section-5.2
// http://tools.ietf.org/html/rfc6749#section-7.2
var (
	// ErrInvalidRequest is the error for an invalid request.
	ErrInvalidRequest = &ResponseError{
		Code:  http.StatusOK,
		Type:  "invalid_request",
		Title: "Invalid Request",
		Desc:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.",
	}

	// ErrUnauthorizedClient is the error for an authorized client.
	ErrUnauthorizedClient = &ResponseError{
		Code:  http.StatusOK,
		Type:  "unauthorized_client",
		Title: "Unauthorized Client",
		Desc:  "The client is not authorized to request a token using this method.",
	}

	// ErrAccessDenied is the error when access is denied.
	ErrAccessDenied = &ResponseError{
		Code:  http.StatusOK,
		Type:  "access_denied",
		Title: "Access Denied",
		Desc:  "The resource owner or authorization server denied the request.",
	}

	// ErrUnsupportedResponseType is when the response type requested is not
	// supported.
	ErrUnsupportedResponseType = &ResponseError{
		Code:  http.StatusOK,
		Type:  "unsupported_response_type",
		Title: "Unsupported Response Type",
		Desc:  "The authorization server does not support obtaining a token using this method.",
	}

	// ErrInvalidScope is the error when the scope is invalid.
	ErrInvalidScope = &ResponseError{
		Code:  http.StatusOK,
		Type:  "invalid_scope",
		Title: "Invalid Scope",
		Desc:  "The requested scope is invalid, unknown, or malformed.",
	}

	// ErrServerError is the error when the server has encountered an error and
	// cannot fulfill the request.
	ErrServerError = &ResponseError{
		Code:  http.StatusOK,
		Type:  "server_error",
		Title: "Server Error",
		Desc:  "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
	}

	// ErrTemporarilyUnavailable is the error when the server is temporarily
	// unavailable.
	ErrTemporarilyUnavailable = &ResponseError{
		Code:  http.StatusServiceUnavailable,
		Type:  "temporarily_unavailable",
		Title: "Temporarily Unavailable",
		Desc:  "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.",
	}

	// ErrUnsupportedGrantType is is the error when the supplied grant type is
	// not supported.
	ErrUnsupportedGrantType = &ResponseError{
		Code:  http.StatusOK,
		Type:  "unsupported_grant_type",
		Title: "Unsupported Grant Type",
		Desc:  "The authorization grant type is not supported by the authorization server.",
	}

	// ErrInvalidGrant is the error when an authorization request supplies an
	// invalid grant.
	ErrInvalidGrant = &ResponseError{
		Code:  http.StatusOK,
		Type:  "invalid_grant",
		Title: "Invalid Grant",
		Desc:  "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.",
	}

	// ErrInvalidClient is the error when the requesting client is invalid.
	ErrInvalidClient = &ResponseError{
		Code:  http.StatusOK,
		Type:  "invalid_client",
		Title: "Invalid Client",
		Desc:  "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).",
	}
)
