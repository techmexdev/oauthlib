package oauthlib

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// ResponseData for response output.
type ResponseData map[string]interface{}

// ResponseType enum.
type ResponseType int

const (
	// DATA response type.
	DATA ResponseType = iota

	// REDIRECT response type.
	REDIRECT
)

// Response is a server response.
type Response struct {
	ResponseType       ResponseType
	StatusCode         int
	StatusText         string
	HttpStatusCode     int
	URL                string
	Output             ResponseData
	Headers            http.Header
	IsError            bool
	ErrorId            string
	InternalError      error
	RedirectInFragment bool

	// Storage to use in this response - required
	Storage Storage
}

// NewResponse builds a new server response.
func NewResponse(storage Storage) *Response {
	r := &Response{
		ResponseType:   DATA,
		StatusCode:     200,
		HttpStatusCode: 200,
		Output:         make(ResponseData),
		Headers:        make(http.Header),
		IsError:        false,
		Storage:        storage,
	}
	r.Headers.Add(
		"Cache-Control",
		"no-cache, no-store, max-age=0, must-revalidate",
	)
	r.Headers.Add("Pragma", "no-cache")
	r.Headers.Add("Expires", "Fri, 01 Jan 1990 00:00:00 GMT")
	return r
}

// SetError sets an error id and description on the Response
// state and uri are left blank
func (r *Response) SetError(e *ResponseError, state ...string) {
	// set error parameters
	r.IsError = true
	r.ErrorId = e.Type
	r.StatusCode = r.HttpStatusCode
	if r.StatusCode != http.StatusOK {
		r.StatusText = e.Desc
	} else {
		r.StatusText = ""
	}
	r.Output = make(ResponseData) // clear output
	r.Output["error"] = e.Type
	r.Output["error_description"] = e.Desc
	/*if uri != "" {
		r.Output["error_uri"] = uri
	}*/

	if len(state) > 0 && state[0] != "" {
		r.Output["state"] = state[0]
	}
}

// SetRedirect changes the response to redirect to the given url.
func (r *Response) SetRedirect(url string) {
	// set redirect parameters
	r.ResponseType = REDIRECT
	r.URL = url
}

// SetRedirectFragment sets redirect values to be passed in fragment instead of
// as query parameters.
func (r *Response) SetRedirectFragment(f bool) {
	r.RedirectInFragment = f
}

// GetRedirectURL returns the redirect url with all query string parameters.
func (r *Response) GetRedirectURL() (string, error) {
	if r.ResponseType != REDIRECT {
		return "", errors.New("Not a redirect response")
	}

	u, err := url.Parse(r.URL)
	if err != nil {
		return "", err
	}

	// add parameters
	q := u.Query()
	for n, v := range r.Output {
		q.Set(n, fmt.Sprint(v))
	}
	if r.RedirectInFragment {
		u.RawQuery = ""
		u.Fragment, err = url.QueryUnescape(q.Encode())
		if err != nil {
			return "", err
		}
	} else {
		u.RawQuery = q.Encode()
	}

	return u.String(), nil
}
