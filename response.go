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
	ErrorType          string
	InternalError      error
	RedirectInFragment bool

	// Storage to use in this response - required
	Storage Storage
}

// NewResponse builds a new server response.
func NewResponse(storage Storage) *Response {
	r := &Response{
		ResponseType:   DATA,
		StatusCode:     http.StatusOK,
		HttpStatusCode: http.StatusOK,
		Output:         ResponseData{},
		Headers:        http.Header{},
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
	r.ErrorType = e.Type
	r.StatusCode = r.HttpStatusCode
	if r.StatusCode != http.StatusOK {
		r.StatusText = e.Desc
	} else {
		r.StatusText = ""
	}
	r.Output = ResponseData{} // clear output
	r.Output["error"] = e.Type
	r.Output["error_description"] = e.Desc
	/*if uri != "" {
		r.Output["error_uri"] = uri
	}*/

	if len(state) > 0 && state[0] != "" {
		r.Output["state"] = state[0]
	}
}

// GetRedirectURL returns the redirect url with all query string parameters.
func (r *Response) GetRedirectURL() (string, error) {
	if r.ResponseType != REDIRECT {
		return "", errors.New("not a redirect response")
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

	// manage redirect
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
