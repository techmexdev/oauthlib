package oauthlib

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"
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

// Server is an OAuth2 implementation
type Server struct {
	Config            *Config
	Storage           Storage
	AuthorizeTokenGen AuthorizeTokenGen
	AccessTokenGen    AccessTokenGen
	Now               func() time.Time
}

// NewServer creates a new server instance
func NewServer(config *Config, storage Storage) *Server {
	return &Server{
		Config:            config,
		Storage:           storage,
		AuthorizeTokenGen: &AuthorizeTokenGenDefault{},
		AccessTokenGen:    &AccessTokenGenDefault{},
		Now:               time.Now,
	}
}

// NewResponse creates a new response for the server
func (s *Server) NewResponse() *Response {
	r := NewResponse(s.Storage)
	r.HttpStatusCode = s.Config.HttpStatusCode
	return r
}

// checkBasicAuth checks the authorization header data for correct basic auth.
func (s *Server) checkBasicAuth(r *http.Request) (*BasicAuth, error) {
	if r.Header.Get("Authorization") == "" {
		return nil, nil
	}

	ss := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(ss) != 2 || ss[0] != "Basic" {
		return nil, errors.New("Invalid authorization header")
	}

	b, err := base64.StdEncoding.DecodeString(ss[1])
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
func (s *Server) checkBearerAuth(r *http.Request) *BearerAuth {
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
