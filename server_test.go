package oauthlib

import (
	"net/http"
	"net/url"
	"testing"
)

const (
	badAuthValue        = "Digest XHHHHHHH"
	goodAuthValue       = "Basic dGVzdDp0ZXN0"
	goodBearerAuthValue = "Bearer BGFVTDUJDp0ZXN0"
)

func TestGetClientAuth(t *testing.T) {
	urlWithSecret, _ := url.Parse("http://host.tld/path?client_id=xxx&client_secret=yyy")
	urlWithEmptySecret, _ := url.Parse("http://host.tld/path?client_id=xxx&client_secret=")
	urlNoSecret, _ := url.Parse("http://host.tld/path?client_id=xxx")

	headerNoAuth := make(http.Header)
	headerBadAuth := make(http.Header)
	headerBadAuth.Set("Authorization", badAuthValue)
	headerOKAuth := make(http.Header)
	headerOKAuth.Set("Authorization", goodAuthValue)

	var tests = []struct {
		header     http.Header
		url        *url.URL
		expectAuth bool
	}{
		//{headerNoAuth, urlWithSecret, true},
		{headerNoAuth, urlWithSecret, false},
		//{headerNoAuth, urlWithEmptySecret, true},
		{headerNoAuth, urlWithEmptySecret, false},
		{headerNoAuth, urlNoSecret, false},
		{headerNoAuth, urlNoSecret, false},

		//{headerBadAuth, urlWithSecret, true},
		{headerBadAuth, urlWithSecret, false},
		//{headerBadAuth, urlWithEmptySecret, true},
		{headerBadAuth, urlWithEmptySecret, false},
		{headerBadAuth, urlNoSecret, false},
		{headerBadAuth, urlNoSecret, false},

		{headerOKAuth, urlWithSecret, true},
		{headerOKAuth, urlWithSecret, true},
		{headerOKAuth, urlWithEmptySecret, true},
		{headerOKAuth, urlWithEmptySecret, true},
		{headerOKAuth, urlNoSecret, true},
		{headerOKAuth, urlNoSecret, true},
	}

	for i, tt := range tests {
		s := &Server{}
		w := new(Response)
		r := &http.Request{Header: tt.header, URL: tt.url}
		err := r.ParseForm()
		if err != nil {
			t.Fatal(err)
		}

		auth := s.getClientAuth(w, r)
		if tt.expectAuth && auth == nil {
			t.Errorf("auth should not be nil (%d) for %+v", i, tt)
		} else if !tt.expectAuth && auth != nil {
			t.Errorf("auth should be nil (%d) for %+v", i, tt)
		}
	}
}

func TestBasicAuth(t *testing.T) {
	s := &Server{}
	r := &http.Request{Header: make(http.Header)}

	// Without any header
	if b, err := s.checkBasicAuth(r); b != nil || err != nil {
		t.Errorf("validated basic auth without header")
	}

	// with invalid header
	r.Header.Set("Authorization", badAuthValue)
	b, err := s.checkBasicAuth(r)
	if b != nil || err == nil {
		t.Errorf("validated invalid auth")
		return
	}

	// with valid header
	r.Header.Set("Authorization", goodAuthValue)
	b, err = s.checkBasicAuth(r)
	if b == nil || err != nil {
		t.Errorf("could not extract basic auth")
		return
	}

	// check extracted auth data
	if b.Username != "test" || b.Password != "test" {
		t.Errorf("error decoding basic auth")
	}
}

func TestBearerAuth(t *testing.T) {
	s := &Server{}
	r := &http.Request{Header: make(http.Header)}

	// Without any header
	if b := s.checkBearerAuth(r); b != nil {
		t.Errorf("validated bearer auth without header")
	}

	// with invalid header
	r.Header.Set("Authorization", badAuthValue)
	b := s.checkBearerAuth(r)
	if b != nil {
		t.Errorf("validated invalid auth")
		return
	}

	// with valid header
	r.Header.Set("Authorization", goodBearerAuthValue)
	b = s.checkBearerAuth(r)
	if b == nil {
		t.Errorf("could not extract bearer auth")
		return
	}

	// check extracted auth data
	if b.Code != "BGFVTDUJDp0ZXN0" {
		t.Errorf("error decoding bearer auth")
	}

	// extracts bearer auth from query string
	url, _ := url.Parse("http://host.tld/path?code=XYZ")
	r = &http.Request{URL: url}
	err := r.ParseForm()
	if err != nil {
		t.Fatal(err)
	}

	b = s.checkBearerAuth(r)
	if b.Code != "XYZ" {
		t.Errorf("error decoding bearer auth")
	}
}
