package oauthlib

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

const (
	badAuthValue        = "Digest XHHHHHHH"
	goodAuthValue       = "Basic dGVzdDp0ZXN0"
	goodBearerAuthValue = "Bearer BGFVTDUJDp0ZXN0"
)

func TestBasicAuth(t *testing.T) {
	r := &http.Request{Header: make(http.Header)}

	// Without any header
	if b, err := CheckBasicAuth(r); b != nil || err != nil {
		t.Errorf("Validated basic auth without header")
	}

	// with invalid header
	r.Header.Set("Authorization", badAuthValue)
	b, err := CheckBasicAuth(r)
	if b != nil || err == nil {
		t.Errorf("Validated invalid auth")
		return
	}

	// with valid header
	r.Header.Set("Authorization", goodAuthValue)
	b, err = CheckBasicAuth(r)
	if b == nil || err != nil {
		t.Errorf("Could not extract basic auth")
		return
	}

	// check extracted auth data
	if b.Username != "test" || b.Password != "test" {
		t.Errorf("Error decoding basic auth")
	}
}

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
		header           http.Header
		url              *url.URL
		allowQueryParams bool
		expectAuth       bool
	}{
		{headerNoAuth, urlWithSecret, true, true},
		{headerNoAuth, urlWithSecret, false, false},
		{headerNoAuth, urlWithEmptySecret, true, true},
		{headerNoAuth, urlWithEmptySecret, false, false},
		{headerNoAuth, urlNoSecret, true, false},
		{headerNoAuth, urlNoSecret, false, false},

		{headerBadAuth, urlWithSecret, true, true},
		{headerBadAuth, urlWithSecret, false, false},
		{headerBadAuth, urlWithEmptySecret, true, true},
		{headerBadAuth, urlWithEmptySecret, false, false},
		{headerBadAuth, urlNoSecret, true, false},
		{headerBadAuth, urlNoSecret, false, false},

		{headerOKAuth, urlWithSecret, true, true},
		{headerOKAuth, urlWithSecret, false, true},
		{headerOKAuth, urlWithEmptySecret, true, true},
		{headerOKAuth, urlWithEmptySecret, false, true},
		{headerOKAuth, urlNoSecret, true, true},
		{headerOKAuth, urlNoSecret, false, true},
	}

	for _, tt := range tests {
		w := new(Response)
		r := &http.Request{Header: tt.header, URL: tt.url}
		r.ParseForm()
		auth := getClientAuth(w, r, tt.allowQueryParams)
		if tt.expectAuth && auth == nil {
			t.Errorf("Auth should not be nil for %v", tt)
		} else if !tt.expectAuth && auth != nil {
			t.Errorf("Auth should be nil for %v", tt)
		}
	}

}

func TestBearerAuth(t *testing.T) {
	r := &http.Request{Header: make(http.Header)}

	// Without any header
	if b := CheckBearerAuth(r); b != nil {
		t.Errorf("Validated bearer auth without header")
	}

	// with invalid header
	r.Header.Set("Authorization", badAuthValue)
	b := CheckBearerAuth(r)
	if b != nil {
		t.Errorf("Validated invalid auth")
		return
	}

	// with valid header
	r.Header.Set("Authorization", goodBearerAuthValue)
	b = CheckBearerAuth(r)
	if b == nil {
		t.Errorf("Could not extract bearer auth")
		return
	}

	// check extracted auth data
	if b.Code != "BGFVTDUJDp0ZXN0" {
		t.Errorf("Error decoding bearer auth")
	}

	// extracts bearer auth from query string
	url, _ := url.Parse("http://host.tld/path?code=XYZ")
	r = &http.Request{URL: url}
	r.ParseForm()
	b = CheckBearerAuth(r)
	if b.Code != "XYZ" {
		t.Errorf("Error decoding bearer auth")
	}
}

func TestResponseJSON(t *testing.T) {
	w := httptest.NewRecorder()

	r := NewResponse(NewTestStorage(t))
	r.Output["access_token"] = "1234"
	r.Output["token_type"] = "5678"

	err := WriteJSON(w, r)
	if err != nil {
		t.Fatalf("Error outputting json: %s", err)
	}

	//fmt.Printf("%d - %s - %+v", w.Code, w.Body.String(), w.HeaderMap)

	if w.Code != 200 {
		t.Fatalf("Invalid response code for output: %d", w.Code)
	}

	if w.HeaderMap.Get("Content-Type") != "application/json" {
		t.Fatalf("Result from json must be application/json")
	}

	// parse output json
	output := make(map[string]interface{})
	if err := json.Unmarshal(w.Body.Bytes(), &output); err != nil {
		t.Fatalf("Could not decode output json: %s", err)
	}

	if d, ok := output["access_token"]; !ok || d != "1234" {
		t.Fatalf("Invalid or not found output data: access_token=%s", d)
	}

	if d, ok := output["token_type"]; !ok || d != "5678" {
		t.Fatalf("Invalid or not found output data: token_type=%s", d)
	}
}

func TestErrorResponseJSON(t *testing.T) {
	w := httptest.NewRecorder()

	r := NewResponse(NewTestStorage(t))
	r.HttpStatusCode = http.StatusInternalServerError
	r.SetError(E_INVALID_REQUEST, "")

	err := WriteJSON(w, r)
	if err != nil {
		t.Fatalf("Error outputting json: %s", err)
	}

	//fmt.Printf("%d - %s - %+v", w.Code, w.Body.String(), w.HeaderMap)

	if w.Code != 500 {
		t.Fatalf("Invalid response code for error output: %d", w.Code)
	}

	if w.HeaderMap.Get("Content-Type") != "application/json" {
		t.Fatalf("Result from json must be application/json")
	}

	// parse output json
	output := make(map[string]interface{})
	if err := json.Unmarshal(w.Body.Bytes(), &output); err != nil {
		t.Fatalf("Could not decode output json: %s", err)
	}

	if d, ok := output["error"]; !ok || d != E_INVALID_REQUEST {
		t.Fatalf("Invalid or not found output data: error=%s", d)
	}
}

func TestRedirectResponseJSON(t *testing.T) {
	w := httptest.NewRecorder()

	r := NewResponse(NewTestStorage(t))
	r.SetRedirect("http://localhost:14000")

	err := WriteJSON(w, r)
	if err != nil {
		t.Fatalf("Error outputting json: %s", err)
	}

	//fmt.Printf("%d - %s - %+v", w.Code, w.Body.String(), w.HeaderMap)

	if w.Code != 302 {
		t.Fatalf("Invalid response code for redirect output: %d", w.Code)
	}

	if w.HeaderMap.Get("Location") != "http://localhost:14000" {
		t.Fatalf("Invalid response location url: %s", w.HeaderMap.Get("Location"))
	}
}

// Predictable testing token generation
type TestingAuthorizeTokenGen struct {
	counter int64
}

func (a *TestingAuthorizeTokenGen) GenerateAuthorizeToken(data *AuthorizeData) (ret string, err error) {
	a.counter++
	return strconv.FormatInt(a.counter, 10), nil
}

type TestingAccessTokenGen struct {
	acounter int64
	rcounter int64
}

func (a *TestingAccessTokenGen) GenerateAccessToken(data *AccessGrant, generaterefresh bool) (accesstoken string, refreshtoken string, err error) {
	a.acounter++
	accesstoken = strconv.FormatInt(a.acounter, 10)

	if generaterefresh {
		a.rcounter++
		refreshtoken = "r" + strconv.FormatInt(a.rcounter, 10)
	}
	return
}
