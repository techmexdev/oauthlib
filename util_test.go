package oauthlib

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

const (
	badAuthValue        = "Digest XHHHHHHH"
	goodAuthValue       = "Basic dGVzdDp0ZXN0"
	goodBearerAuthValue = "Bearer BGFVTDUJDp0ZXN0"
)

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
	r.SetError(ErrInvalidRequest)

	err := WriteJSON(w, r)
	if err != nil {
		t.Fatalf("Error writing json: %v", err)
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

	if d, ok := output["error"]; !ok || d != ErrInvalidRequest.Type {
		t.Fatalf("Invalid or not found output data: error=%s", d)
	}
}

func TestRedirectResponseJSON(t *testing.T) {
	w := httptest.NewRecorder()

	r := NewResponse(NewTestStorage(t))
	r.ResponseType = REDIRECT
	r.URL = "http://localhost:14000"

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

func TestValidateURI(t *testing.T) {
	valid := [][]string{
		{
			// Exact match
			"http://localhost:14000/appauth",
			"http://localhost:14000/appauth",
		},
		{
			// Trailing slash
			"http://www.google.com/myapp",
			"http://www.google.com/myapp/",
		},
		{
			// Exact match with trailing slash
			"http://www.google.com/myapp/",
			"http://www.google.com/myapp/",
		},
		{
			// Subpath
			"http://www.google.com/myapp",
			"http://www.google.com/myapp/interface/implementation",
		},
		{
			// Subpath with trailing slash
			"http://www.google.com/myapp/",
			"http://www.google.com/myapp/interface/implementation",
		},
		{
			// Subpath with things that are close to path traversals, but aren't
			"http://www.google.com/myapp",
			"http://www.google.com/myapp/.../..implementation../...",
		},
		{
			// If the allowed basepath contains path traversals, allow them?
			"http://www.google.com/traversal/../allowed",
			"http://www.google.com/traversal/../allowed/with/subpath",
		},
	}
	for _, v := range valid {
		if err := validateURI(v[0], v[1]); err != nil {
			t.Errorf("Expected validateURI(%s, %s) to succeed, got %v", v[0], v[1], err)
		}
	}

	invalid := [][]string{
		{
			// Doesn't satisfy base path
			"http://localhost:14000/appauth",
			"http://localhost:14000/app",
		},
		{
			// Doesn't satisfy base path
			"http://localhost:14000/app/",
			"http://localhost:14000/app",
		},
		{
			// Not a subpath of base path
			"http://localhost:14000/appauth",
			"http://localhost:14000/appauthmodifiedpath",
		},
		{
			// Host mismatch
			"http://www.google.com/myapp",
			"http://www2.google.com/myapp",
		},
		{
			// Scheme mismatch
			"http://www.google.com/myapp",
			"https://www.google.com/myapp",
		},
		{
			// Path traversal
			"http://www.google.com/myapp",
			"http://www.google.com/myapp/..",
		},
		{
			// Embedded path traversal
			"http://www.google.com/myapp",
			"http://www.google.com/myapp/../test",
		},
		{
			// Not a subpath
			"http://www.google.com/myapp",
			"http://www.google.com/myapp../test",
		},
	}
	for _, v := range invalid {
		if err := validateURI(v[0], v[1]); err == nil {
			t.Errorf("Expected validateURI(%s, %s) to fail", v[0], v[1])
		}
	}
}

func TestValidateURIList(t *testing.T) {
	// V1
	if err := validateURIList("http://localhost:14000/appauth", "http://localhost:14000/appauth", ""); err != nil {
		t.Errorf("V1: %s", err)
	}

	// V2
	if err := validateURIList("http://localhost:14000/appauth", "http://localhost:14000/app", ""); err == nil {
		t.Error("V2 should have failed")
	}

	// V3
	if err := validateURIList("http://xxx:14000/appauth;http://localhost:14000/appauth", "http://localhost:14000/appauth", ";"); err != nil {
		t.Errorf("V3: %s", err)
	}

	// V4
	if err := validateURIList("http://xxx:14000/appauth;http://localhost:14000/appauth", "http://localhost:14000/app", ";"); err == nil {
		t.Error("V4 should have failed")
	}
}
