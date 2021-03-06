package oauthlib

import (
	"net/http"
	"net/url"
	"testing"
)

func TestAuthorizeCode(t *testing.T) {
	sconfig := NewConfig()
	sconfig.AllowedAuthRequestTypes = []string{"code"}
	server := NewServer(sconfig, NewTestStorage(t))
	server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}
	resp := server.NewResponse()

	req, err := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Form = url.Values{}
	req.Form.Set("response_type", "code")
	req.Form.Set("client_id", "1234")
	req.Form.Set("state", "a")

	if ar := server.HandleAuthRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAuthRequest(resp, req, ar)
	}

	if resp.IsError && resp.InternalError != nil {
		t.Fatalf("Error in response: %s", resp.InternalError)
	}

	if resp.IsError {
		t.Fatalf("Should not be an error")
	}

	if resp.ResponseType != REDIRECT {
		t.Fatalf("Response should be a redirect")
	}

	if d := resp.Output["code"]; d != "1" {
		t.Fatalf("Unexpected authorization code: %s", d)
	}
}

func TestAuthorizeToken(t *testing.T) {
	sconfig := NewConfig()
	sconfig.AllowedAuthRequestTypes = []string{"token"}
	server := NewServer(sconfig, NewTestStorage(t))
	server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}
	server.AccessTokenGen = &TestingAccessTokenGen{}
	resp := server.NewResponse()

	req, err := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Form = url.Values{}
	req.Form.Set("response_type", "token")
	req.Form.Set("client_id", "1234")
	req.Form.Set("state", "a")

	if ar := server.HandleAuthRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAuthRequest(resp, req, ar)
	}

	if resp.IsError && resp.InternalError != nil {
		t.Fatalf("Error in response: %s", resp.InternalError)
	}

	if resp.IsError {
		t.Fatalf("Should not be an error")
	}

	if resp.ResponseType != REDIRECT || !resp.RedirectInFragment {
		t.Fatalf("Response should be a redirect with fragment")
	}

	if d := resp.Output["access_token"]; d != "1" {
		t.Fatalf("Unexpected access token: %s", d)
	}
}
