package oauthlib

import (
	"testing"
	"time"
)

// NewTestStorage creates an instance of MemStorage for use in testing with
// some preconfigured clients, grants, etc.
//
// This should not be used in production.
func NewTestStorage(t *testing.T) *MemStorage {
	ms := NewMemStorage()
	if t != nil {
		ms.Logger = t.Logf
	}

	err := ms.SetClient("1234", &DefaultClient{
		Id:          "1234",
		Secret:      "aabbccdd",
		RedirectURI: "http://localhost:14000/appauth",
	})
	if t != nil && err != nil {
		t.Fatalf("error: %v", err)
	}

	err = ms.SaveAuthorizeData(&AuthorizeData{
		Client:      ms.Clients["1234"],
		Code:        "9999",
		ExpiresIn:   3600,
		CreatedAt:   time.Now(),
		RedirectURI: "http://localhost:14000/appauth",
	})
	if t != nil && err != nil {
		t.Fatalf("error: %v", err)
	}

	err = ms.SaveAccessGrant(&AccessGrant{
		Client:        ms.Clients["1234"],
		AuthorizeData: ms.AuthorizeData["9999"],
		AccessToken:   "9999",
		ExpiresIn:     3600,
		CreatedAt:     time.Now(),
	})
	if t != nil && err != nil {
		t.Fatalf("error: %v", err)
	}

	err = ms.SaveAccessGrant(&AccessGrant{
		Client:        ms.Clients["1234"],
		AuthorizeData: ms.AuthorizeData["9999"],
		AccessGrant:   ms.AccessGrants["9999"],
		AccessToken:   "9999",
		RefreshToken:  "r9999",
		ExpiresIn:     3600,
		CreatedAt:     time.Now(),
	})
	if t != nil && err != nil {
		t.Fatalf("error: %v", err)
	}

	ms.RefreshGrants["r9999"] = "9999"

	return ms
}
