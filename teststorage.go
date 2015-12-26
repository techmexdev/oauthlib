package oauthlib

import (
	"strconv"
	"testing"
	"time"
)

// NewTestStorage creates an instance of MemStorage for use in testing with
// some preconfigured clients, grants, etc.
//
// This should not be used in production.
func NewTestStorage(t *testing.T) *MemStorage {
	ms := NewMemStorage()
	ms.Logger = t.Logf

	ms.SetClient("1234", &DefaultClient{
		Id:          "1234",
		Secret:      "aabbccdd",
		RedirectURI: "http://localhost:14000/appauth",
	})

	ms.SaveAuthorizeData(&AuthorizeData{
		Client:      ms.Clients["1234"],
		Code:        "9999",
		ExpiresIn:   3600,
		CreatedAt:   time.Now(),
		RedirectURI: "http://localhost:14000/appauth",
	})

	ms.SaveAccessGrant(&AccessGrant{
		Client:        ms.Clients["1234"],
		AuthorizeData: ms.AuthorizeData["9999"],
		AccessToken:   "9999",
		ExpiresIn:     3600,
		CreatedAt:     time.Now(),
	})

	ms.SaveAccessGrant(&AccessGrant{
		Client:        ms.Clients["1234"],
		AuthorizeData: ms.AuthorizeData["9999"],
		AccessGrant:   ms.AccessGrants["9999"],
		AccessToken:   "9999",
		RefreshToken:  "r9999",
		ExpiresIn:     3600,
		CreatedAt:     time.Now(),
	})

	ms.RefreshGrants["r9999"] = "9999"

	return ms
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
