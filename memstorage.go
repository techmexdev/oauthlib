package oauthlib

import (
	"errors"
	"log"
	"sync"
)

type Logger func(string, ...interface{})

// MemStorage is a simple example ofo how to use
type MemStorage struct {
	sync.RWMutex

	Clients       map[string]Client
	AuthorizeData map[string]*AuthorizeData
	AccessGrants  map[string]*AccessGrant
	RefreshGrants map[string]string
	Logger        Logger
}

func NewMemStorage() *MemStorage {
	return &MemStorage{
		Clients:       make(map[string]Client),
		AuthorizeData: make(map[string]*AuthorizeData),
		AccessGrants:  make(map[string]*AccessGrant),
		RefreshGrants: make(map[string]string),
	}
}

func (ms *MemStorage) printf(str string, args ...interface{}) {
	logger := ms.Logger
	if ms.Logger == nil {
		logger = log.Printf
	}

	logger(str, args...)
}

func (ms *MemStorage) GetClient(id string) (Client, error) {
	ms.printf("GetClient: %s\n", id)

	ms.RLock()
	defer ms.RUnlock()
	if c, ok := ms.Clients[id]; ok {
		return c, nil
	}

	return nil, errors.New("Client not found")
}

func (ms *MemStorage) SetClient(id string, client Client) error {
	ms.printf("SetClient: %s\n", id)

	ms.Lock()
	ms.Clients[id] = client
	ms.Unlock()

	return nil
}

func (ms *MemStorage) SaveAuthorizeData(ad *AuthorizeData) error {
	ms.printf("SaveAuthorizeData: %s\n", ad.Code)

	ms.Lock()
	ms.AuthorizeData[ad.Code] = ad
	ms.Unlock()

	return nil
}

func (ms *MemStorage) LoadAuthorizeData(code string) (*AuthorizeData, error) {
	ms.printf("LoadAuthorizeData: %s\n", code)

	ms.RLock()
	defer ms.RUnlock()

	if d, ok := ms.AuthorizeData[code]; ok {
		return d, nil
	}

	return nil, errors.New("Authorize not found")
}

func (ms *MemStorage) RemoveAuthorizeData(code string) error {
	ms.printf("RemoveAuthorizeData: %s\n", code)

	ms.Lock()
	delete(ms.AuthorizeData, code)
	ms.Unlock()

	return nil
}

func (ms *MemStorage) SaveAccessGrant(ag *AccessGrant) error {
	ms.printf("SaveAccessGrant: %s\n", ag.AccessToken)

	ms.Lock()
	ms.AccessGrants[ag.AccessToken] = ag
	if ag.RefreshToken != "" {
		ms.RefreshGrants[ag.RefreshToken] = ag.AccessToken
	}
	ms.Unlock()

	return nil
}

func (ms *MemStorage) LoadAccessGrant(code string) (*AccessGrant, error) {
	ms.printf("LoadAccessGrant: %s\n", code)

	ms.RLock()
	defer ms.RUnlock()
	if d, ok := ms.AccessGrants[code]; ok {
		return d, nil
	}

	return nil, errors.New("Access not found")
}

func (ms *MemStorage) RemoveAccessGrant(code string) error {
	ms.printf("RemoveAccessGrant: %s\n", code)

	ms.Lock()
	delete(ms.AccessGrants, code)
	ms.Unlock()

	return nil
}

func (ms *MemStorage) LoadRefreshGrant(code string) (*AccessGrant, error) {
	ms.printf("LoadRefreshGrant: %s\n", code)

	ms.RLock()
	defer ms.RUnlock()
	if d, ok := ms.RefreshGrants[code]; ok {
		return ms.LoadAccessGrant(d)
	}

	return nil, errors.New("Refresh not found")
}

func (ms *MemStorage) RemoveRefreshGrant(code string) error {
	ms.printf("RemoveRefreshGrant: %s\n", code)

	ms.Lock()
	delete(ms.RefreshGrants, code)
	ms.Unlock()

	return nil
}
