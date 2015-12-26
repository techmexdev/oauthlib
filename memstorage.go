package oauthlib

import (
	"errors"
	"log"
	"sync"
)

// Logger is a func compatible with most logging func's.
type Logger func(string, ...interface{})

// MemStorage is a simple Storage compatiable example data store.
//
// It is not suitable for use in production.
type MemStorage struct {
	sync.RWMutex

	// Clients are a list of the clients.
	Clients map[string]Client

	// AuthorizeData is the saved authorize data.
	AuthorizeData map[string]*AuthorizeData

	// AccessGrants are the saved access grants.
	AccessGrants map[string]*AccessGrant

	// RefreshGrants are the saved refresh grants.
	RefreshGrants map[string]string

	// Logger is a logger to log output to.
	Logger Logger
}

// NewMemStorage creates a new MemStorage.
func NewMemStorage() *MemStorage {
	return &MemStorage{
		Clients:       make(map[string]Client),
		AuthorizeData: make(map[string]*AuthorizeData),
		AccessGrants:  make(map[string]*AccessGrant),
		RefreshGrants: make(map[string]string),
	}
}

// printf is a simple logging utility
func (ms *MemStorage) printf(str string, args ...interface{}) {
	logger := ms.Logger
	if ms.Logger == nil {
		logger = log.Printf
	}

	logger(str, args...)
}

// GetClient loads the client by id.
func (ms *MemStorage) GetClient(id string) (Client, error) {
	ms.printf("GetClient: %s\n", id)

	ms.RLock()
	defer ms.RUnlock()

	if c, ok := ms.Clients[id]; ok {
		return c, nil
	}

	return nil, errors.New("Client not found")
}

// SetClient saves Client with id to storage.
func (ms *MemStorage) SetClient(id string, client Client) error {
	ms.printf("SetClient: %s\n", id)

	ms.Lock()
	ms.Clients[id] = client
	ms.Unlock()

	return nil
}

// SaveAuthorizeData saves the provided authorize data.
func (ms *MemStorage) SaveAuthorizeData(ad *AuthorizeData) error {
	ms.printf("SaveAuthorizeData: %s\n", ad.Code)

	ms.Lock()
	ms.AuthorizeData[ad.Code] = ad
	ms.Unlock()

	return nil
}

// LoadAuthorizeData retrieves AuthorizeData by a code.
//
// Client information MUST be loaded together.
// Optionally can return error if expired.
func (ms *MemStorage) LoadAuthorizeData(code string) (*AuthorizeData, error) {
	ms.printf("LoadAuthorizeData: %s\n", code)

	ms.RLock()
	defer ms.RUnlock()

	if d, ok := ms.AuthorizeData[code]; ok {
		return d, nil
	}

	return nil, errors.New("Authorize not found")
}

// RemoveAuthorizeData revokes or deletes the authorization code.
func (ms *MemStorage) RemoveAuthorizeData(code string) error {
	ms.printf("RemoveAuthorizeData: %s\n", code)

	ms.Lock()
	delete(ms.AuthorizeData, code)
	ms.Unlock()

	return nil
}

// SaveAccessGrant saves AccessGrant to storage.
//
// If RefreshToken is not blank, it must save in a way that can be loaded using
// LoadRefresh.
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

// LoadAccessGrant retrieves access data by token. Client information MUST be
// loaded together.
//
// AuthorizeData and AccessGrant DON'T NEED to be loaded if not easily
// available. Optionally can return error if expired.
func (ms *MemStorage) LoadAccessGrant(code string) (*AccessGrant, error) {
	ms.printf("LoadAccessGrant: %s\n", code)

	ms.RLock()
	defer ms.RUnlock()

	if d, ok := ms.AccessGrants[code]; ok {
		return d, nil
	}

	return nil, errors.New("Access not found")
}

// RemoveAccessGrant revokes or deletes an AccessGrant.
func (ms *MemStorage) RemoveAccessGrant(code string) error {
	ms.printf("RemoveAccessGrant: %s\n", code)

	ms.Lock()
	delete(ms.AccessGrants, code)
	ms.Unlock()

	return nil
}

// LoadRefreshGrant retrieves refresh AccessGrant. Client information MUST be
// loaded together.
//
// AuthorizeData and AccessGrant DON'T NEED to be loaded if not easily
// available. Optionally can return error if expired.
func (ms *MemStorage) LoadRefreshGrant(code string) (*AccessGrant, error) {
	ms.printf("LoadRefreshGrant: %s\n", code)

	ms.RLock()
	defer ms.RUnlock()

	if d, ok := ms.RefreshGrants[code]; ok {
		return ms.LoadAccessGrant(d)
	}

	return nil, errors.New("Refresh not found")
}

// RemoveRefreshGrant revokes or deletes refresh AccessGrant.
func (ms *MemStorage) RemoveRefreshGrant(code string) error {
	ms.printf("RemoveRefreshGrant: %s\n", code)

	ms.Lock()
	delete(ms.RefreshGrants, code)
	ms.Unlock()

	return nil
}
