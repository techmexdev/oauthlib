package oauthlib

// Storage interface
type Storage interface {
	// GetClient loads the client by id.
	GetClient(id string) (Client, error)

	// SetClient saves Client with id to storage.
	SetClient(id string, client Client) error

	// SaveAuthorizeData saves the AuthorizeData to storage.
	SaveAuthorizeData(*AuthorizeData) error

	// LoadAuthorizeData retrieves AuthorizeData by a code.
	//
	// Client information MUST be loaded together.
	// Optionally can return error if expired.
	LoadAuthorizeData(code string) (*AuthorizeData, error)

	// RemoveAuthorizeData revokes or deletes the authorization code.
	RemoveAuthorizeData(code string) error

	// SaveAccessGrant saves AccessGrant to storage.
	//
	// If RefreshToken is not blank, it must save in a way that can be loaded
	// using LoadRefresh.
	SaveAccessGrant(*AccessGrant) error

	// LoadAccessGrant retrieves access data by token. Client information MUST
	// be loaded together.
	//
	// AuthorizeData and AccessGrant DON'T NEED to be loaded if not easily
	// available. Optionally can return error if expired.
	LoadAccessGrant(token string) (*AccessGrant, error)

	// RemoveAccessGrant revokes or deletes an AccessGrant.
	RemoveAccessGrant(token string) error

	// LoadRefreshGrant retrieves refresh AccessGrant. Client information MUST
	// be loaded together.
	//
	// AuthorizeData and AccessGrant DON'T NEED to be loaded if not easily
	// available. Optionally can return error if expired.
	LoadRefreshGrant(token string) (*AccessGrant, error)

	// RemoveRefreshGrant revokes or deletes refresh AccessGrant.
	RemoveRefreshGrant(token string) error
}
