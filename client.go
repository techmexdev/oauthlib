package oauthlib

// Client information.
type Client interface {
	// Client id
	GetID() string

	// Client secret
	GetSecret() string

	// Base client uri
	GetRedirectURI() string

	// Data to be passed to storage. Not used by the library.
	GetUserData() interface{}
}

// ClientSecretMatcher is an optional interface clients can implement which
// allows them to be the one to determine if a secret matches.  If a Client
// implements ClientSecretMatcher, the framework will never call GetSecret.
type ClientSecretMatcher interface {
	// SecretMatches returns true if the given secret matches
	ClientSecretMatches(secret string) bool
}

// DefaultClient stores all data in struct variables
type DefaultClient struct {
	// ID is the client id.
	ID string

	// Secret is the client secret.
	Secret string

	// RedirectURI is the redirect uri for the client.
	RedirectURI string

	// UserData is the user data.
	UserData interface{}
}

// GetID retrieves the client id.
func (d *DefaultClient) GetID() string {
	return d.ID
}

// GetSecret retrieves the client secret.
func (d *DefaultClient) GetSecret() string {
	return d.Secret
}

// GetRedirectURI retrieves the client redirect uri.
func (d *DefaultClient) GetRedirectURI() string {
	return d.RedirectURI
}

// GetUserData retrieves the user data.
func (d *DefaultClient) GetUserData() interface{} {
	return d.UserData
}

// ClientSecretMatches provides compatibility with the ClientSecretMatcher
// interface.
func (d *DefaultClient) ClientSecretMatches(secret string) bool {
	return d.Secret == secret
}
