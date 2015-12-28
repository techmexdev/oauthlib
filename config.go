package oauthlib

import "net/http"

// Config contains server configuration information
type Config struct {
	// Authorization token expiration in seconds (default 5 minutes)
	AuthorizationExpiration int32

	// Access token expiration in seconds (default 1 hour)
	AccessExpiration int32

	// Token type to return
	TokenType string

	// List of allowed authorize types ("code" or "token" only)
	AllowedAuthRequestTypes []string

	// List of allowed access types (only AuthorizationCodeGrant by default)
	AllowedGrantTypes []GrantType

	// HTTP status code to return for errors - default 200
	// Only used if response was created from server
	HttpStatusCode int

	// Separator to support multiple URIs in Client.GetRedirectURI().
	// If blank (the default), don't allow multiple URIs.
	RedirectURISeparator string
}

// isAuthRequestTypeAllowed determines if the passed AuthorizedRequestType
// is in the Config.AllowedAuthRequestTypes
func (c Config) isAuthRequestTypeAllowed(at string) bool {
	for _, k := range c.AllowedAuthRequestTypes {
		if k == at {
			return true
		}
	}
	return false
}

// isGrantTypeAllowed determines if the passed AuthorizedRequestType is in the
// Config.AllowedGrantTypes
func (c Config) isGrantTypeAllowed(gt GrantType) bool {
	for _, k := range c.AllowedGrantTypes {
		if k == gt {
			return true
		}
	}
	return false
}

// NewConfig returns a new Config with default configuration
func NewConfig() *Config {
	return &Config{
		AuthorizationExpiration: 250,
		AccessExpiration:        3600,
		TokenType:               "Bearer",
		AllowedAuthRequestTypes: []string{"code"},
		AllowedGrantTypes:       []GrantType{AuthorizationCodeGrant},
		HttpStatusCode:          http.StatusOK,
	}
}
