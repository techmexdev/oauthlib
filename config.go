package oauthlib

import "net/http"

// ServerConfig contains server configuration information
type ServerConfig struct {
	// Authorization token expiration in seconds (default 5 minutes)
	AuthorizationExpiration int32

	// Access token expiration in seconds (default 1 hour)
	AccessExpiration int32

	// Token type to return
	TokenType string

	// List of allowed authorize types (only CODE by default)
	AllowedAuthorizeRequestTypes []AuthorizeRequestType

	// List of allowed access types (only AuthorizationCodeGrant by default)
	AllowedGrantTypes []GrantType

	// HTTP status code to return for errors - default 200
	// Only used if response was created from server
	HttpStatusCode int

	// If true allows client secret also in params, else only in
	// Authorization header - default false
	AllowClientSecretInParams bool

	// If true allows access request using GET, else only POST - default false
	AllowGetAccessRequest bool

	// Separator to support multiple URIs in Client.GetRedirectURI().
	// If blank (the default), don't allow multiple URIs.
	RedirectURISeparator string
}

// isAuthorizeRequestTypeAllowed determines if the passed AuthorizedRequestType
// is in the ServerConfig.AllowedAuthorizeRequestTypes
func (c ServerConfig) isAuthorizeRequestTypeAllowed(at AuthorizeRequestType) bool {
	for _, k := range c.AllowedAuthorizeRequestTypes {
		if k == at {
			return true
		}
	}
	return false
}

// isGrantTypeAllowed determines if the passed AuthorizedRequestType is in the
// ServerConfig.AllowedGrantTypes
func (c ServerConfig) isGrantTypeAllowed(gt GrantType) bool {
	for _, k := range c.AllowedGrantTypes {
		if k == gt {
			return true
		}
	}
	return false
}

// NewServerConfig returns a new ServerConfig with default configuration
func NewServerConfig() *ServerConfig {
	return &ServerConfig{
		AuthorizationExpiration:      250,
		AccessExpiration:             3600,
		TokenType:                    "Bearer",
		AllowedAuthorizeRequestTypes: []AuthorizeRequestType{CODE},
		AllowedGrantTypes:            []GrantType{AuthorizationCodeGrant},
		HttpStatusCode:               http.StatusOK,
		AllowClientSecretInParams:    false,
		AllowGetAccessRequest:        false,
	}
}
