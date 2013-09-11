package osin

// Helper allowing objects
type AllowedAuthorizeType []AuthorizeRequestType

// Checks if the type exists in the list
func (t AllowedAuthorizeType) Exists(rt AuthorizeRequestType) bool {
	for _, k := range t {
		if k == rt {
			return true
		}
	}
	return false
}

type AllowedAccessType []AccessRequestType

// Checks if the type exists in the list
func (t AllowedAccessType) Exists(rt AccessRequestType) bool {
	for _, k := range t {
		if k == rt {
			return true
		}
	}
	return false
}

// Server configuration
type ServerConfig struct {
	// Authorization token expiration in seconds (default 5 minutes)
	AuthorizationExpiration int32

	// Access token expiration in seconds (default 1 hour)
	AccessExpiration int32

	// Token type to return
	TokenType string

	// List of allowed authorize types (only CODE by default)
	AllowedAuthorizeTypes AllowedAuthorizeType

	// List of allowed access types (only AUTHORIZATION_CODE by default)
	AllowedAccessTypes AllowedAccessType
}

func NewServerConfig() *ServerConfig {
	return &ServerConfig{
		AuthorizationExpiration: 250,
		AccessExpiration:        3600,
		TokenType:               "bearer",
		AllowedAuthorizeTypes:   AllowedAuthorizeType{CODE},
		AllowedAccessTypes:      AllowedAccessType{AUTHORIZATION_CODE},
	}
}
