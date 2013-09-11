package osin

// Helper allowing objects
type AllowedAuthorizeType []AuthorizeRequestType
type AllowedAccessType []AccessRequestType

func (t AllowedAuthorizeType) Exists(rt AuthorizeRequestType) bool {
	for _, k := range t {
		if k == rt {
			return true
		}
	}
	return false
}

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
	AuthorizationExpiration int32
	AccessExpiration        int32
	TokenType               string
	AllowedAuthorizeTypes   AllowedAuthorizeType
	AllowedAccessTypes      AllowedAccessType
}

func NewServerConfig() *ServerConfig {
	return &ServerConfig{
		AuthorizationExpiration: 3600,
		AccessExpiration:        3600,
		TokenType:               "bearer",
		AllowedAuthorizeTypes:   AllowedAuthorizeType{CODE},
		AllowedAccessTypes:      AllowedAccessType{AUTHORIZATION_CODE},
	}
}
