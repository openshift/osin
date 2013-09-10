package osin

import ()

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

// OAuth2 server class
type Server struct {
	Config            *ServerConfig
	Storage           Storage
	AuthorizeTokenGen AuthorizeTokenGen
	AccessTokenGen    AccessTokenGen
}

func NewServer(config *ServerConfig, storage Storage) *Server {
	return &Server{
		Config:            config,
		Storage:           storage,
		AuthorizeTokenGen: &AuthorizeTokenGenDefault{&DefaultTokenGen{}},
		AccessTokenGen:    &AccessTokenGenDefault{&DefaultTokenGen{}},
	}
}
