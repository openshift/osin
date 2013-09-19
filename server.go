package osin

import ()

// OAuth2 server class
type Server struct {
	Config            *ServerConfig
	Storage           Storage
	AuthorizeTokenGen AuthorizeTokenGen
	AccessTokenGen    AccessTokenGen
}

// Creates a new server instance
func NewServer(config *ServerConfig, storage Storage) *Server {
	return &Server{
		Config:            config,
		Storage:           storage,
		AuthorizeTokenGen: &AuthorizeTokenGenDefault{},
		AccessTokenGen:    &AccessTokenGenDefault{},
	}
}

// Creates a new response for the server
func (s *Server) NewResponse() *Response {
	r := NewDefaultResponse()
	r.ErrorStatusCode = s.Config.ErrorStatusCode
	return r
}
