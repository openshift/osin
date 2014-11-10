package osin

import (
	"net/http"
)

// Server is an OAuth2 implementation
type Server struct {
	Config            *ServerConfig
	Storage           Storage
	AuthorizeTokenGen AuthorizeTokenGen
	AccessTokenGen    AccessTokenGen
}

// NewServer creates a new server instance
func NewServer(config *ServerConfig, storage Storage) *Server {
	return &Server{
		Config:            config,
		Storage:           storage,
		AuthorizeTokenGen: &AuthorizeTokenGenDefault{},
		AccessTokenGen:    &AccessTokenGenDefault{},
	}
}

// NewResponse creates a new response for the server
func (s *Server) NewResponse() *Response {
	r := &Response{
		Type:            DATA,
		StatusCode:      200,
		ErrorStatusCode: s.Config.ErrorStatusCode,
		Output:          make(ResponseData),
		Headers:         make(http.Header),
		IsError:         false,
		Storage:         s.Storage.Clone(),
	}
	r.Headers.Add("Cache-Control", "no-store")
	return r
}
