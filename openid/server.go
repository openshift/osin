package openid

import (
	"github.com/RangelReale/osin"
)

type Server struct {
	OsinServer *osin.Server

	// Issuer identifier
	IssuerIdentifier string

	// jwt library signong methods (RS256, HS256)
	SigningMethod string

	PrivateKey []byte
	PublicKey  []byte
}

// NewServer creates a new server instance
func NewServer(osinserver *osin.Server, IssuerIdentifier string, SigningMethod string) *Server {
	return &Server{
		OsinServer:       osinserver,
		IssuerIdentifier: IssuerIdentifier,
		SigningMethod:    SigningMethod,
	}
}

// NewServer creates a new server instance
func NewServerAssociation(osinserver *osin.Server, IssuerIdentifier string, SigningMethod string) *Server {
	s := NewServer(osinserver, IssuerIdentifier, SigningMethod)
	osinserver.AccessOutput = s
	return s
}
