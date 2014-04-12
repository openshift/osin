package osin

import (
	"net/http"
)

// Storage interface
type Storage interface {

	// GetClient loads the client by id (client_id)
	GetClient(id string, r *http.Request) (*Client, error)

	// SaveAuthorize saves authorize data.
	SaveAuthorize(d *AuthorizeData, r *http.Request) error

	// LoadAuthorize looks up AuthorizeData by a code.
	// Client information MUST be loaded together.
	// Optionally can return error if expired.
	LoadAuthorize(code string, r *http.Request) (*AuthorizeData, error)

	// RemoveAuthorize revokes or deletes the authorization code.
	RemoveAuthorize(code string, r *http.Request) error

	// SaveAccess writes AccessData.
	// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
	SaveAccess(d *AccessData, r *http.Request) error

	// LoadAccess retrieves access data by token. Client information MUST be loaded together.
	// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
	// Optionally can return error if expired.
	LoadAccess(token string, r *http.Request) (*AccessData, error)

	// RemoveAccess revokes or deletes an AccessData.
	RemoveAccess(token string, r *http.Request) error

	// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
	// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
	// Optionally can return error if expired.
	LoadRefresh(token string, r *http.Request) (*AccessData, error)

	// RemoveRefresh revokes or deletes refresh AccessData.
	RemoveRefresh(token string, r *http.Request) error
}
