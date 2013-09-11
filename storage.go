package osin

import ()

// Storage interface
type Storage interface {
	// Load client.
	GetClient(id string) (*Client, error)

	// Save authorize data.
	SaveAuthorize(*AuthorizeData) error

	// Load authorize data. Client information MUST be loaded together.
	// Optionally can return error if expired.
	LoadAuthorize(code string) (*AuthorizeData, error)

	// Remove authorize data.
	RemoveAuthorize(code string) error

	// Save access data. If RefreshToken is not blank, must save in a way
	// that can be loaded using LoadRefresh.
	SaveAccess(*AccessData) error

	// Load access data. Client information MUST be loaded together.
	// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
	// Optionally can return error if expired.
	LoadAccess(code string) (*AccessData, error)

	// Remove access data.
	RemoveAccess(code string) error

	// Load refresh access data. Client information MUST be loaded together.
	// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
	// Optionally can return error if expired.
	LoadRefresh(code string) (*AccessData, error)

	// Remove refresh data.
	RemoveRefresh(code string) error
}
