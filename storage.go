package osin

import ()

// Storage interface
type Storage interface {
	GetClient(id string) (*Client, error)

	SaveAuthorize(*AuthorizeData) error
	LoadAuthorize(code string) (*AuthorizeData, error)
	RemoveAuthorize(code string) error

	SaveAccess(*AccessData) error
	LoadAccess(code string) (*AccessData, error)
	RemoveAccess(code string) error

	LoadRefresh(code string) (*AccessData, error)
	RemoveRefresh(code string) error
}
