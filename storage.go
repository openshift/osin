package osin

import "golang.org/x/net/context"

// Storage interface
type Storage interface {
	// Clone the storage if needed. For example, using mgo, you can clone the session with session.Clone
	// to avoid concurrent access problems.
	// This is to avoid cloning the connection at each method access.
	// Can return itself if not a problem.
	Clone() Storage

	// Close the resources the Storage potentially holds (using Clone for example)
	Close()

	// GetClient loads the client by id (client_id)
	GetClient(id string) (Client, error)

	// SaveAuthorize saves authorize data.
	SaveAuthorize(*AuthorizeData) error

	// LoadAuthorize looks up AuthorizeData by a code.
	// Client information MUST be loaded together.
	// Optionally can return error if expired.
	LoadAuthorize(code string) (*AuthorizeData, error)

	// RemoveAuthorize revokes or deletes the authorization code.
	RemoveAuthorize(code string) error

	// SaveAccess writes AccessData.
	// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
	SaveAccess(*AccessData) error

	// LoadAccess retrieves access data by token. Client information MUST be loaded together.
	// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
	// Optionally can return error if expired.
	LoadAccess(token string) (*AccessData, error)

	// RemoveAccess revokes or deletes an AccessData.
	RemoveAccess(token string) error

	// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
	// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
	// Optionally can return error if expired.
	LoadRefresh(token string) (*AccessData, error)

	// RemoveRefresh revokes or deletes refresh AccessData.
	RemoveRefresh(token string) error
}

// Storage interface that takes a context object for database operations.
type StorageWithContext interface {
	// Clone the storage if needed. For example, using mgo, you can clone the session with session.Clone
	// to avoid concurrent access problems.
	// This is to avoid cloning the connection at each method access.
	// Can return itself if not a problem.
	Clone(ctx context.Context) StorageWithContext

	// Close the resources the Storage potentially holds (using Clone for example)
	Close()

	// GetClient loads the client by id (client_id)
	GetClient(ctx context.Context, id string) (Client, error)

	// SaveAuthorize saves authorize data.
	SaveAuthorize(ctx context.Context, data *AuthorizeData) error

	// LoadAuthorize looks up AuthorizeData by a code.
	// Client information MUST be loaded together.
	// Optionally can return error if expired.
	LoadAuthorize(ctx context.Context, code string) (*AuthorizeData, error)

	// RemoveAuthorize revokes or deletes the authorization code.
	RemoveAuthorize(ctx context.Context, code string) error

	// SaveAccess writes AccessData.
	// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
	SaveAccess(ctx context.Context, data *AccessData) error

	// LoadAccess retrieves access data by token. Client information MUST be loaded together.
	// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
	// Optionally can return error if expired.
	LoadAccess(ctx context.Context, token string) (*AccessData, error)

	// RemoveAccess revokes or deletes an AccessData.
	RemoveAccess(ctx context.Context, token string) error

	// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
	// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
	// Optionally can return error if expired.
	LoadRefresh(ctx context.Context, token string) (*AccessData, error)

	// RemoveRefresh revokes or deletes refresh AccessData.
	RemoveRefresh(ctx context.Context, token string) error
}

type oldStorageWithContext struct {
	Storage
}

func (s *oldStorageWithContext) Clone(ctx context.Context) StorageWithContext {
	return &oldStorageWithContext{Storage: s.Storage.Clone()}
}

func (s *oldStorageWithContext) GetClient(ctx context.Context, id string) (Client, error) {
	return s.Storage.GetClient(id)
}

func (s *oldStorageWithContext) SaveAuthorize(ctx context.Context, data *AuthorizeData) error {
	return s.Storage.SaveAuthorize(data)
}

func (s *oldStorageWithContext) LoadAuthorize(ctx context.Context, code string) (*AuthorizeData, error) {
	return s.Storage.LoadAuthorize(code)
}

func (s *oldStorageWithContext) RemoveAuthorize(ctx context.Context, code string) error {
	return s.Storage.RemoveAuthorize(code)
}

func (s *oldStorageWithContext) SaveAccess(ctx context.Context, access *AccessData) error {
	return s.Storage.SaveAccess(access)
}

func (s *oldStorageWithContext) LoadAccess(ctx context.Context, token string) (*AccessData, error) {
	return s.Storage.LoadAccess(token)
}

func (s *oldStorageWithContext) RemoveAccess(ctx context.Context, token string) error {
	return s.Storage.RemoveAccess(token)
}

func (s *oldStorageWithContext) LoadRefresh(ctx context.Context, token string) (*AccessData, error) {
	return s.Storage.LoadRefresh(token)
}

func (s *oldStorageWithContext) RemoveRefresh(ctx context.Context, token string) error {
	return s.Storage.RemoveRefresh(token)
}
