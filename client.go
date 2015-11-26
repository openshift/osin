package osin

// Client information
type Client interface {
	// Client id
	GetId() string

	// Client secret
	GetSecret() Secret

	// Base client uri
	GetRedirectUri() string

	// Data to be passed to storage. Not used by the library.
	GetUserData() interface{}
}

// DefaultClient stores all data in struct variables
type DefaultClient struct {
	Id          string
	Secret      Secret
	RedirectUri string
	UserData    interface{}
}

func (d *DefaultClient) GetId() string {
	return d.Id
}

func (d *DefaultClient) GetSecret() Secret {
	return d.Secret
}

func (d *DefaultClient) GetRedirectUri() string {
	return d.RedirectUri
}

func (d *DefaultClient) GetUserData() interface{} {
	return d.UserData
}

func (d *DefaultClient) CopyFrom(client Client) {
	d.Id = client.GetId()
	d.Secret = client.GetSecret()
	d.RedirectUri = client.GetRedirectUri()
	d.UserData = client.GetUserData()
}

// Secret encapsulates information about a client secret.
type Secret interface {
	// Validate returns true if the given string matches the client secret.
	Validate(string) bool
}

// DefaultSecret stores a client secret in cleartext.
type DefaultSecret string

func (d DefaultSecret) Validate(secret string) bool {
	return secret == string(d)
}
