package osin

type AuthMethod string

const (
	NONE                AuthMethod = "none" // The client is public
	CLIENT_SECRET_BASIC AuthMethod = "client_secret_basic"
	CLIENT_SECRET_POST  AuthMethod = "client_secret_post"
)

// Client information
type Client interface {
	// Client id
	GetId() string

	// Client secret
	GetSecret() string

	// Authentication Method
	GetAuthMethod() AuthMethod

	// Base client uri
	GetRedirectUri() string

	// Data to be passed to storage. Not used by the library.
	GetUserData() interface{}
}

// DefaultClient stores all data in struct variables
type DefaultClient struct {
	Id          string
	Secret      string
	AuthMethod  AuthMethod
	RedirectUri string
	UserData    interface{}
}

func (d *DefaultClient) GetId() string {
	return d.Id
}

func (d *DefaultClient) GetSecret() string {
	return d.Secret
}

func (d *DefaultClient) GetAuthMethod() AuthMethod {
	return d.AuthMethod
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
