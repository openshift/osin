package osin

// Client information
type Client struct {
	// Client id
	Id string

	// Client secret
	Secret string

	// Base client uri
	RedirectUri string

	// Data to be passed to storage. Not used by the library.
	UserData interface{}
}
