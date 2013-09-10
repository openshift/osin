package osin

// Client information
type Client struct {
	Id          string
	Secret      string
	RedirectUri string
	UserData    interface{}
}
