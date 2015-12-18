package osin

import (
	"crypto/md5"
	"math/rand"
	"fmt"
)

// Client information
type Client interface {
	// Client id
	GetId() string

	// Client secret
	GetSecret() string

	// Base client uri
	GetRedirectUri() string

	// Data to be passed to storage. Not used by the library.
	GetUserData() interface{}
}

// ClientSecretMatcher is an optional interface clients can implement
// which allows them to be the one to determine if a secret matches.
// If a Client implements ClientSecretMatcher, the framework will never call GetSecret
type ClientSecretMatcher interface {
	// SecretMatches returns true if the given secret matches
	ClientSecretMatches(secret string) bool
}

// DefaultClient stores all data in struct variables
type DefaultClient struct {
	Id          string
	Secret      string
	RedirectUri string
	UserData    interface{}
}

func (d *DefaultClient) GetId() string {
	return d.Id
}

func (d *DefaultClient) GetSecret() string {
	return d.Secret
}

func (d *DefaultClient) GetRedirectUri() string {
	return d.RedirectUri
}

func (d *DefaultClient) GetUserData() interface{} {
	return d.UserData
}

// Implement the ClientSecretMatcher interface
func (d *DefaultClient) ClientSecretMatches(secret string) bool {
	return d.Secret == secret
}

func (d *DefaultClient) CopyFrom(client Client) {
	d.Id = client.GetId()
	d.Secret = client.GetSecret()
	d.RedirectUri = client.GetRedirectUri()
	d.UserData = client.GetUserData()
}

// DEFAULTSALTLEN Default number of chars used for SALT
const DEFAULTSALTLEN = 4

// DEFAULTMAXSECRETLEN Default max secret len
const DEFAULTMAXSECRETLEN = 40

// SecuredDefaultClient Secured client Secret implementation
type SecuredDefaultClient struct {
	DefaultClient
	// SaltLen Number of chars used for SALT
	SaltLen int
	// MaxSecretLen Max secret len
	MaxSecretLen int
}

// ClientSecretMatches with salt encrytion
func (d *SecuredDefaultClient) ClientSecretMatches(secret string) bool {
	d.checkLens()
	if len(d.Secret) <= d.SaltLen {
		return false;
	}
	salt := d.Secret[0:d.SaltLen]
	expected := d.saltPassword(salt, secret)
	return d.Secret == expected
}

// checkLens verrify SaltLen and MaxSecretLen values
func (d *SecuredDefaultClient) checkLens() {
	if d.SaltLen <= 0 {
		d.SaltLen = DEFAULTSALTLEN
	}
	if d.MaxSecretLen <= 0 {
		d.MaxSecretLen = DEFAULTMAXSECRETLEN
	}
}

// SaltPassword generate a Saled Secret
func (d *SecuredDefaultClient) SaltPassword(newPass string) {
	d.checkLens()
	b := make([]rune, d.SaltLen)
	var runes = []rune("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	var ll = len(runes)
	for i:=0; i< d.SaltLen; i++ {
		b[i] = runes[rand.Intn(ll)];
	}
	d.Secret = d.saltPassword(string(b), newPass)
}

// saltPassword compute saled Secret
func (d *SecuredDefaultClient) saltPassword(salt string, secret string) string {
	secret = salt + secret
	bytes := []byte(secret)
	sum := md5.Sum(bytes)
	salted := fmt.Sprintf("%s%x", salt, sum)
	if len(salted) > d.MaxSecretLen {
		salted = salted[0:d.MaxSecretLen]
	}
	return salted
}