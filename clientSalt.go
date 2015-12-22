package osin

import (
	"crypto/sha256"
	"encoding/base64"
	"math/rand"
)

// encodeURLRunes runes used in salt generator
var encodeURLRunes = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

// SecuredDefaultClient Secured client Secret implementation
type SecuredDefaultClient struct {
	Id           string
	Salt         string
	SecretSum    string
	RedirectUri  string
	UserData     interface{}
	SaltFn       func(salt string, secret string) (saltedSecret string, err error)
}

// GetId return the Client id
func (d *SecuredDefaultClient) GetId() string {
	return d.Id
}

// GetSecret return the SaltedSecret, the secret is unknow
func (d *SecuredDefaultClient) GetSecret() string {
	panic("Using OSIN SecuredClient do not permit you to access secret")
}

// GetRedirectUri return One or more Base client uri separate by config.RedirectUriSeparator
func (d *SecuredDefaultClient) GetRedirectUri() string {
	return d.RedirectUri
}

// GetUserData return Data to be passed to storage. Not used by the library.
func (d *SecuredDefaultClient) GetUserData() interface{} {
	return d.UserData
}

// ClientSecretMatches with salt encrytion
func (d *SecuredDefaultClient) ClientSecretMatches(secret string) bool {
	expected, err := d.SaltFn(d.Salt, secret)
	if (err != nil) {
		return false
	}
	return d.SecretSum == expected
}

// SaltSHA256 Select a predifined salting function
func SaltSHA256(salt string, secret string) (string, error) {
	// get hash bytes
	sumData := sha256.Sum256([]byte(salt + secret))
	// encode using base64 for greater data density than Hexadecimal
	sumString := base64.RawURLEncoding.EncodeToString(sumData[:])
	return sumString, nil
}

// GenSalt create a new salt
func GenSalt(saltLen int) string {
	b := make([]rune, saltLen)
	var ll = len(encodeURLRunes)
	for i:=0; i<saltLen; i++ {
		b[i] = encodeURLRunes[rand.Intn(ll)];
	}
	return string(b)
}
