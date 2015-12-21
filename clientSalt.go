package osin

import (
	"crypto/sha256"
	"math/rand"
	"fmt"
)

var globalSalt = "changeMe"

var saltLen = 4

var maxSecretLen = 128

// SaltLen number of chars used for SALT (change it one at process start)
func SaltLen(len int) {
	saltLen = len
}

// GlobalSalt set the common salt for all entry in base
func GlobalSalt(salt string) {
	globalSalt = salt
}

// maxSecretLen max secret len (change it one at process start)
func MaxSecretLen(len int) {
	maxSecretLen = len
}

// SecuredDefaultClient Secured client Secret implementation
type SecuredDefaultClient struct {
	Id           string
	Salt         string
	SecretSum    string
	RedirectUri  string
	UserData     interface{}
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
	expected := SaltPasswordSHA256(d.Salt, secret)
	return d.SecretSum == expected
}

// UpdateSaltedSecret generate a Saled Secret
func (d *SecuredDefaultClient) UpdateSaltedSecret(newSecret string) {
	d.Salt = GenSalt()
	d.SecretSum = SaltPasswordSHA256(d.Salt, newSecret)
}

// GenSalt returna random String used for salting
func GenSalt() string {
	b := make([]rune, saltLen)
	var runes = []rune("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	var ll = len(runes)
	for i:=0; i<saltLen; i++ {
		b[i] = runes[rand.Intn(ll)];
	}
	return string(b)
}

// saltPasswordSHA256 compute saled Secret
func SaltPasswordSHA256(salt string, secret string) string {
	sum := sha256.Sum256([]byte(globalSalt + salt + secret))
	sumStr := fmt.Sprintf("%x", sum)
	if len(sumStr) > maxSecretLen {
		sumStr = sumStr[0:maxSecretLen]
	}
	return sumStr
}
