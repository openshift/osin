package osin

import (
	"crypto/sha256"
	"math/rand"
	"fmt"
)

var GenSalt func() string
//var GenSalt = GenSalt6

var SaltPassword func(salt string, secret string) string
//var SaltPassword = SaltPasswordSHA256

func init() {
	SetSaltLen(6, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	SetPasswordFnc("sample", 128)
}

func SetPasswordFnc(globalSalt string, maxSecretLen int) {
	SaltPassword = func (salt string, secret string) string {
		sumData := sha256.Sum256([]byte(globalSalt + salt + secret))
		sumStr := fmt.Sprintf("%x", sumData)
		if len(sumStr) > maxSecretLen {
			sumStr = sumStr[0:maxSecretLen]
		}
		return sumStr
	}
}

func SetSaltLen(saltLen int, charset string) {
	GenSalt = func() string {
		b := make([]rune, saltLen)
		var runes = []rune(charset)
		var ll = len(runes)
		for i:=0; i<saltLen; i++ {
			b[i] = runes[rand.Intn(ll)];
		}
		return string(b)
	}
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
	expected := SaltPassword(d.Salt, secret)
	return d.SecretSum == expected
}

// UpdateSaltedSecret generate a Saled Secret
func (d *SecuredDefaultClient) UpdateSaltedSecret(newSecret string) {
	d.Salt = GenSalt()
	d.SecretSum = SaltPassword(d.Salt, newSecret)
}
