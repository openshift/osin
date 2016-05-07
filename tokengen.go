package osin

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"
)

func randomBytes(len int) []byte {
	b := make([]byte, len)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		// rand.Reader should never fail
		panic(err.Error())
	}
	return b
}
func randomToken() string {
	// 16 bytes (128 bits) = 22 base64-encoded characters
	b := randomBytes(16)
	// Use URLEncoding to ensure we don't get / characters
	s := base64.URLEncoding.EncodeToString(b)
	// Strip trailing ='s... they're ugly
	return strings.TrimRight(s, "=")
}

// AuthorizeTokenGenDefault is the default authorization token generator
type AuthorizeTokenGenDefault struct {
}

// GenerateAuthorizeToken generates a base64-encoded random code
func (a *AuthorizeTokenGenDefault) GenerateAuthorizeToken(data *AuthorizeData) (ret string, err error) {
	return randomToken(), nil
}

// AccessTokenGenDefault is the default authorization token generator
type AccessTokenGenDefault struct {
}

// GenerateAccessToken generates base64-encoded random access and refresh tokens
func (a *AccessTokenGenDefault) GenerateAccessToken(data *AccessData, generaterefresh bool) (accesstoken string, refreshtoken string, err error) {
	accesstoken = randomToken()
	if generaterefresh {
		refreshtoken = randomToken()
	}
	return
}
