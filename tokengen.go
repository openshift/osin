package osin

import (
	"encoding/base64"
	"strings"

	"github.com/satori/go.uuid"
)

// AuthorizeTokenGenDefault is the default authorization token generator
type AuthorizeTokenGenDefault struct {
}

func removePadding(token string) string {
	return strings.TrimRight(token, "=")
}

// GenerateAuthorizeToken generates a base64-encoded UUID code
func (a *AuthorizeTokenGenDefault) GenerateAuthorizeToken(data *AuthorizeData) (ret string, err error) {
	token := uuid.NewV4()
	return removePadding(base64.URLEncoding.EncodeToString(token.Bytes())), nil
}

// AccessTokenGenDefault is the default authorization token generator
type AccessTokenGenDefault struct {
}

// GenerateAccessToken generates base64-encoded UUID access and refresh tokens
func (a *AccessTokenGenDefault) GenerateAccessToken(data *AccessData, generaterefresh bool) (accesstoken string, refreshtoken string, err error) {
	token := uuid.NewV4()
	accesstoken = removePadding(base64.URLEncoding.EncodeToString(token.Bytes()))

	if generaterefresh {
		rtoken := uuid.NewV4()
		refreshtoken = removePadding(base64.URLEncoding.EncodeToString(rtoken.Bytes()))
	}
	return
}
