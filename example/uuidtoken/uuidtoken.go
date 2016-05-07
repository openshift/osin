package uuidtoken

import (
	"encoding/base64"
	"strings"

	"github.com/pborman/uuid"
)

// UUIDTokenGen generates authorization and access tokens using bytes from a random UUID
type UUIDTokenGen struct {
}

func removePadding(token string) string {
	return strings.TrimRight(token, "=")
}

// GenerateAuthorizeToken generates a base64-encoded UUID code
func (a *UUIDTokenGen) GenerateAuthorizeToken(data *AuthorizeData) (ret string, err error) {
	token := uuid.NewRandom()
	return removePadding(base64.URLEncoding.EncodeToString([]byte(token))), nil
}

// GenerateAccessToken generates base64-encoded UUID access and refresh tokens
func (a *UUIDTokenGen) GenerateAccessToken(data *AccessData, generaterefresh bool) (accesstoken string, refreshtoken string, err error) {
	token := uuid.NewRandom()
	accesstoken = removePadding(base64.URLEncoding.EncodeToString([]byte(token)))

	if generaterefresh {
		rtoken := uuid.NewRandom()
		refreshtoken = removePadding(base64.URLEncoding.EncodeToString([]byte(rtoken)))
	}
	return
}
