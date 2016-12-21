package osin

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/pborman/uuid"
)

// AuthorizeTokenGenDefault is the default authorization token generator
type AuthorizeTokenGenDefault struct {
}

// GenerateAuthorizeToken generates a base64-encoded UUID code
func (a *AuthorizeTokenGenDefault) GenerateAuthorizeToken(data *AuthorizeData) (ret string, err error) {
	token := uuid.NewRandom()
	return base64.RawURLEncoding.EncodeToString([]byte(token)), nil
}

// AccessTokenGenDefault is the default authorization token generator
type AccessTokenGenDefault struct {
}

// GenerateAccessToken generates base64-encoded UUID access and refresh tokens
func (a *AccessTokenGenDefault) GenerateAccessToken(data *AccessData, generaterefresh bool) (accesstoken string, refreshtoken string, err error) {
	token := uuid.NewRandom()
	accesstoken = base64.RawURLEncoding.EncodeToString([]byte(token))

	if generaterefresh {
		rtoken := uuid.NewRandom()
		refreshtoken = base64.RawURLEncoding.EncodeToString([]byte(rtoken))
	}
	return
}

// AccessTokenSubScoperDefault checks if the given scopes of AT request are a string subset of already granted scopes.
type AccessTokenSubScoperDefault struct {
}

// GenerateAccessToken generates base64-encoded UUID access and refresh tokens
func (a *AccessTokenSubScoperDefault) CheckSubScopes(accessTokenScopes string, refreshTokenScopes string) (resultingScope string, err error) {
	refresh_scopes_list := strings.Split(refreshTokenScopes, ",")
	access_scope_list := strings.Split(accessTokenScopes, ",")

	refresh_map := make(map[string]int)

	for _, scope := range refresh_scopes_list {
		if scope == "" {
			continue
		}
		refresh_map[scope] = 1
	}

	for _, scope := range access_scope_list {
		if scope == "" {
			continue
		}
		if _, ok := refresh_map[scope]; !ok {
			return "", fmt.Errorf("scope %v is not in original grant")
		}
	}
	return accessTokenScopes, nil
}
