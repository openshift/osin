package osin

import (
	"encoding/base64"
	"errors"
	"net/http"
	"reflect"
	"strings"
)

// Parse basic authentication header
type BasicAuth struct {
	Username string
	Password string
}

// Parse bearer authentication header
type BearerAuth struct {
	Code string
}

// CheckClientSecret determines whether the given secret matches a secret held by the client.
// Public clients return true for a secret of ""
func CheckClientSecret(client Client, secret string) bool {
	switch client := client.(type) {
	case ClientSecretMatcher:
		// Prefer the more secure method of giving the secret to the client for comparison
		return client.ClientSecretMatches(secret)
	default:
		// Fallback to the less secure method of extracting the plain text secret from the client for comparison
		return client.GetSecret() == secret
	}
}

// Return authorization header data
func CheckBasicAuth(r *http.Request) (*BasicAuth, error) {
	if r.Header.Get("Authorization") == "" {
		return nil, nil
	}

	s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 || s[0] != "Basic" {
		return nil, errors.New("Invalid authorization header")
	}

	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return nil, err
	}
	pair := strings.SplitN(string(b), ":", 2)
	if len(pair) != 2 {
		return nil, errors.New("Invalid authorization message")
	}

	return &BasicAuth{Username: pair[0], Password: pair[1]}, nil
}

// Return "Bearer" token from request. The header has precedence over query string.
func CheckBearerAuth(r *http.Request) *BearerAuth {
	authHeader := r.Header.Get("Authorization")
	authForm := r.Form.Get("code")
	if authHeader == "" && authForm == "" {
		return nil
	}
	token := authForm
	if authHeader != "" {
		s := strings.SplitN(authHeader, " ", 2)
		if (len(s) != 2 || strings.ToLower(s[0]) != "bearer") && token == "" {
			return nil
		}
		//Use authorization header token only if token type is bearer else query string access token would be returned
		if len(s) > 0 && strings.ToLower(s[0]) == "bearer" {
			token = s[1]
		}
	}
	return &BearerAuth{Code: token}
}

// getClientAuth checks client basic authentication in params if allowed,
// otherwise gets it from the header.
// Sets an error on the response if no auth is present or a server error occurs.
func getClientAuth(w *Response, r *http.Request, allowQueryParams bool) *BasicAuth {

	if allowQueryParams {
		// Allow for auth without password
		if _, hasSecret := r.Form["client_secret"]; hasSecret {
			auth := &BasicAuth{
				Username: r.Form.Get("client_id"),
				Password: r.Form.Get("client_secret"),
			}
			if auth.Username != "" {
				return auth
			}
		}
	}

	auth, err := CheckBasicAuth(r)
	if err != nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = err
		return nil
	}
	if auth == nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = errors.New("Client authentication not sent")
		return nil
	}
	return auth
}

func EqualAuthorizeRequestType(t1, t2 AuthorizeRequestType) bool {
	t1s := strings.Split(string(t1), " ")
	t2s := strings.Split(string(t2), " ")
	return reflect.DeepEqual(t1s, t2s)
}

func GetKnownAuthorizeRequestType(rt AuthorizeRequestType) AuthorizeRequestType {
	rts := strings.Split(string(rt), " ")
	hasToken := false
	for _, v := range rts {
		switch AuthorizeRequestType(v) {
		case CODE: // if both of CODE and TOKEN exist, considered as code flow
			return CODE
		case TOKEN:
			hasToken = true
		}
	}
	if hasToken {
		return TOKEN
	} else {
		return ""
	}
}
