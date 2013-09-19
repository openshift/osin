package osin

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

// Parse basic authentication header
type BasicAuth struct {
	Username string
	Password string
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

// Check client authentication in params if allowed, and on authorization header
func CheckClientAuth(r *http.Request, useparams bool) (*BasicAuth, error) {
	if useparams {
		ret := &BasicAuth{Username: r.Form.Get("client_id"), Password: r.Form.Get("client_secret")}
		if ret.Username != "" && ret.Password != "" {
			return ret, nil
		}
	}

	return CheckBasicAuth(r)
}
