// +build go1.7

package osin

import (
	"net/http"

	"golang.org/x/net/context"
)

func contextFromRequest(req *http.Request) context.Context {
	return req.Context()
}
