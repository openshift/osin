package osin

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// Data for response output
type ResponseData map[string]interface{}

// Response type enum
type ResponseType int

const (
	DATA ResponseType = iota
	REDIRECT
)

// Interface for response output
type ResponseOutput interface {
	Output(*Response, http.ResponseWriter, *http.Request) error
}

// Server response
type Response struct {
	Type               ResponseType
	StatusCode         int
	StatusText         string
	ErrorStatusCode    int
	URL                string
	Output             ResponseData
	Headers            http.Header
	IsError            bool
	InternalError      error
	RedirectInFragment bool
}

// Creates a new response
func NewResponse() *Response {
	r := &Response{
		Type:            DATA,
		StatusCode:      200,
		ErrorStatusCode: 200,
		Output:          make(ResponseData),
		Headers:         make(http.Header),
		IsError:         false,
	}
	r.Headers.Add("Cache-Control", "no-store")
	return r
}

// Set error
func (r *Response) SetError(id string, description string) {
	r.SetErrorUri(id, description, "", "")
}

// Set error with state
func (r *Response) SetErrorState(id string, description string, state string) {
	r.SetErrorUri(id, description, "", state)
}

// Set error with uri
func (r *Response) SetErrorUri(id string, description string, uri string, state string) {
	// get default error message
	if description == "" {
		description = deferror.Get(id)
	}

	// set error parameters
	r.IsError = true
	r.StatusCode = r.ErrorStatusCode
	r.Output = make(ResponseData) // clear output
	r.Output["error"] = id
	r.Output["error_description"] = description
	if uri != "" {
		r.Output["error_uri"] = uri
	}
	if state != "" {
		r.Output["state"] = state
	}
}

// Set response to be redirect instead of data output
func (r *Response) SetRedirect(url string) {
	// set redirect parameters
	r.Type = REDIRECT
	r.URL = url
}

// If true, redirect values are passed in fragment instead of as query parameters
func (r *Response) SetRedirectFragment(f bool) {
	r.RedirectInFragment = f
}

// Returns the redirect url with parameters
func (r *Response) GetRedirectUrl() (string, error) {
	if r.Type != REDIRECT {
		return "", errors.New("Not a redirect response")
	}

	u, err := url.Parse(r.URL)
	if err != nil {
		return "", err
	}

	// add parameters
	q := u.Query()
	for n, v := range r.Output {
		q.Set(n, fmt.Sprint(v))
	}
	if r.RedirectInFragment {
		u.RawQuery = ""
		u.Fragment = q.Encode()
	} else {
		u.RawQuery = q.Encode()
	}

	return u.String(), nil
}
