package osin

import (
	"net/http"
	"net/url"
	"testing"
)

const (
	badAuthValue        = "Digest XHHHHHHH"
	goodAuthValue       = "Basic dGVzdDp0ZXN0"
	goodBearerAuthValue = "Bearer BGFVTDUJDp0ZXN0"
)

func TestBasicAuth(t *testing.T) {
	r := &http.Request{Header: make(http.Header)}

	// Without any header
	if b, err := CheckBasicAuth(r); b != nil || err != nil {
		t.Errorf("Validated basic auth without header")
	}

	// with invalid header
	r.Header.Set("Authorization", badAuthValue)
	b, err := CheckBasicAuth(r)
	if b != nil || err == nil {
		t.Errorf("Validated invalid auth")
		return
	}

	// with valid header
	r.Header.Set("Authorization", goodAuthValue)
	b, err = CheckBasicAuth(r)
	if b == nil || err != nil {
		t.Errorf("Could not extract basic auth")
		return
	}

	// check extracted auth data
	if b.Username != "test" || b.Password != "test" {
		t.Errorf("Error decoding basic auth")
	}
}

func TestBearerAuth(t *testing.T) {
	r := &http.Request{Header: make(http.Header)}

	// Without any header
	if b := CheckBearerAuth(r); b != nil {
		t.Errorf("Validated bearer auth without header")
	}

	// with invalid header
	r.Header.Set("Authorization", badAuthValue)
	b := CheckBearerAuth(r)
	if b != nil {
		t.Errorf("Validated invalid auth")
		return
	}

	// with valid header
	r.Header.Set("Authorization", goodBearerAuthValue)
	b = CheckBearerAuth(r)
	if b == nil {
		t.Errorf("Could not extract bearer auth")
		return
	}

	// check extracted auth data
	if b.Code != "BGFVTDUJDp0ZXN0" {
		t.Errorf("Error decoding bearer auth")
	}

	// extracts bearer auth from query string
	url, _ := url.Parse("http://host.tld/path?code=XYZ")
	r = &http.Request{URL: url}
	r.ParseForm()
	b = CheckBearerAuth(r)
	if b.Code != "XYZ" {
		t.Errorf("Error decoding bearer auth")
	}
}
