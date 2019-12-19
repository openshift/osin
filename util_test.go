package osin

import (
	"net/http"
	"net/url"
	"testing"
)

const (
	badAuthValue           = "Digest XHHHHHHH"
	badUsernameInAuthValue = "Basic dSUyc2VybmFtZTpwYXNzd29yZA==" // u%2sername:password
	badPasswordInAuthValue = "Basic dXNlcm5hbWU6cGElMnN3b3Jk"     // username:pa%2sword
	goodAuthValue          = "Basic Y2xpZW50K25hbWU6Y2xpZW50KyUyNGVjcmV0"
	goodBearerAuthValue    = "Bearer BGFVTDUJDp0ZXN0"
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

	// with invalid username
	r.Header.Set("Authorization", badUsernameInAuthValue)
	b, err = CheckBasicAuth(r)
	if b != nil || err == nil {
		t.Errorf("Validated invalid auth with bad username")
		return
	}

	// with invalid username
	r.Header.Set("Authorization", badPasswordInAuthValue)
	b, err = CheckBasicAuth(r)
	if b != nil || err == nil {
		t.Errorf("Validated invalid auth with bad password")
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
	if b.Username != "client name" || b.Password != "client $ecret" {
		t.Errorf("Error decoding basic auth")
	}
}

func TestGetClientAuth(t *testing.T) {

	urlWithSecret, _ := url.Parse("http://host.tld/path?client_id=xxx&client_secret=yyy")
	urlWithEmptySecret, _ := url.Parse("http://host.tld/path?client_id=xxx&client_secret=")
	urlNoSecret, _ := url.Parse("http://host.tld/path?client_id=xxx")

	headerNoAuth := make(http.Header)
	headerBadAuth := make(http.Header)
	headerBadAuth.Set("Authorization", badAuthValue)
	headerOKAuth := make(http.Header)
	headerOKAuth.Set("Authorization", goodAuthValue)

	sconfig := NewServerConfig()
	server := NewServer(sconfig, NewTestingStorage())

	var tests = []struct {
		header           http.Header
		url              *url.URL
		allowQueryParams bool
		expectAuth       bool
	}{
		{headerNoAuth, urlWithSecret, true, true},
		{headerNoAuth, urlWithSecret, false, false},
		{headerNoAuth, urlWithEmptySecret, true, true},
		{headerNoAuth, urlWithEmptySecret, false, false},
		{headerNoAuth, urlNoSecret, true, true},
		{headerNoAuth, urlNoSecret, false, false},

		{headerBadAuth, urlWithSecret, true, true},
		{headerBadAuth, urlWithSecret, false, false},
		{headerBadAuth, urlWithEmptySecret, true, true},
		{headerBadAuth, urlWithEmptySecret, false, false},
		{headerBadAuth, urlNoSecret, true, true},
		{headerBadAuth, urlNoSecret, false, false},

		{headerOKAuth, urlWithSecret, true, true},
		{headerOKAuth, urlWithSecret, false, true},
		{headerOKAuth, urlWithEmptySecret, true, true},
		{headerOKAuth, urlWithEmptySecret, false, true},
		{headerOKAuth, urlNoSecret, true, true},
		{headerOKAuth, urlNoSecret, false, true},
	}

	for testIdx, tt := range tests {
		w := new(Response)
		r := &http.Request{Header: tt.header, URL: tt.url}
		r.ParseForm()
		auth := server.getClientAuth(w, r, tt.allowQueryParams)
		if tt.expectAuth && auth == nil {
			t.Errorf("Auth should not be nil for %v [test %d]", tt, testIdx)
		} else if !tt.expectAuth && auth != nil {
			t.Errorf("Auth should be nil for %v [test %d]", tt, testIdx)
		}
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
