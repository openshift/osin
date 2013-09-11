package osin

import (
	"net/http"
	"testing"
)

func TestBasicAuth(t *testing.T) {
	r := &http.Request{Header: make(http.Header)}

	// Without any header
	if b, err := CheckBasicAuth(r); b != nil || err != nil {
		t.Errorf("Validated basic auth without header")
	}

	// with invalid header
	r.Header.Set("Authorization", "Digest XHHHHHHH")
	b, err := CheckBasicAuth(r)
	if b != nil || err == nil {
		t.Errorf("Validated invalid auth")
		return
	}

	// with valid header
	r.Header.Set("Authorization", "Basic dGVzdDp0ZXN0")
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
