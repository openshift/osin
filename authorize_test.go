package osin

import (
	"net/http"
	"net/url"
	"testing"
)

func TestAuthorize(t *testing.T) {
	server := NewServer(NewServerConfig(), NewTestingStorage())
	server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}
	resp := server.NewResponse()

	req, err := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "1234")
	req.Form.Set("state", "a")

	if ar := server.HandleAuthorizeRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAuthorizeRequest(resp, req, ar)
	}

	if resp.IsError && resp.InternalError != nil {
		t.Fatalf("Error in response: %s", resp.InternalError)
	}

	if resp.IsError {
		t.Fatalf("Should not be an error")
	}

	if resp.Type != REDIRECT {
		t.Fatalf("Response should be a redirect")
	}

	if d := resp.Output["code"]; d != "1" {
		t.Fatalf("Unexpected authorization code: %s", d)
	}

	//fmt.Printf("%+v", resp)
}
