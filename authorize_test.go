package osin

import (
	"net/http"
	"net/url"
	"testing"
)

var redirectURITestCases = map[string]struct {
	StorageURI string
	RequestURI string
}{
	"unspecified": {
		StorageURI: "http://localhost:14000/appauth",
		RequestURI: "",
	},
	"specified": {
		StorageURI: "http://localhost:14000/appauth",
		RequestURI: "http://localhost:14000/appauth",
	},
	"special": {
		StorageURI: "http://localhost:14000/app%25auth",
		RequestURI: "http://localhost:14000/app%25auth",
	},
}

func TestAuthorizeCode(t *testing.T) {
	for desc, testcase := range redirectURITestCases {
		sconfig := NewServerConfig()
		sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
		server := NewServer(sconfig, NewTestingStorageWithRedirectURI(testcase.StorageURI))
		server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}
		resp := server.NewResponse()

		req, err := http.NewRequest("GET", "http://example.com", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Form = make(url.Values)
		req.Form.Set("response_type", string(CODE))
		req.Form.Set("client_id", "1234")
		req.Form.Set("state", "a")
		if len(testcase.RequestURI) > 0 {
			req.Form.Set("redirect_uri", testcase.RequestURI)
		}

		if ar := server.HandleAuthorizeRequest(resp, req); ar != nil {
			ar.Authorized = true
			server.FinishAuthorizeRequest(resp, req, ar)
		}

		//fmt.Printf("%+v", resp)

		if resp.IsError && resp.InternalError != nil {
			t.Errorf("%s: Error in response: %s", desc, resp.InternalError)
			continue
		}

		if resp.IsError {
			t.Errorf("%s: Should not be an error", desc)
			continue
		}

		if resp.Type != REDIRECT {
			t.Errorf("%s: Response should be a redirect", desc)
			continue
		}

		if d := resp.Output["code"]; d != "1" {
			t.Errorf("%s: Unexpected authorization code: %s", desc, d)
			continue
		}
	}
}

func TestAuthorizeToken(t *testing.T) {
	for desc, testcase := range redirectURITestCases {
		sconfig := NewServerConfig()
		sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{TOKEN}
		server := NewServer(sconfig, NewTestingStorageWithRedirectURI(testcase.StorageURI))
		server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}
		server.AccessTokenGen = &TestingAccessTokenGen{}
		resp := server.NewResponse()

		req, err := http.NewRequest("GET", "http://example.com", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Form = make(url.Values)
		req.Form.Set("response_type", string(TOKEN))
		req.Form.Set("client_id", "1234")
		req.Form.Set("state", "a")
		if len(testcase.RequestURI) > 0 {
			req.Form.Set("redirect_uri", testcase.RequestURI)
		}

		if ar := server.HandleAuthorizeRequest(resp, req); ar != nil {
			ar.Authorized = true
			server.FinishAuthorizeRequest(resp, req, ar)
		}

		//fmt.Printf("%+v", resp)

		if resp.IsError && resp.InternalError != nil {
			t.Errorf("%s: Error in response: %s", desc, resp.InternalError)
			continue
		}

		if resp.IsError {
			t.Errorf("%s: Should not be an error", desc)
			continue
		}

		if resp.Type != REDIRECT || !resp.RedirectInFragment {
			t.Errorf("%s: Response should be a redirect with fragment", desc)
			continue
		}

		if d := resp.Output["access_token"]; d != "1" {
			t.Errorf("%s: Unexpected access token: %s", desc, d)
			continue
		}
	}
}
