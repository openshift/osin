OSIN
====

Golang OAuth2 server library
----------------------------

OSIN is an OAuth2 server library for the Go language, as specified at
http://tools.ietf.org/html/rfc6749 and http://tools.ietf.org/html/draft-ietf-oauth-v2-10.

Using it, you can build your own OAuth2 authentication service.

The library implements the majority of the specification, like authorization and token endpoints, and authorization code, implicit, resource owner and client credentials grant types.

### Dependencies

* go-uuid (http://code.google.com/p/go-uuid)

### Example Server

````go
import "github.com/RangelReale/osin"

// TestStorage implements the "osin.Storage" interface
server := osin.NewServer(osin.NewServerConfig(), &TestStorage{})

// Authorization code endpoint
http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
	resp := server.NewResponse()
	if ar := server.HandleAuthorizeRequest(resp, r); ar != nil {

		// HANDLE LOGIN PAGE HERE

		ar.Authorized = true
		server.FinishAuthorizeRequest(resp, r, ar)
	}
	osin.OutputJSON(resp, w, r)
})

// Access token endpoint
http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
	resp := server.NewResponse()
	if ar := server.HandleAccessRequest(resp, r); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(resp, r, ar)
	}
	osin.OutputJSON(resp, w, r)
})

http.ListenAndServe(":14000", nil)
````

### Example Access

Open in your web browser:

````
http://localhost:14000/authorize?response_type=code&client_id=1234&redirect_url=http%3A%2F%2Flocalhost%3A14000%2Fappauth%2Fcode
````

### License

The code is licensed using "New BSD" license.

### Author

Rangel Reale
