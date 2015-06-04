package osin

import (
	
	"testing"
	"net/url"
	"net/http"
	"bytes"
	"strconv"
	"encoding/base64"
	"fmt"
)

type AuthHeader struct {
	UserName		*string
	Password		*string
	HeaderName 		string
	FormattedValue 	string
}


func TestAuthenticateClient_password(t *testing.T) {

	headerNoAuth := &AuthHeader{}
	headerBadAuth := &AuthHeader{ HeaderName: "Authorization", FormattedValue: "Digest XHHHHHHH"}
	headerOKAuth :=func(username string, password string) *AuthHeader {
		header :=  &AuthHeader{}
		header.HeaderName = "Authorization"
		header.FormattedValue = "Basic " + base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s",
			username, password)))
		header.UserName = &username
		header.Password = &password
		return header
	}
	
	no_param_secret := func() *string {	return nil}
	no_param_id := func() *string {	return nil}
	NO_ERROR := ""
	param_secret := func(value string) *string {return &value}
	param_id := func(value string) *string {return &value}
	in_storage := true;
	not_in_storage := false;
	proceed_expected := true;
	proceed_not_expected := false;
	with_www_auth := true;
	no_www_auth := false;

	var tests = []struct {
		id                      int
		header           		*AuthHeader
		grant_type       		string
		param_client_id	     	*string
		param_client_secret    	*string
		clientIsInStorage		bool
		storedClientSecret		string
		storedAuthMethod		AuthMethod
		canProceed       		bool
		returnedError			string
		must_return_www_auth    bool
		
	}{
	{1, headerNoAuth, "password", param_id("123"), param_secret("secret"), in_storage,     "secret", CLIENT_SECRET_BASIC,  proceed_not_expected, E_INVALID_CLIENT, no_www_auth},
	{2, headerNoAuth, "password", param_id("123"), param_secret("secret"), in_storage,     "secret", CLIENT_SECRET_BASIC,   	proceed_not_expected, 	  E_INVALID_CLIENT, no_www_auth},
	{231,headerNoAuth,"password",  param_id("123"), param_secret("secret"), in_storage,     "secret", CLIENT_SECRET_POST,   	proceed_expected, 	   NO_ERROR, no_www_auth},
	{3, headerNoAuth, "password", param_id("123"), param_secret("secret"), not_in_storage, ""		, CLIENT_SECRET_BASIC,   	proceed_not_expected, E_INVALID_CLIENT, no_www_auth},
	{4, headerNoAuth, "password", param_id("123"), param_secret("xxxxxx"), in_storage,     "secret", CLIENT_SECRET_BASIC,   	proceed_not_expected, E_INVALID_CLIENT, no_www_auth},
	{5, headerNoAuth, "password", param_id("123"), param_secret(""), 		 in_storage,   "secret", CLIENT_SECRET_BASIC,   	proceed_not_expected, E_INVALID_CLIENT, no_www_auth},
	{6, headerNoAuth, "password", param_id("123"), param_secret(""), 		 in_storage,     ""		, CLIENT_SECRET_BASIC,   	proceed_not_expected, 	  E_INVALID_CLIENT, no_www_auth},
	{7, headerNoAuth, "password", param_id("123"), no_param_secret(), 	 in_storage,     "", 		  CLIENT_SECRET_BASIC,   	proceed_not_expected, 	  E_INVALID_CLIENT, no_www_auth},
	{8, headerNoAuth, "password", param_id("123"), no_param_secret(),      in_storage,     "secret", CLIENT_SECRET_BASIC,   	proceed_not_expected, E_INVALID_CLIENT, no_www_auth},
	{9, headerNoAuth, "password", no_param_id()  , param_secret("xxxxxx"), not_in_storage, "", 	      CLIENT_SECRET_BASIC,   	proceed_not_expected, E_INVALID_CLIENT, no_www_auth},
	{10,headerNoAuth, "password", no_param_id()  , no_param_secret(), 	 not_in_storage, "", 	      CLIENT_SECRET_BASIC,   	proceed_not_expected, E_INVALID_CLIENT, no_www_auth},
	{11,headerNoAuth, "password", param_id("noredirect"), param_secret("secret"), in_storage,     "secret", CLIENT_SECRET_BASIC,   	proceed_not_expected, 	  E_INVALID_CLIENT, no_www_auth},
	
	{12,headerNoAuth, "password", param_id("123"), no_param_secret(),      in_storage,     "", 		NONE	   ,  proceed_expected, 	  NO_ERROR, no_www_auth},
	{13,headerNoAuth, "password", param_id("123"), no_param_secret(),      in_storage,     "", 		NONE	   ,   	proceed_expected, 	  NO_ERROR, no_www_auth},
	{14,headerNoAuth, "password", param_id("123"), no_param_secret(),      not_in_storage, "", 		NONE	   ,   	proceed_not_expected, E_INVALID_CLIENT, no_www_auth},
	{15,headerNoAuth, "password", param_id("123"), param_secret("secret"), not_in_storage, "", 		NONE	   ,   	proceed_not_expected, E_INVALID_CLIENT, no_www_auth},
	{16,headerNoAuth, "password", param_id("123"), param_secret("xxxxxx"), in_storage,    "secret",NONE	   ,   	proceed_not_expected, E_INVALID_CLIENT, no_www_auth},
	{17,headerNoAuth, "password", no_param_id()  , param_secret("xxxxxx"), not_in_storage, "", 	    NONE	   ,   	proceed_not_expected, E_INVALID_CLIENT, no_www_auth},
	{18,headerNoAuth, "password", no_param_id()  , no_param_secret(), 	 not_in_storage, "", 	    NONE	   ,   	proceed_not_expected, E_INVALID_CLIENT, no_www_auth},
	{19,headerNoAuth, "password", param_id("123"), param_secret(""), 		 in_storage,     "", 	NONE	   ,   	proceed_expected, 	  NO_ERROR, no_www_auth},
	{20,headerNoAuth, "password", param_id("123"), param_secret(""), 		 in_storage,  "secret",NONE	   ,   	proceed_not_expected, E_INVALID_CLIENT, no_www_auth},
	{21,headerNoAuth, "password", param_id("123"), no_param_secret(), 	 in_storage,     "secret", NONE	   ,   	proceed_not_expected, E_INVALID_CLIENT, no_www_auth},
	{22,headerNoAuth, "password", param_id("noredirect"), no_param_secret(), in_storage,     "",   NONE      ,   	proceed_not_expected, E_INVALID_CLIENT, no_www_auth},
	
	{23,headerBadAuth, "password", param_id("123"), param_secret("secret"), in_storage,     "secret", CLIENT_SECRET_BASIC,  proceed_not_expected, E_INVALID_CLIENT, with_www_auth},
	{24,headerBadAuth, "password", param_id("123"), param_secret("secret"), in_storage,     "secret", CLIENT_SECRET_BASIC,   	proceed_not_expected, 	  E_INVALID_CLIENT, with_www_auth},
	{25,headerBadAuth, "password", param_id("123"), param_secret("secret"), not_in_storage, "", 	    CLIENT_SECRET_BASIC,   	proceed_not_expected, E_INVALID_CLIENT, with_www_auth},
	{26,headerBadAuth, "password", param_id("123"), param_secret("xxxxxx"), in_storage,     "secret", CLIENT_SECRET_BASIC,   	proceed_not_expected, E_INVALID_CLIENT, with_www_auth},
	{27,headerBadAuth, "password", param_id("123"), param_secret(""), 	  in_storage,     "secret", CLIENT_SECRET_BASIC,   	proceed_not_expected, E_INVALID_CLIENT, with_www_auth},
	{28,headerBadAuth, "password", param_id("123"), param_secret(""), 	  in_storage,     "", 		CLIENT_SECRET_BASIC,   	proceed_not_expected, 	  E_INVALID_CLIENT, with_www_auth},
	{29,headerBadAuth, "password", param_id("123"), no_param_secret(), 	  in_storage,     "", 		CLIENT_SECRET_BASIC,   	proceed_not_expected, 	  E_INVALID_CLIENT, with_www_auth},
	{30,headerBadAuth, "password", param_id("123"), no_param_secret(),      in_storage,     "secret", CLIENT_SECRET_BASIC,   	proceed_not_expected, E_INVALID_CLIENT, with_www_auth},
	{31,headerBadAuth, "password", no_param_id()  , param_secret("xxxxxx"), not_in_storage, "", 	    CLIENT_SECRET_BASIC,   	proceed_not_expected, E_INVALID_CLIENT, with_www_auth},
	{32,headerBadAuth, "password", no_param_id()  , no_param_secret(), 	  not_in_storage, "", 	    CLIENT_SECRET_BASIC,   	proceed_not_expected, E_INVALID_CLIENT, with_www_auth},
	
	{33,headerBadAuth, "password", param_id("123"), no_param_secret(),      in_storage,     "", 		NONE	   ,  proceed_expected, 	  NO_ERROR, no_www_auth},
	{34,headerBadAuth, "password", param_id("123"), no_param_secret(),      in_storage,     "", 		NONE	   ,   	proceed_expected, 	  NO_ERROR, no_www_auth},
	{35,headerBadAuth, "password", param_id("123"), no_param_secret(),      not_in_storage, "", 		NONE	   ,   	proceed_not_expected, E_INVALID_CLIENT, with_www_auth},
	{36,headerBadAuth, "password", param_id("123"), param_secret("secret"), not_in_storage, "", 		NONE	   ,   	proceed_not_expected, E_INVALID_CLIENT, with_www_auth},
	{37,headerBadAuth, "password", param_id("123"), param_secret("xxxxxx"), in_storage,     "secret", NONE	   ,   	proceed_not_expected, E_INVALID_CLIENT, with_www_auth},
	{38,headerBadAuth, "password", no_param_id()  , param_secret("xxxxxx"), not_in_storage, "", 	    NONE	   ,   	proceed_not_expected, E_INVALID_CLIENT, with_www_auth},
	{39,headerBadAuth, "password", no_param_id()  , no_param_secret(), 	  not_in_storage, "", 	    NONE	   ,   	proceed_not_expected, E_INVALID_CLIENT, with_www_auth},
	{40,headerBadAuth, "password", param_id("123"), param_secret(""), 	  in_storage,     "", 		NONE	   ,   	proceed_expected, 	  NO_ERROR, no_www_auth},
	{41,headerBadAuth, "password", param_id("123"), param_secret(""), 	  in_storage,     "secret", 	NONE	   ,   	proceed_not_expected, E_INVALID_CLIENT, with_www_auth},
	{42,headerBadAuth, "password", param_id("123"), no_param_secret(), 	  in_storage,     "secret", 	NONE	   ,   	proceed_not_expected, E_INVALID_CLIENT, with_www_auth},
	
	
	{43,headerOKAuth("456", "secret"), "password", no_param_id(), no_param_secret(), in_storage,     "secret", CLIENT_SECRET_BASIC,   proceed_expected, 	 NO_ERROR, no_www_auth},
	{44,headerOKAuth("456", "secret"), "password", no_param_id(), no_param_secret(), in_storage,     "secret", CLIENT_SECRET_BASIC,   	  proceed_expected, 	 NO_ERROR, no_www_auth},
	{440,headerOKAuth("456", "secret"), "password", no_param_id(), no_param_secret(), in_storage,     "secret", CLIENT_SECRET_POST,   	  proceed_not_expected, 	 E_INVALID_CLIENT, with_www_auth},
	{45,headerOKAuth("456", "secret"), "password", no_param_id(), no_param_secret(), not_in_storage, "", 	  CLIENT_SECRET_BASIC,   	  proceed_not_expected, E_INVALID_CLIENT, with_www_auth},
	{46,headerOKAuth("456", "xxxxxx"), "password", no_param_id(), no_param_secret(), in_storage, 		"secret", CLIENT_SECRET_BASIC,   	  proceed_not_expected, E_INVALID_CLIENT, with_www_auth},
	{47,headerOKAuth("456", ""),       "password", no_param_id(), no_param_secret(), in_storage, 		"secret", CLIENT_SECRET_BASIC,   	  proceed_not_expected, E_INVALID_CLIENT, with_www_auth},
	{48,headerOKAuth("456", ""),       "password", no_param_id(), no_param_secret(), in_storage, 		"", 	  CLIENT_SECRET_BASIC,   	  proceed_not_expected, 	E_INVALID_CLIENT, with_www_auth},
	{49,headerOKAuth("", "xxxxxx"),    "password", no_param_id(), no_param_secret(), not_in_storage,	"", 	  CLIENT_SECRET_BASIC,   	  proceed_not_expected, E_INVALID_CLIENT, with_www_auth},
	{50,headerOKAuth("", ""),    		 "password", no_param_id(), no_param_secret(), not_in_storage,	"", 	  CLIENT_SECRET_BASIC,   	  proceed_not_expected, E_INVALID_CLIENT, with_www_auth},
	
	{51,headerOKAuth("456", "secret"), "password", no_param_id(), no_param_secret(), in_storage,     "secret", NONE,  		 proceed_expected, 	 NO_ERROR, no_www_auth},
	{52,headerOKAuth("456", "secret"), "password", no_param_id(), no_param_secret(), in_storage,     "secret", NONE,  		 	  proceed_expected, 	 NO_ERROR, no_www_auth},
	{53,headerOKAuth("456", "secret"), "password", no_param_id(), no_param_secret(), not_in_storage, "", 	  NONE,  		 	  proceed_not_expected, E_INVALID_CLIENT, with_www_auth},
	{54,headerOKAuth("456", "xxxxxx"), "password", no_param_id(), no_param_secret(), in_storage, 		"secret", NONE,  		 	  proceed_not_expected, E_INVALID_CLIENT, with_www_auth},
	{55,headerOKAuth("456", ""),       "password", no_param_id(), no_param_secret(), in_storage, 		"secret", NONE,  		 	  proceed_not_expected, E_INVALID_CLIENT, with_www_auth},
	{56,headerOKAuth("456", ""),       "password", no_param_id(), no_param_secret(), in_storage, 		"", 	  NONE,  		 	  proceed_expected, 	NO_ERROR, no_www_auth},
	{57,headerOKAuth("", "xxxxxx"),    "password", no_param_id(), no_param_secret(), not_in_storage,	"", 	  NONE,  		 	  proceed_not_expected, E_INVALID_CLIENT, with_www_auth},
	{58,headerOKAuth("", ""),    		 "password", no_param_id(), no_param_secret(), not_in_storage,	"", 	  NONE,  		 	  proceed_not_expected, E_INVALID_CLIENT, with_www_auth},
	{59,headerOKAuth("noredirect", "secret"), "password", no_param_id(), no_param_secret(), in_storage, "secret",     NONE      ,   	proceed_not_expected, E_INVALID_CLIENT, with_www_auth},

	}

	for _, tt := range tests {
		
		var client_id *string
		
		if tt.header.UserName != nil {
			client_id = tt.header.UserName
		} else {
			client_id = tt.param_client_id
		}
		
		storage := &TestingStorage{
			clients:   make(map[string]Client),
			authorize: make(map[string]*AuthorizeData),
			access:    make(map[string]*AccessData),
			refresh:   make(map[string]string),
		}
		
		redirectUri := "http://localhost:14000/appauth"
		if client_id != nil {
		 if *client_id == "noredirect" { redirectUri = ""}
		} 
		if tt.clientIsInStorage && client_id != nil {
			storage.clients[*client_id] = &DefaultClient{
				Id:          *client_id,
				Secret:      tt.storedClientSecret,
				RedirectUri: redirectUri,
				AuthMethod: tt.storedAuthMethod,
			}
		}
		
		params := url.Values{}
    	params.Set("grant_type", tt.grant_type)
		if tt.param_client_id != nil { params.Set("client_id", *(tt.param_client_id)) }
		if tt.param_client_secret != nil { params.Set("client_secret", *(tt.param_client_secret)) }
		
		header := make(http.Header)
		header.Set(tt.header.HeaderName, tt.header.FormattedValue)
		
		
		r := makeRequest(header, params)
		r.ParseForm()
		result := authenticateClient(storage, r, tt.grant_type)
		if tt.canProceed != result.CanProceed {
			t.Errorf("Can proceed is wrong %v", tt)
		} else {
		
			if tt.canProceed == true {
				if result.InternalError != nil {
					t.Errorf("Expected internalError to be nil %v", tt)
				}
				if result.Client.GetId() != *client_id {
					t.Errorf("Expected ClientId to be match %v", tt)
				}
			}
		}
		
		if tt.returnedError != result.Error {
			t.Errorf("Expected error '%v' but was '%v',  %v", tt.returnedError, result.Error, tt)
		}
		
		if tt.must_return_www_auth != result.MustReturn401 {
			t.Errorf("Expected www-authenticate to be '%v' but was '%v',  %v", tt.must_return_www_auth, result.MustReturn401, tt)
		}
				
	}

}

func makeRequest(header http.Header, params url.Values) *http.Request {
	r, _ := http.NewRequest("POST", "/token", bytes.NewBufferString(params.Encode()))
    r.Header = header
    r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
    r.Header.Add("Content-Length", strconv.Itoa(len(params.Encode())))
	return r
}