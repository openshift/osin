package osin

import (
	"net/http"
	"time"
)

// AccessRequestType is the type for OAuth param `grant_type`
type AccessRequestType string

const (
	AUTHORIZATION_CODE AccessRequestType = "authorization_code"
	REFRESH_TOKEN                        = "refresh_token"
	PASSWORD                             = "password"
	CLIENT_CREDENTIALS                   = "client_credentials"
	IMPLICIT                             = "__implicit"
)

// AccessRequest is a request for access tokens
type AccessRequest struct {
	Type          AccessRequestType
	Code          string
	Client        *Client
	AuthorizeData *AuthorizeData
	AccessData    *AccessData
	RedirectUri   string
	Scope         string
	Username      string
	Password      string

	// Set if request is authorized
	Authorized bool

	// Token expiration in seconds. Change if different from default
	Expiration int32

	// Set if a refresh token should be generated
	GenerateRefresh bool

	// Data to be passed to storage. Not used by the library.
	UserData interface{}
}

// AccessData represents an access grant (tokens, expiration, client, etc)
type AccessData struct {
	// Client information
	Client *Client

	// Authorize data, for authorization code
	AuthorizeData *AuthorizeData

	// Previous access data, for refresh token
	AccessData *AccessData

	// Access token
	AccessToken string

	// Refresh Token. Can be blank
	RefreshToken string

	// Token expiration in seconds
	ExpiresIn int32

	// Requested scope
	Scope string

	// Redirect Uri from request
	RedirectUri string

	// Date created
	CreatedAt time.Time

	// Data to be passed to storage. Not used by the library.
	UserData interface{}
}

// IsExpired returns true if access expired
func (d *AccessData) IsExpired() bool {
	return d.CreatedAt.Add(time.Duration(d.ExpiresIn) * time.Second).Before(time.Now())
}

// ExpireAt returns the expiration date
func (d *AccessData) ExpireAt() time.Time {
	return d.CreatedAt.Add(time.Duration(d.ExpiresIn) * time.Second)
}

// AccessTokenGen generates access tokens
type AccessTokenGen interface {
	GenerateAccessToken(data *AccessData, generaterefresh bool) (accesstoken string, refreshtoken string, err error)
}

// HandleAccessRequest is the http.HandlerFunc for handling access token requests
func (s *Server) HandleAccessRequest(w *Response, r *http.Request) *AccessRequest {
	// Only allow GET or POST
	if r.Method == "GET" {
		if !s.Config.AllowGetAccessRequest {
			w.SetError(E_INVALID_REQUEST, "")
			return nil
		}
	} else if r.Method != "POST" {
		w.SetError(E_INVALID_REQUEST, "")
		return nil
	}

	err := r.ParseForm()
	if err != nil {
		w.SetError(E_INVALID_REQUEST, "")
		return nil
	}

	grantType := AccessRequestType(r.Form.Get("grant_type"))
	if s.Config.AllowedAccessTypes.Exists(grantType) {
		switch grantType {
		case AUTHORIZATION_CODE:
			return s.handleAuthorizationCodeRequest(w, r)
		case REFRESH_TOKEN:
			return s.handleRefreshTokenRequest(w, r)
		case PASSWORD:
			return s.handlePasswordRequest(w, r)
		case CLIENT_CREDENTIALS:
			return s.handleClientCredentialsRequest(w, r)
		}
	}

	w.SetError(E_UNSUPPORTED_GRANT_TYPE, "")
	return nil
}

func (s *Server) handleAuthorizationCodeRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            AUTHORIZATION_CODE,
		Code:            r.Form.Get("code"),
		RedirectUri:     r.Form.Get("redirect_uri"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
	}

	// "code" is required
	if ret.Code == "" {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	// must have a valid client
	if ret.Client = getClient(auth, s.Storage, w, r); ret.Client == nil {
		return nil
	}

	// must be a valid authorization code
	var err error
	ret.AuthorizeData, err = s.Storage.LoadAuthorize(ret.Code, r)
	if err != nil {
		w.SetError(E_INVALID_GRANT, "")
		w.InternalError = err
		return nil
	}
	if ret.AuthorizeData.Client == nil {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.AuthorizeData.Client.RedirectUri == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.AuthorizeData.IsExpired() {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	// code must be from the client
	if ret.AuthorizeData.Client.Id != ret.Client.Id {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	// check redirect uri
	if ret.RedirectUri == "" {
		ret.RedirectUri = ret.Client.RedirectUri
	}
	if err = ValidateUri(ret.Client.RedirectUri, ret.RedirectUri); err != nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = err
		return nil
	}
	if ret.AuthorizeData.RedirectUri != ret.RedirectUri {
		w.SetError(E_INVALID_REQUEST, "")
		return nil
	}

	// set rest of data
	ret.Scope = ret.AuthorizeData.Scope
	ret.UserData = ret.AuthorizeData.UserData

	return ret
}

func (s *Server) handleRefreshTokenRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            REFRESH_TOKEN,
		Code:            r.Form.Get("refresh_token"),
		Scope:           r.Form.Get("scope"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
	}

	// "refresh_token" is required
	if ret.Code == "" {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	// must have a valid client
	if ret.Client = getClient(auth, s.Storage, w, r); ret.Client == nil {
		return nil
	}

	// must be a valid refresh code
	var err error
	ret.AccessData, err = s.Storage.LoadRefresh(ret.Code, r)
	if err != nil {
		w.SetError(E_INVALID_GRANT, "")
		w.InternalError = err
		return nil
	}
	if ret.AccessData.Client == nil {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.AccessData.Client.RedirectUri == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}

	// client must be the same as the previous token
	if ret.AccessData.Client.Id != ret.Client.Id {
		w.SetError(E_INVALID_CLIENT, "")
		return nil

	}

	// set rest of data
	ret.RedirectUri = ret.AccessData.RedirectUri
	ret.UserData = ret.AccessData.UserData
	if ret.Scope == "" {
		ret.Scope = ret.AccessData.Scope
	}

	return ret
}

func (s *Server) handlePasswordRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            PASSWORD,
		Username:        r.Form.Get("username"),
		Password:        r.Form.Get("password"),
		Scope:           r.Form.Get("scope"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
	}

	// "username" and "password" is required
	if ret.Username == "" || ret.Password == "" {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	// must have a valid client
	if ret.Client = getClient(auth, s.Storage, w, r); ret.Client == nil {
		return nil
	}

	// set redirect uri
	ret.RedirectUri = ret.Client.RedirectUri

	return ret
}

func (s *Server) handleClientCredentialsRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            CLIENT_CREDENTIALS,
		Scope:           r.Form.Get("scope"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
	}

	// must have a valid client
	if ret.Client = getClient(auth, s.Storage, w, r); ret.Client == nil {
		return nil
	}

	// set redirect uri
	ret.RedirectUri = ret.Client.RedirectUri

	return ret
}

func (s *Server) FinishAccessRequest(w *Response, r *http.Request, ar *AccessRequest) {
	// don't process if is already an error
	if w.IsError {
		return
	}
	redirectUri := r.Form.Get("redirect_uri")
	// Get redirect uri from AccessRequest if it's there (e.g., refresh token request)
	if ar.RedirectUri != "" {
		redirectUri = ar.RedirectUri
	}
	if ar.Authorized {
		// generate access token
		ret := &AccessData{
			Client:        ar.Client,
			AuthorizeData: ar.AuthorizeData,
			AccessData:    ar.AccessData,
			RedirectUri:   redirectUri,
			CreatedAt:     time.Now(),
			ExpiresIn:     ar.Expiration,
			UserData:      ar.UserData,
			Scope:         ar.Scope,
		}

		var err error

		// generate access token
		ret.AccessToken, ret.RefreshToken, err = s.AccessTokenGen.GenerateAccessToken(ret, ar.GenerateRefresh)
		if err != nil {
			w.SetError(E_SERVER_ERROR, "")
			w.InternalError = err
			return
		}

		// save access token
		if err = s.Storage.SaveAccess(ret, r); err != nil {
			w.SetError(E_SERVER_ERROR, "")
			w.InternalError = err
			return
		}

		// remove authorization token
		if ret.AuthorizeData != nil {
			s.Storage.RemoveAuthorize(ret.AuthorizeData.Code, r)
		}

		// remove previous access token
		if ret.AccessData != nil {
			if ret.AccessData.RefreshToken != "" {
				s.Storage.RemoveRefresh(ret.AccessData.RefreshToken, r)
			}
			s.Storage.RemoveAccess(ret.AccessData.AccessToken, r)
		}

		// output data
		w.Output["access_token"] = ret.AccessToken
		w.Output["token_type"] = s.Config.TokenType
		w.Output["expires_in"] = ret.ExpiresIn
		if ret.RefreshToken != "" {
			w.Output["refresh_token"] = ret.RefreshToken
		}
		if ar.Scope != "" {
			w.Output["scope"] = ar.Scope
		}
	} else {
		w.SetError(E_ACCESS_DENIED, "")
	}
}

// Helper Functions

// getClient looks up and authenticates the basic auth using the given
// storage. Sets an error on the response if auth fails or a server error occurs.
func getClient(auth *BasicAuth, storage Storage, w *Response, r *http.Request) *Client {
	client, err := storage.GetClient(auth.Username, r)
	if err != nil {
		w.SetError(E_SERVER_ERROR, "")
		w.InternalError = err
		return nil
	}
	if client == nil {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if client.Secret != auth.Password {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if client.RedirectUri == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	return client
}
