package osin

import (
	"errors"
	"net/http"
	"time"
)

type AccessRequestType string

const (
	AUTHORIZATION_CODE AccessRequestType = "authorization_code"
	REFRESH_TOKEN                        = "refresh_token"
	PASSWORD                             = "password"
	CLIENT_CREDENTIALS                   = "client_credentials"
	IMPLICIT                             = "__implicit"
)

// Access request information
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

// Access data
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

// Returns true if access expired
func (d *AccessData) IsExpired() bool {
	return d.CreatedAt.Add(time.Duration(d.ExpiresIn) * time.Second).Before(time.Now())
}

// Returns the expiration date
func (d *AccessData) ExpireAt() time.Time {
	return d.CreatedAt.Add(time.Duration(d.ExpiresIn) * time.Second)
}

// Access token generator interface
type AccessTokenGen interface {
	GenerateAccessToken(data *AccessData, generaterefresh bool) (accesstoken string, refreshtoken string, err error)
}

// Access token request
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

	r.ParseForm()

	grantType := AccessRequestType(r.Form.Get("grant_type"))
	if s.Config.AllowedAccessTypes.Exists(grantType) {
		switch grantType {
		case AUTHORIZATION_CODE:
			return s.handleAccessRequestAuthorizationCode(w, r)
		case REFRESH_TOKEN:
			return s.handleAccessRequestRefreshToken(w, r)
		case PASSWORD:
			return s.handleAccessRequestPassword(w, r)
		case CLIENT_CREDENTIALS:
			return s.handleAccessRequestClientCredentials(w, r)
		}
	}

	w.SetError(E_UNSUPPORTED_GRANT_TYPE, "")
	return nil
}

func (s *Server) handleAccessRequestAuthorizationCode(w *Response, r *http.Request) *AccessRequest {
	// get client information from basic authentication
	auth, err := CheckClientAuth(r, s.Config.AllowClientSecretInParams)
	if err != nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = err
		return nil
	}
	if auth == nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = errors.New("Client authentication not sent")
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
	ret.Client, err = s.Storage.GetClient(auth.Username)
	if err != nil {
		w.SetError(E_SERVER_ERROR, "")
		w.InternalError = err
		return nil
	}
	if ret.Client == nil {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.Client.Secret != auth.Password {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.Client.RedirectUri == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}

	// must be a valid authorization code
	ret.AuthorizeData, err = s.Storage.LoadAuthorize(ret.Code)
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

	return ret
}

func (s *Server) handleAccessRequestRefreshToken(w *Response, r *http.Request) *AccessRequest {
	// get client information from basic authentication
	auth, err := CheckClientAuth(r, s.Config.AllowClientSecretInParams)
	if err != nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = err
		return nil
	}
	if auth == nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = errors.New("Client authentication not sent")
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
	ret.Client, err = s.Storage.GetClient(auth.Username)
	if err != nil {
		w.SetError(E_SERVER_ERROR, "")
		w.InternalError = err
		return nil
	}
	if ret.Client == nil {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.Client.Secret != auth.Password {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.Client.RedirectUri == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}

	// must be a valid refresh code
	ret.AccessData, err = s.Storage.LoadRefresh(ret.Code)
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

	// client must be the safe as the previous token
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

func (s *Server) handleAccessRequestPassword(w *Response, r *http.Request) *AccessRequest {
	// get client information from basic authentication
	auth, err := CheckClientAuth(r, s.Config.AllowClientSecretInParams)
	if err != nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = err
		return nil
	}
	if auth == nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = errors.New("Client authentication not sent")
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
	ret.Client, err = s.Storage.GetClient(auth.Username)
	if err != nil {
		w.SetError(E_SERVER_ERROR, "")
		w.InternalError = err
		return nil
	}
	if ret.Client == nil {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.Client.Secret != auth.Password {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.Client.RedirectUri == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}

	// set redirect uri
	ret.RedirectUri = ret.Client.RedirectUri

	// set rest of data

	return ret
}

func (s *Server) handleAccessRequestClientCredentials(w *Response, r *http.Request) *AccessRequest {
	// get client information from basic authentication
	auth, err := CheckClientAuth(r, s.Config.AllowClientSecretInParams)
	if err != nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = err
		return nil
	}
	if auth == nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = errors.New("Client authentication not sent")
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
	ret.Client, err = s.Storage.GetClient(auth.Username)
	if err != nil {
		w.SetError(E_SERVER_ERROR, "")
		w.InternalError = err
		return nil
	}
	if ret.Client == nil {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.Client.Secret != auth.Password {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.Client.RedirectUri == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}

	// set redirect uri
	ret.RedirectUri = ret.Client.RedirectUri

	// set rest of data

	return ret
}

func (s *Server) FinishAccessRequest(w *Response, r *http.Request, ar *AccessRequest) {
	// don't process if is already an error
	if w.IsError {
		return
	}

	if ar.Authorized {
		// generate access token
		ret := &AccessData{
			Client:        ar.Client,
			AuthorizeData: ar.AuthorizeData,
			AccessData:    ar.AccessData,
			RedirectUri:   r.Form.Get("redirect_uri"),
			CreatedAt:     time.Now(),
			ExpiresIn:     ar.Expiration,
			UserData:      ar.UserData,
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
		if err = s.Storage.SaveAccess(ret); err != nil {
			w.SetError(E_SERVER_ERROR, "")
			w.InternalError = err
			return
		}

		// remove authorization token
		if ret.AuthorizeData != nil {
			s.Storage.RemoveAuthorize(ret.AuthorizeData.Code)
		}

		// remove previous access token
		if ret.AccessData != nil {
			if ret.AccessData.RefreshToken != "" {
				s.Storage.RemoveRefresh(ret.AccessData.RefreshToken)
			}
			s.Storage.RemoveAccess(ret.AccessData.AccessToken)
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
