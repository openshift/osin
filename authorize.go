package osin

import (
	"net/http"
	"time"
)

type AuthorizeRequestType string

const (
	CODE  AuthorizeRequestType = "code"
	TOKEN                      = "token"
)

// Authorize request information
type AuthorizeRequest struct {
	Type        AuthorizeRequestType
	Client      *Client
	Scope       string
	RedirectUri string
	State       string

	Authorized bool
	UserData   interface{}
}

// Authorization data
type AuthorizeData struct {
	Client      *Client
	Code        string
	ExpiresIn   int32
	Scope       string
	RedirectUri string
	State       string
	CreatedAt   time.Time
	UserData    interface{}
}

func (d *AuthorizeData) IsExpired() bool {
	return d.CreatedAt.Add(time.Duration(d.ExpiresIn) * time.Second).Before(time.Now())
}

// Authorization token generator interface
type AuthorizeTokenGen interface {
	GenerateAuthorizeToken(data *AuthorizeData) (string, error)
}

// Default authorization token generator
type AuthorizeTokenGenDefault struct {
	TokenGen TokenGen
}

func (a *AuthorizeTokenGenDefault) GenerateAuthorizeToken(data *AuthorizeData) (ret string, err error) {
	ret, err = a.TokenGen.GenerateToken()
	return
}

// Authorize request
func (s *Server) HandleAuthorizeRequest(w *Response, r *http.Request) *AuthorizeRequest {
	r.ParseForm()

	requestType := AuthorizeRequestType(r.Form.Get("response_type"))
	if s.Config.AllowedAuthorizeTypes.Exists(requestType) {
		switch requestType {
		case CODE:
			return s.handleAuthorizeRequestCode(w, r)
		case TOKEN:
			return s.handleAuthorizeRequestToken(w, r)
		}
	}

	w.SetError(E_UNSUPPORTED_RESPONSE_TYPE, "")
	return nil
}

func (s *Server) handleAuthorizeRequestCode(w *Response, r *http.Request) *AuthorizeRequest {
	// create the authorization request
	ret := &AuthorizeRequest{
		Type:        CODE,
		State:       r.Form.Get("state"),
		Scope:       r.Form.Get("scope"),
		RedirectUri: r.Form.Get("redirect_uri"),
		Authorized:  false,
	}

	var err error

	// must have a valid client
	ret.Client, err = s.Storage.GetClient(r.Form.Get("client_id"))
	if err != nil {
		w.SetErrorState(E_SERVER_ERROR, "", ret.State)
		w.InternalError = err
		return nil
	}
	if ret.Client == nil {
		w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
		return nil
	}
	if ret.Client.RedirectUri == "" {
		w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
		return nil
	}

	// force redirect response to client redirecturl first
	w.SetRedirect(ret.Client.RedirectUri)

	// check redirect uri
	if ret.RedirectUri == "" {
		ret.RedirectUri = ret.Client.RedirectUri
	}
	if err = ValidateUri(ret.Client.RedirectUri, ret.RedirectUri); err != nil {
		w.SetErrorState(E_INVALID_REQUEST, "", ret.State)
		w.InternalError = err
		return nil
	}

	return ret
}

func (s *Server) handleAuthorizeRequestToken(w *Response, r *http.Request) *AuthorizeRequest {
	// create the authorization request
	ret := &AuthorizeRequest{
		Type:        TOKEN,
		State:       r.Form.Get("state"),
		Scope:       r.Form.Get("scope"),
		RedirectUri: r.Form.Get("redirect_uri"),
		Authorized:  false,
	}

	var err error

	// must have a valid client
	ret.Client, err = s.Storage.GetClient(r.Form.Get("client_id"))
	if err != nil {
		w.SetErrorState(E_SERVER_ERROR, "", ret.State)
		w.InternalError = err
		return nil
	}
	if ret.Client == nil {
		w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
		return nil
	}
	if ret.Client.RedirectUri == "" {
		w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
		return nil
	}

	// force redirect response to client redirecturl first
	w.SetRedirect(ret.Client.RedirectUri)

	// check redirect uri
	if ret.RedirectUri == "" {
		ret.RedirectUri = ret.Client.RedirectUri
	}
	if err = ValidateUri(ret.Client.RedirectUri, ret.RedirectUri); err != nil {
		w.SetErrorState(E_INVALID_REQUEST, "", ret.State)
		w.InternalError = err
		return nil
	}

	return ret
}

func (s *Server) FinishAuthorizeRequest(w *Response, r *http.Request, ar *AuthorizeRequest) {
	// force redirect response
	w.SetRedirect(ar.RedirectUri)

	if ar.Authorized {
		if ar.Type == TOKEN {
			w.SetRedirectFragment(true)

			// generate token directly
			ret := &AccessRequest{
				Type:            IMPLICIT,
				Code:            "",
				Client:          ar.Client,
				RedirectUri:     ar.RedirectUri,
				Scope:           ar.Scope,
				GenerateRefresh: false,
				Authorized:      true,
				UserData:        ar.UserData,
			}

			s.FinishAccessRequest(w, r, ret)
		} else {
			// generate authorization token
			ret := &AuthorizeData{
				Client:      ar.Client,
				CreatedAt:   time.Now(),
				ExpiresIn:   s.Config.AuthorizationExpiration,
				RedirectUri: ar.RedirectUri,
				State:       ar.State,
				Scope:       ar.Scope,
				UserData:    ar.UserData,
			}

			// generate token code
			code, err := s.AuthorizeTokenGen.GenerateAuthorizeToken(ret)
			if err != nil {
				w.SetErrorState(E_SERVER_ERROR, "", ar.State)
				w.InternalError = err
				return
			}
			ret.Code = code

			// save authorization token
			if err = s.Storage.SaveAuthorize(ret); err != nil {
				w.SetErrorState(E_SERVER_ERROR, "", ar.State)
				w.InternalError = err
				return
			}

			// redirect with code
			w.Output["code"] = ret.Code
			w.Output["state"] = ret.State
		}
	} else {
		// redirect with error
		w.SetErrorState(E_ACCESS_DENIED, "", ar.State)
	}
}
