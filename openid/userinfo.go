package openid

import (
	"github.com/RangelReale/osin"
	"net/http"
)

// UserInfoRequest is a request for information about some AccessData
type UserInfoRequest struct {
	Schema     string           // Schema (openid)
	Code       string           // Code to look up
	AccessData *osin.AccessData // AccessData associated with Code
}

// UserInfoOutput allows processing the Response object before finishing
type UserInfoOutput interface {
	ProcessOutput(w *osin.Response, r *http.Request, ir *UserInfoRequest)
}

// HandleInfoRequest is an http.HandlerFunc for server information
// NOT an RFC specification.
func (s *Server) HandleUserInfoRequest(w *osin.Response, r *http.Request) *UserInfoRequest {
	r.ParseForm()

	// generate info request
	ret := &UserInfoRequest{
		//Code: r.Form.Get("code"),
		Schema: r.Form.Get("schema"),
	}

	if ret.Schema != "openid" {
		w.SetError(osin.E_INVALID_REQUEST, "") // E_INVALID_SCHEMA
		return nil
	}

	if ret.Code == "" {
		w.SetError(osin.E_INVALID_REQUEST, "")
		return nil
	}

	var err error

	// load access data
	ret.AccessData, err = s.OsinServer.Storage.LoadAccess(ret.Code)
	if err != nil {
		w.SetError(osin.E_INVALID_REQUEST, "")
		w.InternalError = err
		return nil
	}
	if ret.AccessData.Client == nil {
		w.SetError(osin.E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.AccessData.Client.RedirectUri == "" {
		w.SetError(osin.E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.AccessData.IsExpired() {
		w.SetError(osin.E_INVALID_GRANT, "")
		return nil
	}

	return ret
}

// FinishInfoRequest finalizes the request handled by HandleInfoRequest
func (s *Server) FinishUserInfoRequest(w *osin.Response, r *http.Request, ir *UserInfoRequest) {
	// don't process if is already an error
	if w.IsError {
		return
	}

	// output data
	/*
		w.Output["client_id"] = ir.AccessData.Client.Id
		w.Output["access_token"] = ir.AccessData.AccessToken
		w.Output["token_type"] = s.Config.TokenType
		w.Output["expires_in"] = ir.AccessData.CreatedAt.Add(time.Duration(ir.AccessData.ExpiresIn)*time.Second).Sub(time.Now()) / time.Second
		if ir.AccessData.RefreshToken != "" {
			w.Output["refresh_token"] = ir.AccessData.RefreshToken
		}
		if ir.AccessData.Scope != "" {
			w.Output["scope"] = ir.AccessData.Scope
		}

		if s.InfoOutput != nil {
			s.InfoOutput.ProcessOutput(w, r, ir)
		}
	*/
}
