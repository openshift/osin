package osin

import (
	"net/http"
	"time"
)

// Info request information
type InfoRequest struct {
	Code       string
	AccessData *AccessData
}

// Information request.
// NOT an RFC specification.
func (s *Server) HandleInfoRequest(w *Response, r *http.Request) *InfoRequest {
	r.ParseForm()

	// generate info request
	ret := &InfoRequest{
		Code: r.Form.Get("code"),
	}

	if ret.Code == "" {
		w.SetError(E_INVALID_REQUEST, "")
		return nil
	}

	var err error

	// load access data
	ret.AccessData, err = s.Storage.LoadAccess(ret.Code)
	if err != nil {
		w.SetError(E_INVALID_REQUEST, "")
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
	if ret.AccessData.IsExpired() {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	return ret
}

func (s *Server) FinishInfoRequest(w *Response, r *http.Request, ir *InfoRequest) {
	// don't process if is already an error
	if w.IsError {
		return
	}

	// output data
	w.Output["access_token"] = ir.AccessData.AccessToken
	w.Output["token_type"] = s.Config.TokenType
	w.Output["expires_in"] = ir.AccessData.CreatedAt.Add(time.Duration(ir.AccessData.ExpiresIn)*time.Second).Sub(time.Now()) / time.Second
	if ir.AccessData.RefreshToken != "" {
		w.Output["refresh_token"] = ir.AccessData.RefreshToken
	}
	if ir.AccessData.Scope != "" {
		w.Output["scope"] = ir.AccessData.Scope
	}
}
