package osin

import (
	"net/http"
        "strings"
	"time"
)

// InfoRequest is a request for information about some AccessData
type InfoRequest struct {
	Code       string      // Code to look up
	AccessData *AccessData // AccessData associated with Code
}

// HandleInfoRequest is an http.HandlerFunc for server information
// NOT an RFC specification.
func (s *Server) HandleInfoRequest(w *Response, r *http.Request) *InfoRequest {
	r.ParseForm()

        c := r.Form.Get("code")
        if c == "" {
            token := r.Header.Get("Authorization")
            t := strings.Split(token, " ")
            if t[0] == "Bearer" && len(t) == 2 {
                c = t[1]
            }
        }

	// generate info request
	ret := &InfoRequest{
		Code: c,
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

// FinishInfoRequest finalizes the request handled by HandleInfoRequest
func (s *Server) FinishInfoRequest(w *Response, r *http.Request, ir *InfoRequest) {
	// don't process if is already an error
	if w.IsError {
		return
	}

	// output data
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
}
