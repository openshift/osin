package osin

import (
	"net/http"
	"time"
)

// Information request.
// NOT an RFC specification.
func (s *Server) HandleInfoRequest(w *Response, r *http.Request) bool {
	r.ParseForm()

	code := r.Form.Get("code")
	if code == "" {
		w.SetError(E_INVALID_REQUEST, "")
		return false
	}

	ad, err := s.Storage.LoadAccess(code)
	if err != nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = err
		return false
	}
	if ad.Client == nil {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return false
	}
	if ad.Client.RedirectUri == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return false
	}
	if ad.IsExpired() {
		w.SetError(E_INVALID_GRANT, "")
		return false
	}

	// output data
	w.Output["access_token"] = ad.AccessToken
	w.Output["token_type"] = s.Config.TokenType
	w.Output["expires_in"] = ad.CreatedAt.Add(time.Duration(ad.ExpiresIn)*time.Second).Sub(time.Now()) / time.Second
	if ad.RefreshToken != "" {
		w.Output["refresh_token"] = ad.RefreshToken
	}
	if ad.Scope != "" {
		w.Output["scope"] = ad.Scope
	}

	return true
}
