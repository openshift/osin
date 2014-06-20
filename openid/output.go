// OpenID specification: http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-21
package openid

import (
	"github.com/RangelReale/jwt"
	"github.com/RangelReale/osin"
	"net/http"
)

func (s *Server) ProcessAccessOutput(w *osin.Response, r *http.Request, ar *osin.AccessRequest, ad *osin.AccessData) {
	// generate JWT id_token
	token := jwt.New(jwt.GetSigningMethod(s.SigningMethod))
	token.Claims["iss"] = s.IssuerIdentifier
	//token.Claims["sub"] = ??
	token.Claims["exp"] = ad.ExpiresIn
	token.Claims["aud"] = ad.Client.Id
	token.Claims["iat"] = ad.CreatedAt.Unix()

	id_token, err := token.SignedString(s.PrivateKey)
	if err != nil {
		w.SetError(osin.E_SERVER_ERROR, "")
		w.InternalError = err
		return
	}

	w.Output["id_token"] = id_token
}
