package osin

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2"
)

// AuthorizeRequestType is the type for OAuth param `response_type`
type AuthorizeRequestType string

const (
	CODE     AuthorizeRequestType = "code"
	TOKEN    AuthorizeRequestType = "token"
	ID_TOKEN AuthorizeRequestType = "id_token"

	PKCE_PLAIN = "plain"
	PKCE_S256  = "S256"
)

var (
	pkceMatcher = regexp.MustCompile("^[a-zA-Z0-9~._-]{43,128}$")
)

// Authorize request information
type AuthorizeRequest struct {
	Type        string
	Client      Client
	Scope       string
	RedirectUri string
	State       string

	// Set if request is authorized
	Authorized bool

	// Token expiration in seconds. Change if different from default.
	// If type = TOKEN, this expiration will be for the ACCESS token.
	Expiration int32

	// Data to be passed to storage. Not used by the library.
	UserData interface{}

	// HttpRequest *http.Request for special use
	HttpRequest *http.Request

	// Optional code_challenge as described in rfc7636
	CodeChallenge string
	// Optional code_challenge_method as described in rfc7636
	CodeChallengeMethod string
}

// Authorization data
type AuthorizeData struct {
	// Client information
	Client Client

	// Authorization code
	Code string

	// Token expiration in seconds
	ExpiresIn int32

	// Requested scope
	Scope string

	// Redirect Uri from request
	RedirectUri string

	// State data from request
	State string

	// Date created
	CreatedAt time.Time

	// Data to be passed to storage. Not used by the library.
	UserData interface{}

	// Optional code_challenge as described in rfc7636
	CodeChallenge string
	// Optional code_challenge_method as described in rfc7636
	CodeChallengeMethod string
}

// IsExpired is true if authorization expired
func (d *AuthorizeData) IsExpired() bool {
	return d.IsExpiredAt(time.Now())
}

// IsExpired is true if authorization expires at time 't'
func (d *AuthorizeData) IsExpiredAt(t time.Time) bool {
	return d.ExpireAt().Before(t)
}

// ExpireAt returns the expiration date
func (d *AuthorizeData) ExpireAt() time.Time {
	return d.CreatedAt.Add(time.Duration(d.ExpiresIn) * time.Second)
}

// AuthorizeTokenGen is the token generator interface
type AuthorizeTokenGen interface {
	GenerateAuthorizeToken(data *AuthorizeData) (string, error)
}

// HandleAuthorizeRequest is the main http.HandlerFunc for handling
// authorization requests
func (s *Server) HandleAuthorizeRequest(w *Response, r *http.Request) *AuthorizeRequest {
	r.ParseForm()

	// create the authorization request
	unescapedUri, err := url.QueryUnescape(r.FormValue("redirect_uri"))
	if err != nil {
		w.SetErrorState(E_INVALID_REQUEST, "", "")
		w.InternalError = err
		return nil
	}

	ret := &AuthorizeRequest{
		Type:        r.FormValue("response_type"),
		State:       r.FormValue("state"),
		Scope:       r.FormValue("scope"),
		RedirectUri: unescapedUri,
		Authorized:  false,
		HttpRequest: r,
	}

	// must have a valid client
	ret.Client, err = w.Storage.GetClient(r.FormValue("client_id"))
	if err == ErrNotFound {
		w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
		return nil
	}
	if err != nil {
		w.SetErrorState(E_SERVER_ERROR, "", ret.State)
		w.InternalError = err
		return nil
	}
	if ret.Client == nil {
		w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
		return nil
	}
	if ret.Client.GetRedirectUri() == "" {
		w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
		return nil
	}

	// check redirect uri, if there are multiple client redirect uri's
	// don't set the uri
	if ret.RedirectUri == "" && FirstUri(ret.Client.GetRedirectUri(), s.Config.RedirectUriSeparator) == ret.Client.GetRedirectUri() {
		ret.RedirectUri = FirstUri(ret.Client.GetRedirectUri(), s.Config.RedirectUriSeparator)
	}

	if realRedirectUri, err := ValidateUriList(ret.Client.GetRedirectUri(), ret.RedirectUri, s.Config.RedirectUriSeparator); err != nil {
		w.SetErrorState(E_INVALID_REQUEST, "", ret.State)
		w.InternalError = err
		return nil
	} else {
		ret.RedirectUri = realRedirectUri
	}

	w.SetRedirect(ret.RedirectUri)

	// recognize openid connect
	openIDScope := false
	for _, scope := range strings.Fields(ret.Scope) {
		if scope == "openid" {
			openIDScope = true
			break
		}
	}
	if ret.Type == "" {
		w.SetErrorState(E_INVALID_REQUEST, "no response_type provided", ret.State)
		return nil
	}
	var code, token, idToken bool
	for _, str := range strings.Fields(ret.Type) {
		requestType := AuthorizeRequestType(str)
		// custom setting supported authorize types
		if !s.Config.AllowedAuthorizeTypes.Exists(requestType) {
			w.SetErrorState(E_UNSUPPORTED_RESPONSE_TYPE, "", ret.State)
			return nil
		}

		switch requestType {
		case CODE:
			code = true
		case TOKEN:
			token = true
		case ID_TOKEN:
			idToken = true
		}
	}
	// openid connect flow
	if openIDScope {
		// "token" can't be provided by its own.
		//
		// https://openid.net/specs/openid-connect-core-1_0.html#Authentication
		if token && !code && !idToken {
			w.SetErrorState(E_INVALID_REQUEST, "response type 'token' must be provided with type 'id_token' and/or 'code'", ret.State)
			return nil
		}
		// Either "id_token token" or "id_token" has been provided which implies the
		// implicit flow. Implicit flow requires a nonce value.
		//
		// https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest
		if !code && r.FormValue("nonce") == "" {
			w.SetErrorState(E_INVALID_REQUEST, "response type 'token' requires a 'nonce value'", ret.State)
			return nil
		}
	}
	if code {
		ret.Expiration = s.Config.AuthorizationExpiration

		// Optional PKCE support (https://tools.ietf.org/html/rfc7636)
		if codeChallenge := r.FormValue("code_challenge"); len(codeChallenge) == 0 {
			if s.Config.RequirePKCEForPublicClients && CheckClientSecret(ret.Client, "") {
				// https://tools.ietf.org/html/rfc7636#section-4.4.1
				w.SetErrorState(E_INVALID_REQUEST, "code_challenge (rfc7636) required for public clients", ret.State)
				return nil
			}
		} else {
			codeChallengeMethod := r.FormValue("code_challenge_method")
			// allowed values are "plain" (default) and "S256", per https://tools.ietf.org/html/rfc7636#section-4.3
			if len(codeChallengeMethod) == 0 {
				codeChallengeMethod = PKCE_PLAIN
			}
			if codeChallengeMethod != PKCE_PLAIN && codeChallengeMethod != PKCE_S256 {
				// https://tools.ietf.org/html/rfc7636#section-4.4.1
				w.SetErrorState(E_INVALID_REQUEST, "code_challenge_method transform algorithm not supported (rfc7636)", ret.State)
				return nil
			}

			// https://tools.ietf.org/html/rfc7636#section-4.2
			if matched := pkceMatcher.MatchString(codeChallenge); !matched {
				w.SetErrorState(E_INVALID_REQUEST, "code_challenge invalid (rfc7636)", ret.State)
				return nil
			}

			ret.CodeChallenge = codeChallenge
			ret.CodeChallengeMethod = codeChallengeMethod
		}
	}
	if token || idToken {
		ret.Expiration = s.Config.AccessExpiration
	}
	return ret
}

func (s *Server) FinishAuthorizeRequest(w *Response, r *http.Request, ar *AuthorizeRequest) {
	// don't process if is already an error
	if w.IsError {
		return
	}

	// force redirect response
	w.SetRedirect(ar.RedirectUri)

	if ar.Authorized {
		for _, str := range strings.Fields(ar.Type) {
			requestType := AuthorizeRequestType(str)
			switch requestType {
			case CODE:
				// generate authorization token
				ret := &AuthorizeData{
					Client:      ar.Client,
					CreatedAt:   s.Now(),
					ExpiresIn:   ar.Expiration,
					RedirectUri: ar.RedirectUri,
					State:       ar.State,
					Scope:       ar.Scope,
					UserData:    ar.UserData,
					// Optional PKCE challenge
					CodeChallenge:       ar.CodeChallenge,
					CodeChallengeMethod: ar.CodeChallengeMethod,
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
				if err = w.Storage.SaveAuthorize(ret); err != nil {
					w.SetErrorState(E_SERVER_ERROR, "", ar.State)
					w.InternalError = err
					return
				}

				// redirect with code
				w.Output["code"] = ret.Code
				w.Output["state"] = ret.State
			case TOKEN:
				w.SetRedirectFragment(true)

				// generate token directly
				ret := &AccessRequest{
					Type:            IMPLICIT,
					Code:            "",
					Client:          ar.Client,
					RedirectUri:     ar.RedirectUri,
					Scope:           ar.Scope,
					GenerateRefresh: false, // per the RFC, should NOT generate a refresh token in this case
					Authorized:      true,
					Expiration:      ar.Expiration,
					UserData:        ar.UserData,
				}

				s.FinishAccessRequest(w, r, ret)
				if ar.State != "" && w.InternalError == nil {
					w.Output["state"] = ar.State
				}
			case ID_TOKEN:
				w.SetRedirectFragment(true)

				key, err := s.Storage.GetPrivateKey(ar.Client.GetId())
				if err != nil {
					w.SetErrorState(E_SERVER_ERROR, "", ar.State)
					w.InternalError = err
					return
				}
				// UserData must be id_token data
				idToken, err := signPayload(key, ar.UserData)
				if err != nil {
					w.SetErrorState(E_SERVER_ERROR, "", ar.State)
					w.InternalError = err
					return
				}
				w.Output["id_token"] = idToken
				w.Output["state"] = ar.State
			}
		}
	} else {
		// redirect with error
		w.SetErrorState(E_ACCESS_DENIED, "", ar.State)
	}
}

func signPayload(key crypto.Signer, idToken interface{}) (string, error) {
	algo, err := signatureAlgorithm(key)
	if err != nil {
		return "", err
	}

	// jwt signer
	sk := jose.SigningKey{Algorithm: algo, Key: key}
	signer, err := jose.NewSigner(sk, &jose.SignerOptions{})
	if err != nil {
		panic(err)
	}
	// payload
	payload, err := json.Marshal(idToken)
	if err != nil {
		return "", err
	}
	// sign
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}

// Determine the signature algorithm for a JWT.
func signatureAlgorithm(signer crypto.Signer) (jose.SignatureAlgorithm, error) {
	if signer == nil {
		return "", errors.New("no signing key")
	}
	switch key := signer.(type) {
	case *rsa.PrivateKey:
		// Because OIDC mandates that we support RS256, we always return that
		// value. In the future, we might want to make this configurable on a
		// per client basis. For example allowing PS256 or ECDSA variants.
		return jose.RS256, nil
	case *ecdsa.PrivateKey:
		// We don't actually support ECDSA keys yet, but they're tested for
		// in case we want to in the future.
		//
		// These values are prescribed depending on the ECDSA key type. We
		// can't return different values.
		switch key.Params() {
		case elliptic.P256().Params():
			return jose.ES256, nil
		case elliptic.P384().Params():
			return jose.ES384, nil
		case elliptic.P521().Params():
			return jose.ES512, nil
		default:
			return "", errors.New("unsupported ecdsa curve")
		}
	default:
		return "", fmt.Errorf("unsupported signing key type %T", key)
	}
}
