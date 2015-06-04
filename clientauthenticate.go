package osin

import (
	"errors"
	"net/http"
)

type ClientAuthenticationResult struct {
	Client        Client
	CanProceed    bool
	Error         string
	InternalError error
	MustReturn401 bool
}

func authenticateClient(s Storage, r *http.Request, grantType string) *ClientAuthenticationResult {

	basicAuth, authHeaderFound, basicAuthErr := CheckBasicAuth(r)

	paramsClientId, paramsClientSecret := getParamsClient(r)

	if basicAuthErr != nil && paramsClientId == nil && paramsClientSecret == nil {
		return canNotProceed(E_INVALID_CLIENT, basicAuthErr, authHeaderFound)
	}

	clientId := ""
	clientSecret := ""
	var basicAuthIsComplete bool
	var formParmsIsComplete bool

	if basicAuth != nil {
		clientId = basicAuth.Username
		clientSecret = basicAuth.Password
		basicAuthIsComplete = (basicAuth.Username != "" && basicAuth.Password != "")
	} else {
		if paramsClientId != nil {
			clientId = *paramsClientId
		}
		if paramsClientSecret != nil {
			clientSecret = *paramsClientSecret
		}
		formParmsIsComplete = (clientId != "" && clientSecret != "")
	}

	if clientId == "" {
		return canNotProceed(E_INVALID_CLIENT, errors.New("Client authentication not sent"), authHeaderFound)
	}
	clientSecretSupplied := clientSecret != ""

	client, err := s.GetClient(clientId)
	if err != nil {
		return canNotProceed(E_SERVER_ERROR, err, authHeaderFound)
	}

	if client == nil {
		return canNotProceed(E_INVALID_CLIENT, nil, authHeaderFound)
	}

	if (client.GetAuthMethod() == CLIENT_SECRET_BASIC && !basicAuthIsComplete) ||
		(client.GetAuthMethod() == CLIENT_SECRET_POST && !formParmsIsComplete) {

		return canNotProceed(E_INVALID_CLIENT, errors.New("Client authentication not sent"), authHeaderFound)
	}

	if client.GetRedirectUri() == "" {
		return canNotProceed(E_INVALID_CLIENT, errors.New("Client authentication not sent"), authHeaderFound)
	}

	grantTypeRequiresSecret := grantTypeRequiresSecret(grantType)

	mustAuthenticateWithSecret := grantTypeRequiresSecret ||
		(!grantTypeRequiresSecret && client.GetAuthMethod() != NONE) ||
		(!grantTypeRequiresSecret && client.GetSecret() != "") ||
		(!grantTypeRequiresSecret && clientSecretSupplied)

	if !mustAuthenticateWithSecret {
		return canProceed(client)
	}

	if client.GetSecret() != clientSecret {
		return canNotProceed(E_INVALID_CLIENT, nil, authHeaderFound)
	} else {
		return canProceed(client)
	}

}

func grantTypeRequiresSecret(grantType string) bool {
	switch grantType {
	case PASSWORD, REFRESH_TOKEN, string(AUTHORIZATION_CODE):
		return false
	default:
		return true
	}
}

func canNotProceed(errString string, internalError error, authHeaderFound bool) *ClientAuthenticationResult {
	var mustReturn401 bool
	if authHeaderFound {
		mustReturn401 = true
	}
	return &ClientAuthenticationResult{
		CanProceed:    false,
		Error:         errString,
		InternalError: internalError,
		MustReturn401: mustReturn401}
}

func canProceed(client Client) *ClientAuthenticationResult {
	return &ClientAuthenticationResult{
		CanProceed: true,
		Client:     client,
	}
}

func getParamsClient(r *http.Request) (*string, *string) {
	var client_id *string
	if _, hasClientId := r.Form["client_id"]; hasClientId {
		client_id_val := r.Form.Get("client_id")
		client_id = &client_id_val
	}

	if _, hasClientSecret := r.Form["client_secret"]; hasClientSecret {
		client_secret_val := r.Form.Get("client_secret")
		return client_id, &client_secret_val
	}
	return client_id, nil

}
