package osin

import (
	"errors"
	"net/http"
)

type ClientAuthenticationResult struct {
	Client	        Client
	CanProceed		bool
	Error			string
	InternalError	error
}

func authenticateClient(s Storage, r *http.Request, allowSecretInParams bool, grantType string) *ClientAuthenticationResult {
		
	basicAuth, basicAuthErr := CheckBasicAuth(r)
	
	paramsClientId, paramsClientSecret:= getParamsClient(r)
	
	if basicAuth == nil && allowSecretInParams == false && paramsClientSecret != nil { 
		return invalidRequest(errors.New("Client authentication not sent"))
	}
	
	if basicAuthErr != nil && paramsClientId == nil && paramsClientSecret == nil {
		return invalidRequest(basicAuthErr)
	}
	
	
	clientId := ""
	clientSecret := ""
	
	if basicAuth != nil {
		clientId 		= basicAuth.Username
		clientSecret 	= basicAuth.Password
	} else {
	    if paramsClientId != nil { clientId = *paramsClientId}
		if paramsClientSecret != nil { clientSecret = *paramsClientSecret}
	}
	
	if clientId == "" { 
		return invalidRequest(errors.New("Client authentication not sent"))
		}
	clientSecretSupplied := clientSecret != ""
	
	client, err := s.GetClient(clientId)
	if err != nil {
		return serverError(err)
	}
	
	if client == nil {
		return unauthorizedClient(nil)
	}
	
	if client.GetRedirectUri() == "" {
		return unauthorizedClient(nil)
	}
	
	grantTypeRequiresSecret := grantTypeRequiresSecret(grantType)
	
	mustAuthenticateWithSecret := grantTypeRequiresSecret ||
								  (!grantTypeRequiresSecret && client.GetType() == CONFIDENTIAL_CLIENT) ||
								  (!grantTypeRequiresSecret && client.GetSecret() != "") ||
								  (!grantTypeRequiresSecret && clientSecretSupplied)
								
	
	if !mustAuthenticateWithSecret {
		return canProceed(client)
	}
	
	if client.GetSecret() != clientSecret {
		return unauthorizedClient(nil)
	} else {
		return canProceed(client)
	}
	
	
}

func grantTypeRequiresSecret(grantType string) bool {
	switch grantType{
		case PASSWORD, REFRESH_TOKEN, string(AUTHORIZATION_CODE):
			return false
		default:
			return true	
	}
}


func invalidRequest(internalError error) *ClientAuthenticationResult {
	return &ClientAuthenticationResult{ 
		CanProceed : false, 
		Error : E_INVALID_REQUEST,
		InternalError : internalError}
}

func serverError(internalError error) *ClientAuthenticationResult {
	return &ClientAuthenticationResult{ 
		CanProceed : false, 
		Error : E_SERVER_ERROR,
		InternalError : internalError}
}

func unauthorizedClient(internalError error) *ClientAuthenticationResult {
	return &ClientAuthenticationResult{ 
		CanProceed : false, 
		Error : E_UNAUTHORIZED_CLIENT,
		InternalError : internalError}
}

func canProceed(client Client) *ClientAuthenticationResult {
	return &ClientAuthenticationResult{ 
		CanProceed : true, 
		Client: client,
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