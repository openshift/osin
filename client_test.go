package osin

import (
	"testing"
)

func TestClientIntfUserData(t *testing.T) {
	c := &DefaultClient{
		UserData: make(map[string]interface{}),
	}

	// check if the interface{} returned from the method is a reference
	c.GetUserData().(map[string]interface{})["test"] = "none"

	if _, ok := c.GetUserData().(map[string]interface{})["test"]; !ok {
		t.Error("Returned interface is not a reference")
	}
}

func TestSecureClientIntfUserData(t *testing.T) {
	c := &SecuredDefaultClient{
		MaxSecretLen:40,
		SaltLen:5,
	}

	password := "MySecretCode"
	c.SaltPassword(password)

	if c.ClientSecretMatches("toto") {
		t.Error("Secure Client Accept all Password !")
	}

	if ! c.ClientSecretMatches(password) {
		t.Error("Password Remarch failure")
	}

	c = &SecuredDefaultClient{
		MaxSecretLen:10,
		SaltLen:5,
	}
	c.SaltPassword(password)
	if len(c.Secret) != 10 {
		t.Error("Secret len should be 20")
	}
}
