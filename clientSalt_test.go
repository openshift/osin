package osin

import (
	"testing"
)

func TestSecureClientIntfUserData(t *testing.T) {
	SetSaltLen(5, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	SetPasswordFnc("sample", 40)

	c := &SecuredDefaultClient{Id:"testUnit"}

	password := "MySecretCode"
	c.UpdateSaltedSecret(password)

	if c.ClientSecretMatches("toto") {
		t.Error("Secure Client Accept all Password !")
	}

	if ! c.ClientSecretMatches(password) {
		t.Error("Password Remarch failure")
	}

	SetPasswordFnc("sample", 10)
	c = &SecuredDefaultClient{Id:"V2"}
	c.UpdateSaltedSecret(password)
	pass1 := c.SecretSum
	if len(c.SecretSum) != 10 {
		t.Error("Secret len should be 20")
	}

	c = &SecuredDefaultClient{Id:"V2"}
	c.UpdateSaltedSecret(password)
	pass2 := c.SecretSum
	if len(c.SecretSum) != 10 {
		t.Error("Secret len should be 20")
	}

	if pass1 == pass2 {
		t.Error("salted secret should neved be EQ")
	}
}
