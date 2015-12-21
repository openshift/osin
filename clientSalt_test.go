package osin

import (
	"testing"
)

func TestSecureClientIntfUserData(t *testing.T) {
	saltFn := SaltSHA256
	c := &SecuredDefaultClient{Id:"testUnit", Salt:GenSalt(6), SaltFn:saltFn}

	password := "MySecretCode"
	c.UpdateSaltedSecret(password)

	if c.ClientSecretMatches("toto") {
		t.Error("Secure Client Accept all Password !")
	}

	if ! c.ClientSecretMatches(password) {
		t.Error("Password Remarch failure")
	}
	pass1 := c.SecretSum

	c = &SecuredDefaultClient{Id:"testUnit", Salt:GenSalt(5), SaltFn:saltFn}
	c.UpdateSaltedSecret(password)
	pass2 := c.SecretSum

	if pass1 == pass2 {
		t.Error("salted secret should neved be EQ")
	}
}
