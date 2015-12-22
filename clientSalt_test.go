package osin

import (
	"testing"
)

func TestSecureClientIntfUserData(t *testing.T) {
	saltFn := SaltSHA256
	salt := "MySalt"
	password := "MySecretCode"
	secretSum1, _ := saltFn(salt, password)

	c := &SecuredDefaultClient{Id: "testUnit", Salt: salt, SecretSum: secretSum1, SaltFn: saltFn}

	if c.ClientSecretMatches("toto") {
		t.Error("Secure Client Accept all Password !")
	}

	if !c.ClientSecretMatches(password) {
		t.Error("Password Remarch failure")
	}

	salt = "MySalT"
	secretSum2, _ := saltFn(salt, password)
	c = &SecuredDefaultClient{Id: "testUnit", Salt: salt, SecretSum: secretSum2, SaltFn: saltFn}

	if secretSum1 == secretSum2 {
		t.Error("salted secret should neved be EQ")
	}
}
