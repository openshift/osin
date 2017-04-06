package osin

import "testing"

func TestExtraScopesDefault(t *testing.T) {
	e := ExtraScopesDefault{}

	if e.CheckScopes("", "") == true {
		t.Fatalf("e.CheckScopes returned true with empty scopes")
	}

	if e.CheckScopes("a", "") == true {
		t.Fatalf("e.CheckScopes returned true with less scopes")
	}

	if e.CheckScopes("a,b", "b,a") == true {
		t.Fatalf("e.CheckScopes returned true with matching scopes")
	}

	if e.CheckScopes("a,b", "b,a,c") == false {
		t.Fatalf("e.CheckScopes returned false with extra scopes")
	}

	if e.CheckScopes("", "a") == false {
		t.Fatalf("e.CheckScopes returned false with extra scopes")
	}

}
