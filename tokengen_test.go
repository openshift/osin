package osin

import "testing"

func TestAccessTokenSubScoperDefault(t *testing.T) {
	scope := &AccessTokenSubScoperDefault{}
	if out, err := scope.CheckSubScopes("", ""); out != "" || err != nil {
		t.Fatalf("check sub scopes should not return a match error on empty strings")
	}

	if out, err := scope.CheckSubScopes("a", ""); out != "" || err == nil {
		t.Fatalf("check sub scopes returned true with less scopes")
	}

	if out, err := scope.CheckSubScopes("a,b", "b,a"); out != "a,b" || err != nil {
		t.Fatalf("check sub scopes returned true with matching scopes %v err %v", out, err)
	}

	if out, err := scope.CheckSubScopes("a,b", "b,a,c"); out != "a,b" || err != nil {
		t.Fatalf("check sub scopes returned false with extra scopes")
	}
	if out, err := scope.CheckSubScopes("", "a"); out != "" || err != nil {
		t.Fatalf("check sub scopes returned false with extra scopes")
	}
}
