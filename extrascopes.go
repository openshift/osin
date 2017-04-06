package osin

import "strings"

type ExtraScopesDefault struct {
}

type ExtraScopes interface {
	CheckScopes(access_scopes, refresh_scopes string) bool
}

func (e *ExtraScopesDefault) CheckScopes(access_scopes, refresh_scopes string) bool {

	access_scopes_list := strings.Split(access_scopes, ",")
	refresh_scopes_list := strings.Split(refresh_scopes, ",")

	access_map := make(map[string]int)

	for _, scope := range access_scopes_list {
		if scope == "" {
			continue
		}
		access_map[scope] = 1
	}

	for _, scope := range refresh_scopes_list {
		if scope == "" {
			continue
		}
		if _, ok := access_map[scope]; !ok {
			return true
		}
	}
	return false

}
