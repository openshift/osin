package example

import (
	"errors"
	"fmt"
	"github.com/RangelReale/osin"
	"net/http"
)

type TestStorage struct {
	clients   map[string]*osin.Client
	authorize map[string]*osin.AuthorizeData
	access    map[string]*osin.AccessData
	refresh   map[string]string
}

func NewTestStorage() *TestStorage {
	r := &TestStorage{
		clients:   make(map[string]*osin.Client),
		authorize: make(map[string]*osin.AuthorizeData),
		access:    make(map[string]*osin.AccessData),
		refresh:   make(map[string]string),
	}

	r.clients["1234"] = &osin.Client{
		Id:          "1234",
		Secret:      "aabbccdd",
		RedirectUri: "http://localhost:14000/appauth",
	}

	return r
}

func (s *TestStorage) GetClient(id string, r *http.Request) (*osin.Client, error) {
	fmt.Printf("GetClient: %s\n", id)
	if c, ok := s.clients[id]; ok {
		return c, nil
	}
	return nil, errors.New("Client not found")
}

func (s *TestStorage) SaveAuthorize(data *osin.AuthorizeData, r *http.Request) error {
	fmt.Printf("SaveAuthorize: %s\n", data.Code)
	s.authorize[data.Code] = data
	return nil
}

func (s *TestStorage) LoadAuthorize(code string, r *http.Request) (*osin.AuthorizeData, error) {
	fmt.Printf("LoadAuthorize: %s\n", code)
	if d, ok := s.authorize[code]; ok {
		return d, nil
	}
	return nil, errors.New("Authorize not found")
}

func (s *TestStorage) RemoveAuthorize(code string, r *http.Request) error {
	fmt.Printf("RemoveAuthorize: %s\n", code)
	delete(s.authorize, code)
	return nil
}

func (s *TestStorage) SaveAccess(data *osin.AccessData, r *http.Request) error {
	fmt.Printf("SaveAccess: %s\n", data.AccessToken)
	s.access[data.AccessToken] = data
	if data.RefreshToken != "" {
		s.refresh[data.RefreshToken] = data.AccessToken
	}
	return nil
}

func (s *TestStorage) LoadAccess(code string, r *http.Request) (*osin.AccessData, error) {
	fmt.Printf("LoadAccess: %s\n", code)
	if d, ok := s.access[code]; ok {
		return d, nil
	}
	return nil, errors.New("Access not found")
}

func (s *TestStorage) RemoveAccess(code string) error {
	fmt.Printf("RemoveAccess: %s\n", code)
	delete(s.access, code)
	return nil
}

func (s *TestStorage) LoadRefresh(code string, r *http.Request) (*osin.AccessData, error) {
	fmt.Printf("LoadRefresh: %s\n", code)
	if d, ok := s.refresh[code]; ok {
		return s.LoadAccess(d, r)
	}
	return nil, errors.New("Refresh not found")
}

func (s *TestStorage) RemoveRefresh(code string, r *http.Request) error {
	fmt.Printf("RemoveRefresh: %s\n", code)
	delete(s.refresh, code)
	return nil
}
