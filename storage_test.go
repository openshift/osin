package osin

import (
	"strconv"
	"time"
)

type TestingStorage struct {
	clients   map[string]Client
	authorize map[string]*AuthorizeData
	access    map[string]*AccessData
	refresh   map[string]string
}

func NewTestingStorage() *TestingStorage {
	p := &Argon2Params{
        Memory:      64 * 1024,
        Iterations:  3,
        Parallelism: 2,
        SaltLength:  16,
        KeyLength:   32,
    }
	hashedSecret, _ := GenerateArgon2("aabbccdd", p)
	hashedPublic, _ := GenerateArgon2("", p)
	r := &TestingStorage{
		clients:   make(map[string]Client),
		authorize: make(map[string]*AuthorizeData),
		access:    make(map[string]*AccessData),
		refresh:   make(map[string]string),
	}

	r.clients["1234"] = &DefaultClient{
		Id:          "1234",
		Secret:      hashedSecret,
		RedirectUri: "http://localhost:14000/appauth",
	}

	r.clients["public-client"] = &DefaultClient{
		Id:          "public-client",
		Secret:      hashedPublic,
		RedirectUri: "http://localhost:14000/appauth",
	}

	r.authorize["9999"] = &AuthorizeData{
		Client:      r.clients["1234"],
		Code:        "9999",
		ExpiresIn:   3600,
		CreatedAt:   time.Now(),
		RedirectUri: "http://localhost:14000/appauth",
	}

	r.access["9999"] = &AccessData{
		Client:        r.clients["1234"],
		AuthorizeData: r.authorize["9999"],
		AccessToken:   "9999",
		ExpiresIn:     3600,
		CreatedAt:     time.Now(),
	}

	r.access["r9999"] = &AccessData{
		Client:        r.clients["1234"],
		AuthorizeData: r.authorize["9999"],
		AccessData:    r.access["9999"],
		AccessToken:   "9999",
		RefreshToken:  "r9999",
		ExpiresIn:     3600,
		CreatedAt:     time.Now(),
	}

	r.refresh["r9999"] = "9999"

	return r
}

func (s *TestingStorage) Clone() Storage {
	return s
}

func (s *TestingStorage) Close() {
}

func (s *TestingStorage) GetClient(id string) (Client, error) {
	if c, ok := s.clients[id]; ok {
		return c, nil
	}
	return nil, ErrNotFound
}

func (s *TestingStorage) SetClient(id string, client Client) error {
	s.clients[id] = client
	return nil
}

func (s *TestingStorage) SaveAuthorize(data *AuthorizeData) error {
	s.authorize[data.Code] = data
	return nil
}

func (s *TestingStorage) LoadAuthorize(code string) (*AuthorizeData, error) {
	if d, ok := s.authorize[code]; ok {
		return d, nil
	}
	return nil, ErrNotFound
}

func (s *TestingStorage) RemoveAuthorize(code string) error {
	delete(s.authorize, code)
	return nil
}

func (s *TestingStorage) SaveAccess(data *AccessData) error {
	s.access[data.AccessToken] = data
	if data.RefreshToken != "" {
		s.refresh[data.RefreshToken] = data.AccessToken
	}
	return nil
}

func (s *TestingStorage) LoadAccess(code string) (*AccessData, error) {
	if d, ok := s.access[code]; ok {
		return d, nil
	}
	return nil, ErrNotFound
}

func (s *TestingStorage) RemoveAccess(code string) error {
	delete(s.access, code)
	return nil
}

func (s *TestingStorage) LoadRefresh(code string) (*AccessData, error) {
	if d, ok := s.refresh[code]; ok {
		return s.LoadAccess(d)
	}
	return nil, ErrNotFound
}

func (s *TestingStorage) RemoveRefresh(code string) error {
	delete(s.refresh, code)
	return nil
}

// Predictable testing token generation

type TestingAuthorizeTokenGen struct {
	counter int64
}

func (a *TestingAuthorizeTokenGen) GenerateAuthorizeToken(data *AuthorizeData) (ret string, err error) {
	a.counter++
	return strconv.FormatInt(a.counter, 10), nil
}

type TestingAccessTokenGen struct {
	acounter int64
	rcounter int64
}

func (a *TestingAccessTokenGen) GenerateAccessToken(data *AccessData, generaterefresh bool) (accesstoken string, refreshtoken string, err error) {
	a.acounter++
	accesstoken = strconv.FormatInt(a.acounter, 10)

	if generaterefresh {
		a.rcounter++
		refreshtoken = "r" + strconv.FormatInt(a.rcounter, 10)
	}
	return
}
