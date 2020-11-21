package osin

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"strconv"
	"time"
)

// private key for sign
var privateKey crypto.Signer

func init() {
	b, _ := pem.Decode([]byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtLKRTGNsMNUvTIwOat4GN41txOThVW6Y0hICnhombWMPMWpq
rfduK1pT0MlGG8mrP6VEdj7eJxMvOn5RJtwlLJjYyHBG/cC1a5JROd2jvS983r2+
FbObMCMurdK3QAI7WwjwWXVqFKxg+HZhcp+ENsP4jE/EYn8AicKwptvKSk/xbxRd
KloQc7LOrjhpA6dUwvLVzJ9V545CTTWmyILlk7UCK7ezrGYwExnebCydX9jJBpFi
en2YGPB6Wovs7+pc6hHBjYNCLQGsB4EMoed/fk+MWl4mokv0jNWui9uZErV2i4mU
+0noXBWrH7QPHr8mEA5LWpS3FS01CsSF5ueU6QIDAQABAoIBADrWmnFhPm14PXqT
cG5j9WpJZyDh1m3XIXPl4WxR34lm5B+XIz2agAkl1Hz7zRRnSpfi3LQULIpUuOA3
GX2p2YD4FD7QMI2YHnr0nfZVsWd8+xAcgLTYUwQNsLlxD7KMB3/RHVJD5VLt/nVp
Nrn4LzkV/uzRXIUmDarN9m+eyfQAH9gZGpNIG4pSbLlHsiljxmnGG5I2If/DSRq2
BNDAjPrmzmhOaZEgz0DM/Ng6LnFASLuG3uQHlUTDJZedCDN88kO8zm9SRyX9VKDX
hi77ow2Cg2EI+gpvW4q+mgwy84Gj19JAZeAbpuF7a6PY2UIuf+wWp47F379XjApa
e4BwMgECgYEAz1l2eBU3GPun0KIK4zULlbG3ZNOfPU3NSO5jtVxFyvdaPZ6Qa9gE
PoNbpMSdkgs+0rPokC7ZDs4frR9Rl7x8ezivl70nCnBy5i53axZGp+Q3JjcGOH6Z
e9Em5xm47lOofPlPwk2Uq9BtF9Fqo9k+skAL+G4kL/fNjfPT5vPH3xkCgYEA3xg+
nNABiQa6DZknGXGjYNqqwBiaIByLpwERYonH86dMNm4xeppvqakfzpXdLgfK7lwR
vFTfyD6TEJG2nb970wBUdigRebZ1NqJtyZU0FXDbfs7KJUgBSYnlhT2tAuM9OvMa
3wEu/JFjm4UgtuhRWpbgQkFzqiETsyi2S/8frlECgYAtqSXNi952QfTSnNyI7EWA
0YHxUije9yMdzGForskvyQi2SRTEqu1EVuj3f9SzNIbBH503IxnpiLqxBRSStY80
E2eXoq/WPK0Qw2rIyj8E+dyrLbLQ/hAOlCBdA+0Vjpar7rsBrtPugheEBznUmyKT
XkdEjfyqE4fQmsEvOr/pAQKBgQChMcpj0aOaV4LtOmDW8JYE8Fp5zAzo8NczBwGB
ul4APjxCA+K6XIYcB3hU81HJ5ZWKHnouIwFClXv7d92EI4wbjFx6tz7RO7V7kWdU
RPtKFq5x9IZ444sSkJGHcWXl9T0Tr/4Vbax+j6px/4IAxuGpW+ST2ujw3091nxAA
30kL0QKBgEQfbj/A/rVk+2yWp2IwcuG0Zg8NIMw2ISUh5IkmYycTx/3ocTMsM3Q+
urGXvgf1FCQIT+QgypS2iFDQmWOv6im0UbSC7ej0rKuKPT8rI1th+Uz2Jb0HU3Sm
aZK39t4ulCEBr9fACkY3I6X9JLyR27Fg2ymnyh5pnyOYCQsADvJR
-----END RSA PRIVATE KEY-----`))
	if b == nil {
		panic("invalid private key content")
	}
	var err error
	privateKey, err = x509.ParsePKCS1PrivateKey(b.Bytes)
	if err != nil {
		panic(err)
	}
}

type TestingStorage struct {
	clients   map[string]Client
	authorize map[string]*AuthorizeData
	access    map[string]*AccessData
	refresh   map[string]string
}

func NewTestingStorage() *TestingStorage {
	r := &TestingStorage{
		clients:   make(map[string]Client),
		authorize: make(map[string]*AuthorizeData),
		access:    make(map[string]*AccessData),
		refresh:   make(map[string]string),
	}

	r.clients["1234"] = &DefaultClient{
		Id:          "1234",
		Secret:      "aabbccdd",
		RedirectUri: "http://localhost:14000/appauth",
	}

	r.clients["public-client"] = &DefaultClient{
		Id:          "public-client",
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

func (s *TestingStorage) GetPrivateKey(clientID string) (crypto.Signer, error) {
	// ignore clientID
	return privateKey, nil
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
