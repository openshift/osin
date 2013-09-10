package osin

import (
	"code.google.com/p/go-uuid/uuid"
	"encoding/base64"
)

// Token generator interface
type TokenGen interface {
	AddHeader(name string, value interface{})
	AddValue(name string, value interface{})
	GenerateToken() (string, error)
}

// Default random token generator
type DefaultTokenGen struct {
}

func (t *DefaultTokenGen) AddHeader(name string, value interface{}) {

}

func (t *DefaultTokenGen) AddValue(name string, value interface{}) {

}

func (t *DefaultTokenGen) GenerateToken() (string, error) {
	token := uuid.New()
	return base64.StdEncoding.EncodeToString([]byte(token)), nil
}
