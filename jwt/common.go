package jwt

import (
	"github.com/go-jose/go-jose/v4"
)

type KeyPair struct {
	Public  jose.JSONWebKey
	Private jose.JSONWebKey
}

const keyBasePath string = "keys"
