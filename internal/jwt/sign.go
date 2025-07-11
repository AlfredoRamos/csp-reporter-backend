package jwt

import (
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/getsentry/sentry-go"
	"github.com/go-jose/go-jose/v4"
	"github.com/goccy/go-json"
)

var (
	signKeyPair  *KeyPair
	signer       jose.Signer
	onceSignKeys sync.Once
	onceSigner   sync.Once
)

func SigningKeys() *KeyPair {
	onceSignKeys.Do(func() {
		// Public
		jwkpub := jose.JSONWebKey{}
		pubBuffer, err := os.ReadFile(filepath.Clean(filepath.Join("internal", "keys", "signing-public.json")))
		if err != nil {
			slog.Error("Could not read signing public key", slog.Any("error", err))
			os.Exit(1)
		}

		if err := json.Unmarshal(pubBuffer, &jwkpub); err != nil {
			slog.Error("Could not decode signing public key", slog.Any("error", err))
			os.Exit(1)
		}

		// Private
		jwkkey := jose.JSONWebKey{}
		keyBuffer, err := os.ReadFile(filepath.Clean(filepath.Join("internal", "keys", "signing-private.json")))
		if err != nil {
			slog.Error("Could not read signing private key", slog.Any("error", err))
			os.Exit(1)
		}

		if err := json.Unmarshal(keyBuffer, &jwkkey); err != nil {
			slog.Error("Could not decode signing private key", slog.Any("error", err))
			os.Exit(1)
		}

		// Key pair
		signKeyPair = &KeyPair{Public: jwkpub, Private: jwkkey}
	})

	return signKeyPair
}

func Signer() jose.Signer {
	onceSigner.Do(func() {
		sig, err := jose.NewSigner(
			jose.SigningKey{Algorithm: jose.EdDSA, Key: &SigningKeys().Private},
			(&jose.SignerOptions{}).WithType("JWT"),
		)
		if err != nil {
			sentry.CaptureException(err)
			slog.Error("Could not create signer", slog.Any("error", err))
			os.Exit(1)
		}

		signer = sig
	})

	return signer
}
