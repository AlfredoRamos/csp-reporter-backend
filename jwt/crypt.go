package jwt

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/getsentry/sentry-go"
	"github.com/go-jose/go-jose/v4"
)

var (
	cryptKeyPair  *KeyPair
	encrypter     jose.Encrypter
	onceCryptKeys sync.Once
	onceEncrypter sync.Once
)

func EncryptionKeys() *KeyPair {
	onceCryptKeys.Do(func() {
		// Public
		jwkpub := jose.JSONWebKey{}
		pubBuffer, err := os.ReadFile(filepath.Clean(filepath.Join(keyBasePath, "encryption-public.json")))
		if err != nil {
			slog.Error(fmt.Sprintf("Could not read encription public key: %v", err))
			os.Exit(1)
		}

		if err := json.Unmarshal(pubBuffer, &jwkpub); err != nil {
			slog.Error(fmt.Sprintf("Could not decode encription public key: %v", err))
			os.Exit(1)
		}

		// Private
		jwkkey := jose.JSONWebKey{}
		keyBuffer, err := os.ReadFile(filepath.Clean(filepath.Join(keyBasePath, "encryption-private.json")))
		if err != nil {
			slog.Error(fmt.Sprintf("Could not read encription private key: %v", err))
			os.Exit(1)
		}

		if err := json.Unmarshal(keyBuffer, &jwkkey); err != nil {
			slog.Error(fmt.Sprintf("Could not decode encription private key: %v", err))
			os.Exit(1)
		}

		cryptKeyPair = &KeyPair{Public: jwkpub, Private: jwkkey}
	})

	return cryptKeyPair
}

func Encrypter() jose.Encrypter {
	onceEncrypter.Do(func() {
		enc, err := jose.NewEncrypter(
			jose.A256GCM,
			jose.Recipient{Algorithm: jose.ECDH_ES_A256KW, Key: &EncryptionKeys().Public},
			(&jose.EncrypterOptions{}).WithType("JWE"),
		)
		if err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Could not create encrypter: %v", err))
			os.Exit(1)
		}

		encrypter = enc
	})

	return encrypter
}
