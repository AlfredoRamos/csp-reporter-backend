package cache

import (
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"

	"alfredoramos.mx/csp-reporter/internal/env"
	"alfredoramos.mx/csp-reporter/internal/utils"
	"github.com/getsentry/sentry-go"
	"golang.org/x/crypto/blake2s"
)

func blake2s128Hash(input string, key []byte) (string, error) {
	if len(key) < 1 {
		err := errors.New("invalid key")
		sentry.CaptureException(err)
		return "", err
	}

	if len(key) > blake2s.Size {
		slog.Warn("Key is too long, truncating bytes length", slog.Int("bytes", blake2s.Size))
		key = key[:blake2s.Size]
	}

	hash, err := blake2s.New128(key)
	if err != nil {
		sentry.CaptureException(err)
		return "", err
	}

	hash.Write([]byte(input))

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func Prefix() (string, error) {
	prefix, err := blake2s128Hash(env.String("APP_NAME"), utils.AppKey())
	if err != nil {
		sentry.CaptureException(err)
		slog.Error("Error generating cache key prefix", slog.Any("error", err))
		return "", err
	}

	if !env.IsProduction() {
		prefix += ":" + env.Name()
	}

	return prefix, nil
}

func Key(key string) string {
	key = strings.TrimSpace(key)

	if len(key) < 1 {
		return ""
	}

	prefix, err := Prefix()
	if err != nil {
		sentry.CaptureException(err)
		slog.Error("Error generating cache key prefix", slog.Any("error", err))
		return key
	}

	if strings.HasPrefix(key, prefix) {
		slog.Warn(
			"Cache key already includes the prefix",
			slog.String("key", key),
			slog.String("prefix", prefix),
		)
		return key
	}

	return prefix + ":" + key
}
