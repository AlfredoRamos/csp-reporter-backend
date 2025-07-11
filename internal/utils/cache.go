package utils

import (
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"

	"alfredoramos.mx/csp-reporter/internal/env"
	"github.com/getsentry/sentry-go"
	"golang.org/x/crypto/blake2s"
)

func Blake2s128Hash(input string, key []byte) (string, error) {
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
	sum := hash.Sum(nil)

	return hex.EncodeToString(sum), nil
}

func CacheKey(key string) string {
	key = strings.TrimSpace(key)

	if len(key) < 1 {
		return ""
	}

	appName := env.String("APP_NAME", "")
	appEnv := env.AppEnv()

	prefix, err := Blake2s128Hash(appName, env.AppKey())
	if err != nil {
		sentry.CaptureException(err)
		slog.Error("Error generating cache key prefix", slog.Any("error", err))
		return key
	}

	if !env.IsProduction() {
		prefix += ":" + appEnv
	}

	if strings.HasPrefix(key, prefix) {
		slog.Warn(
			"Cache key already has prefix",
			slog.String("key", key),
			slog.String("prefix", prefix),
		)
		return key
	}

	return prefix + ":" + key
}
