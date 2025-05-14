package utils

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

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
		slog.Warn(fmt.Sprintf("Key is too long, truncating to %d bytes", blake2s.Size))
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

	appName := os.Getenv("APP_NAME")
	appEnv := AppEnv()

	prefix, err := Blake2s128Hash(appName, AppKey())
	if err != nil {
		sentry.CaptureException(err)
		slog.Error("Error generating cache key prefix", "error", err)
		return key
	}

	if !IsProduction() {
		prefix += ":" + appEnv
	}

	if strings.HasPrefix(key, prefix) {
		slog.Warn(fmt.Sprintf("Cache key '%s' already has prefix '%s'", key, prefix))
		return key
	}

	return prefix + ":" + key
}
