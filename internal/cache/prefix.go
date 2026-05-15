package cache

import (
	"log/slog"
	"strings"

	"alfredoramos.mx/csp-reporter/internal/env"
	"alfredoramos.mx/csp-reporter/internal/utils"
)

func Prefix() (string, error) {
	prefix, err := utils.XXHashString(env.String("APP_NAME"))
	if err != nil {
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

func RemoveKey(key string) string {
	key = strings.TrimSpace(key)

	if len(key) < 1 {
		return ""
	}

	prefix, err := Prefix()
	if err != nil {
		slog.Error("Error generating cache key prefix", slog.Any("error", err))
		return key
	}

	if !strings.HasPrefix(key, prefix) {
		slog.Warn(
			"Cache key does not include the prefix",
			slog.String("key", key),
			slog.String("prefix", prefix),
		)
		return key
	}

	return strings.Replace(key, prefix+":", "", 1)
}
