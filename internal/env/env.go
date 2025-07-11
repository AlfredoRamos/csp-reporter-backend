package env

import (
	"errors"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/getsentry/sentry-go"
)

const (
	ProductionEnv  string = "production"
	DevelopmentEnv string = "development"
)

func String(k string, d string) string {
	k = strings.TrimSpace(k)

	if len(k) < 1 {
		sentry.CaptureException(errors.New("invalid environment key"))
		return d
	}

	return strings.TrimSpace(os.Getenv(k))
}

func Bool(k string, d bool) bool {
	keyStr := String(k, "")

	if len(keyStr) < 1 {
		return d
	}

	key, err := strconv.ParseBool(keyStr)
	if err != nil {
		sentry.CaptureException(err)
		return d
	}

	return key
}

func Float64(k string, d float64) float64 {
	keyStr := String(k, "")

	if len(keyStr) < 1 {
		return d
	}

	key, err := strconv.ParseFloat(keyStr, 64)
	if err != nil {
		sentry.CaptureException(err)
		return d
	}

	return key
}

func Int64(k string, d int64) int64 {
	keyStr := String(k, "")

	if len(keyStr) < 1 {
		return d
	}

	key, err := strconv.ParseInt(keyStr, 10, 64)
	if err != nil {
		sentry.CaptureException(err)
		return d
	}

	return key
}

func Int(k string, d int) int {
	return int(Int64(k, int64(d)))
}

func AppKey() []byte {
	key := String("APP_KEY", "")

	if len(key) < 1 {
		panic(errors.New("invalid application key").Error())
	}

	return []byte(key)
}

func AppEnv() string {
	e := String("APP_ENV", ProductionEnv)

	switch {
	case strings.EqualFold(e, ProductionEnv), strings.EqualFold(e, DevelopmentEnv):
		// * Valid environment
	default:
		e = DevelopmentEnv
		slog.Warn("Unknown environment", slog.String("fallback", e))
	}

	return e
}

func IsProduction() bool {
	return strings.EqualFold(AppEnv(), ProductionEnv)
}

func IsDebug() bool {
	return Bool("APP_DEBUG", false)
}
