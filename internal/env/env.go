package env

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
)

const (
	ProductionEnv  string = "production"
	DevelopmentEnv string = "development"
)

func String(k string, d ...string) string {
	if len(d) > 1 {
		//sentry.CaptureException(csperrors.ErrTooManyDefaultValues)
		d = d[:1]
	}

	k = strings.TrimSpace(k)

	if len(k) < 1 {
		//sentry.CaptureException(csperrors.ErrInvalidEnvKey)

		if len(d) > 0 {
			return strings.TrimSpace(d[0])
		}

		return ""
	}

	v := strings.TrimSpace(os.Getenv(k))

	if len(v) < 1 && len(d) > 0 {
		return strings.TrimSpace(d[0])
	}

	return v
}

func Bool(k string, d ...bool) bool {
	if len(d) > 1 {
		//sentry.CaptureException(csperrors.ErrTooManyDefaultValues)
		d = d[:1]
	}

	keyStr := String(k)

	if len(keyStr) < 1 {
		if len(d) > 0 {
			return d[0]
		}

		return false
	}

	key, err := strconv.ParseBool(keyStr)
	if err != nil {
		//sentry.CaptureException(err)

		if len(d) > 0 {
			return d[0]
		}

		return false
	}

	return key
}

func Float64(k string, d ...float64) float64 {
	if len(d) > 1 {
		//sentry.CaptureException(csperrors.ErrTooManyDefaultValues)
		d = d[:1]
	}

	keyStr := String(k)

	if len(keyStr) < 1 {
		if len(d) > 0 {
			return d[0]
		}

		return 0.0
	}

	key, err := strconv.ParseFloat(keyStr, 64)
	if err != nil {
		//sentry.CaptureException(err)

		if len(d) > 0 {
			return d[0]
		}

		return 0.0
	}

	return key
}

func Int64(k string, d ...int64) int64 {
	if len(d) > 1 {
		//sentry.CaptureException(csperrors.ErrTooManyDefaultValues)
		d = d[:1]
	}

	keyStr := String(k)

	if len(keyStr) < 1 {
		if len(d) > 0 {
			return d[0]
		}

		return 0
	}

	key, err := strconv.ParseInt(keyStr, 10, 64)
	if err != nil {
		//sentry.CaptureException(err)

		if len(d) > 0 {
			return d[0]
		}

		return 0
	}

	return key
}

func Int(k string, d ...int) int {
	if len(d) > 1 {
		//sentry.CaptureException(csperrors.ErrTooManyDefaultValues)
		d = d[:1]
	}

	keyStr := String(k)

	if len(keyStr) < 1 {
		if len(d) > 0 {
			return d[0]
		}

		return 0
	}

	key, err := strconv.Atoi(keyStr)
	if err != nil {
		//sentry.CaptureException(err)

		if len(d) > 0 {
			return d[0]
		}

		return 0
	}

	return key
}

func Name() string {
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
	return strings.EqualFold(Name(), ProductionEnv)
}

func IsDebug() bool {
	return Bool("APP_DEBUG", false)
}
