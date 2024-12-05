package utils

import (
	"log/slog"
	"os"
	"strconv"
	"time"
	_ "time/tzdata"

	"github.com/getsentry/sentry-go"
)

const (
	minAccessTokenExpiration      int64 = 1
	defaultAccessTokenExpiration  int64 = 1
	maxAccessTokenExpiration      int64 = 2
	minRefreshTokenExpiration     int64 = 1
	defaultRefreshTokenExpiration int64 = 6
	maxRefreshTokenExpiration     int64 = 12
)

func IsDebug() bool {
	isDebug, err := strconv.ParseBool(os.Getenv("APP_DEBUG"))
	if err != nil {
		sentry.CaptureException(err)
		isDebug = false
	}

	return isDebug
}

func SupportEmail() string {
	e := os.Getenv("SUPPORT_EMAIL")

	if len(e) < 1 {
		slog.Error("Support email is empty.")
		return ""
	}

	if !IsValidEmail(e) {
		slog.Error("Support email is invalid.")
		return ""
	}

	return e
}

func AccessTokenExpiration() time.Duration {
	exp, err := strconv.ParseInt(os.Getenv("JWT_ACCESS_TOKEN_EXPIRATION"), 10, 64)
	if err != nil {
		sentry.CaptureException(err)
		exp = defaultAccessTokenExpiration
	}

	if exp < minAccessTokenExpiration {
		exp = minAccessTokenExpiration
	}

	if exp > maxAccessTokenExpiration {
		exp = maxAccessTokenExpiration
	}

	return time.Duration(exp) * time.Hour
}

func RefreshTokenExpiration() time.Duration {
	exp, err := strconv.ParseInt(os.Getenv("JWT_REFRESH_TOKEN_EXPIRATION"), 10, 64)
	if err != nil {
		sentry.CaptureException(err)
		exp = defaultRefreshTokenExpiration
	}

	if exp < minRefreshTokenExpiration {
		exp = minRefreshTokenExpiration
	}

	if exp > maxRefreshTokenExpiration {
		exp = maxRefreshTokenExpiration
	}

	return time.Duration(exp) * time.Hour
}

func DefaultTimeZone() string {
	tz := os.Getenv("TZ")
	if len(tz) < 1 {
		tz = "America/Mexico_City"
	}

	return tz
}

func DefaultLocation() *time.Location {
	tz := DefaultTimeZone()

	loc, err := time.LoadLocation(tz)
	if err != nil {
		sentry.CaptureException(err)
		return time.Now().Location()
	}

	return loc
}

func InternalStaffEmail() string {
	e := os.Getenv("INTERNAL_STAFF_EMAIL")

	if len(e) < 1 {
		slog.Error("Internal support email is empty.")
		return ""
	}

	if !IsValidEmail(e) {
		slog.Error("Internal support email is invalid.")
		return ""
	}

	return e
}

func EmailLang() string {
	l := os.Getenv("EMAIL_LANG")

	if len(l) < 1 {
		slog.Warn("Empty email language. Falling back to 'en'.")
		l = "en"
	}

	return l
}
