package utils

import (
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"
	_ "time/tzdata"

	"alfredoramos.mx/csp-reporter/internal/env"
)

const (
	minAccessTokenExpiration      int64 = 1
	defaultAccessTokenExpiration  int64 = 1
	maxAccessTokenExpiration      int64 = 2
	minRefreshTokenExpiration     int64 = 1
	defaultRefreshTokenExpiration int64 = 6
	maxRefreshTokenExpiration     int64 = 12
)

func AppKey() []byte {
	key := env.String("APP_KEY", "")

	if len(key) < 1 {
		panic(errors.New("invalid application key").Error())
	}

	return []byte(key)
}

func SupportEmail() string {
	e := env.String("SUPPORT_EMAIL")

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
	exp := env.Int64("JWT_ACCESS_TOKEN_EXPIRATION", defaultAccessTokenExpiration)
	exp = max(exp, minAccessTokenExpiration)
	exp = min(exp, maxAccessTokenExpiration)

	return time.Duration(exp) * time.Hour
}

func RefreshTokenExpiration() time.Duration {
	exp := env.Int64("JWT_REFRESH_TOKEN_EXPIRATION", defaultRefreshTokenExpiration)
	exp = max(exp, minRefreshTokenExpiration)
	exp = min(exp, maxRefreshTokenExpiration)

	return time.Duration(exp) * time.Hour
}

func DefaultTimeZone() string {
	return env.String("TZ", "UTC")
}

func DefaultLocation() *time.Location {
	tz := DefaultTimeZone()

	loc, err := time.LoadLocation(tz)
	if err != nil {
		//sentry.CaptureException(err)
		slog.Warn("Error setting location", slog.String("fallback", loc.String()))
		return time.Now().Location()
	}

	return loc
}

func InternalStaffEmail() string {
	e := env.String("INTERNAL_STAFF_EMAIL")

	if len(e) < 1 {
		slog.Error("Internal support email is empty")
		return ""
	}

	if !IsValidEmail(e) {
		slog.Error("Internal support email is invalid")
		return ""
	}

	return e
}

func DkimSelector() string {
	return env.String("EMAIL_DKIM_SELECTOR", "mail")
}

func CorsOrigins() []string {
	origins := []string{env.String("APP_DOMAIN")}

	orStr := strings.TrimSpace(env.String("APP_CORS_ORIGINS"))

	if len(orStr) < 1 {
		return origins
	}

	orList := strings.Split(orStr, ",")
	orList = CleanStringList(orList)

	const maxOrigins int = 10

	if len(orList) > maxOrigins {
		orList = orList[:maxOrigins]
	}

	for _, or := range orList {
		if !slices.Contains(origins, or) {
			origins = append(origins, or)
		}
	}

	origins = CleanStringList(origins)

	return origins
}
