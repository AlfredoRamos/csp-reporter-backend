package utils

import (
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
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
		tz = "UTC"
		slog.Warn(fmt.Sprintf("Time zone not set. Falling back to '%s'.", tz))
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
		l = "en"
		slog.Warn(fmt.Sprintf("Empty email language. Falling back to '%s'.", l))
	}

	return l
}

func DkimSelector() string {
	s := os.Getenv("EMAIL_DKIM_SELECTOR")

	if len(s) < 1 {
		s = "mail"
		slog.Warn(fmt.Sprintf("Empty DKIM selector. Falling back to '%s'.", s))
	}

	return s
}

func CorsOrigins() string {
	origins := []string{os.Getenv("APP_DOMAIN")}

	orStr := strings.TrimSpace(os.Getenv("APP_CORS_ORIGINS"))

	if len(orStr) < 1 {
		return strings.Join(origins, ",")
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

	return strings.Join(origins, ",")
}
