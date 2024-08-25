package utils

import (
	"log/slog"
	"os"
	"strconv"
	"time"
	_ "time/tzdata"
)

const (
	minJwtExpiration     int64 = 1
	defaultJwtExpiration int64 = 6
	maxJwtExpiration     int64 = 12
)

func IsDebug() bool {
	isDebug, err := strconv.ParseBool(os.Getenv("APP_DEBUG"))
	if err != nil {
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

func JwtExpiration() time.Duration {
	exp, err := strconv.ParseInt(os.Getenv("JWT_TOKEN_EXPIRATION"), 10, 64)
	if err != nil {
		exp = defaultJwtExpiration
	}

	if exp < minJwtExpiration {
		exp = minJwtExpiration
	}

	if exp > maxJwtExpiration {
		exp = maxJwtExpiration
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
