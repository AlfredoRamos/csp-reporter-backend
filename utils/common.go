package utils

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"

	"github.com/getsentry/sentry-go"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/net/publicsuffix"
)

func AddError(m fiber.Map, k string, v string) fiber.Map {
	if _, ok := m[k]; !ok {
		m[k] = []string{v}
	} else {
		m[k] = append(m[k].([]string), v)
	}

	return m
}

func Reverse[T any](s []T) []T {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}

	return s
}

func RandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	ret := make([]byte, n)

	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))

		if err != nil {
			sentry.CaptureException(err)
			return "", err
		}

		ret[i] = letters[num.Int64()]
	}

	return string(ret), nil
}

func GetDomainHostname(d string) (string, error) {
	d = strings.TrimSpace(d)

	if len(d) < 1 {
		return "", errors.New("Invalid domain.")
	}

	if !strings.HasPrefix(d, "http") {
		d = "https://" + d
	}

	u, err := url.Parse(d)
	if err != nil {
		sentry.CaptureException(err)
		return "", fmt.Errorf("Could not parse URL: %w", err)
	}

	if len(u.Scheme) < 1 || len(u.Host) < 1 || len(u.Hostname()) < 1 {
		return "", fmt.Errorf("Invalid URL: %s", d)
	}

	return u.Hostname(), nil
}

func GetApexDomain(d string) (string, error) {
	h, err := GetDomainHostname(d)
	if err != nil {
		sentry.CaptureException(err)
		return "", err
	}

	return publicsuffix.EffectiveTLDPlusOne(h)
}

func ToStringPtr(s string) *string {
	s = strings.TrimSpace(s)

	if len(s) < 1 {
		return nil
	}

	return &s
}
