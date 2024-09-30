package utils

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/getsentry/sentry-go"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/net/publicsuffix"
)

const SplitChars string = "/,;"

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

// https://stackoverflow.com/a/54426140
func SplitAny(s string, seps string) []string {
	s = strings.TrimSpace(s)

	splitter := func(r rune) bool {
		return strings.ContainsRune(seps, r)
	}

	return strings.FieldsFunc(s, splitter)
}

func CleanString(s string) string {
	c := strings.TrimSpace(s)

	if len(c) < 1 {
		return c
	}

	re := regexp.MustCompile(`([\s])+`)
	c = re.ReplaceAllString(c, `$1`)

	return c
}

func RemoveDuplicated[T comparable](sliceList []T) []T {
	allKeys := make(map[T]bool, len(sliceList))
	list := make([]T, 0)

	for _, item := range sliceList {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}

	return list
}

func CleanStringList(s []string) []string {
	if len(s) < 1 {
		return []string{}
	}

	for k, v := range s {
		s[k] = CleanString(v)
	}

	s = RemoveDuplicated(s)

	return slices.DeleteFunc(s, func(e string) bool {
		return len(e) < 1
	})
}
