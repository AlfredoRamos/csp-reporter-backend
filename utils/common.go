package utils

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

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

func Difference[T comparable](a []T, b []T) []T {
	mb := make(map[T]struct{}, len(b))

	for _, x := range b {
		mb[x] = struct{}{}
	}

	var diff []T

	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}

	return diff
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

func CleanString(s string) string {
	c := strings.TrimSpace(s)

	if len(c) < 1 {
		return c
	}

	re := regexp.MustCompile(`([\s])+`)
	c = re.ReplaceAllString(c, `$1`)

	return c
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

func Contains[T comparable](s []T, e T) bool {
	if len(s) < 1 {
		return false
	}

	for _, a := range s {
		if a == e {
			return true
		}
	}

	return false
}

func RandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret), nil
}

// https://stackoverflow.com/a/54426140
func SplitAny(s string, seps string) []string {
	s = strings.TrimSpace(s)

	splitter := func(r rune) bool {
		return strings.ContainsRune(seps, r)
	}

	return strings.FieldsFunc(s, splitter)
}

func GetFirstElement(p string) string {
	p = strings.TrimSpace(p)

	if len(p) < 1 {
		return ""
	}

	pl := SplitAny(p, SplitChars)

	if len(pl) < 1 {
		return ""
	}

	pl = RemoveDuplicated(pl)
	pl = CleanStringList(pl)
	p = strings.TrimSpace(pl[0])

	return p
}

func GetFirstEmail(p string) string {
	p = GetFirstElement(p)

	if !IsValidEmail(p) {
		return ""
	}

	return p
}

func GetFirstPhone(p string) string {
	p = GetFirstElement(p)

	re := regexp.MustCompile(`\D+`)
	p = re.ReplaceAllString(p, "")

	if len(p) < 10 {
		return ""
	}

	return p
}

func RemoveElements[T comparable](a []T, b []T) []T {
	if len(a) < 1 || len(b) < 1 {
		return a
	}

	c := Intersection(a, b)

	for _, v := range c {
		i := slices.Index(a, v)

		if i < 0 {
			continue
		}

		a = slices.Delete(a, i, i+1)
	}

	return a
}

func Intersection[T comparable](a []T, b []T) []T {
	inter := make([]T, 0)

	for _, v := range a {
		if Contains(b, v) {
			inter = append(inter, v)
		}
	}

	return inter
}

func JoinToString(a []int, sep string) string {
	if len(a) < 1 {
		return ""
	}

	if len(sep) < 1 {
		sep = ","
	}

	b := make([]string, len(a))

	for i, v := range a {
		b[i] = strconv.Itoa(v)
	}

	return strings.Join(b, sep)
}

func ToUintPtr[T uint | uint8 | uint16 | uint32 | uint64](s string) *T {
	i, err := strconv.Atoi(s)
	if err != nil || i <= 0 {
		return nil
	}

	u := T(i)

	return &u
}

func ToStringPtr(s string) *string {
	s = strings.TrimSpace(s)

	if len(s) < 1 {
		return nil
	}

	return &s
}

func DifferentEmail(a []string, b []string) string {
	if len(a) < 1 || len(b) < 1 {
		return ""
	}

	x := make([]string, len(a))
	copy(x, a)

	y := make([]string, len(b))
	copy(y, b)

	diff := RemoveElements(x, y)

	if len(diff) > 0 {
		return diff[0]
	}

	return a[0]
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
		return "", err
	}

	return publicsuffix.EffectiveTLDPlusOne(h)
}
