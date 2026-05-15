package utils

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/mail"
	"strings"

	"alfredoramos.mx/csp-reporter/internal/env"
	csperrors "alfredoramos.mx/csp-reporter/internal/errors"
	"alfredoramos.mx/csp-reporter/internal/jwt"
	"github.com/ccojocar/zxcvbn-go"
	"github.com/go-jose/go-jose/v4"
	jose_jwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

const (
	maxPassLen      int     = 255
	minPassLen      int     = 10
	defaultPassLen  int     = 10
	minPassEntrophy float64 = 50.0
	minPassScore    int     = 3
)

type argon2Config struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

type UserClaimData struct {
	ID        uuid.UUID `json:"id"`
	FirstName *string   `json:"first_name,omitempty"`
	LastName  *string   `json:"last_name,omitempty"`
	Email     string    `json:"email"`
	Roles     []string  `json:"roles"`
}

type CustomJwtClaims struct {
	jose_jwt.Claims
	User UserClaimData `json:"user"`
}

func (c CustomJwtClaims) Validate() error {
	if !IsValidIssuer(c.Issuer) {
		return errors.New("the issuer is invalid")
	}

	sub, err := uuid.Parse(c.Subject)
	if err != nil || !IsValidUuid(sub) {
		if err != nil {
			//sentry.CaptureException(err)
			return errors.New("the subject is invalid")
		}

		return errors.New("the subject is invalid")
	}

	if !IsValidUuid(c.User.ID) || sub != c.User.ID {
		return errors.New("the user ID is invalid")
	}

	if !IsValidEmail(c.User.Email) {
		return errors.New("the user email is invalid")
	}

	if len(c.User.Roles) < 1 {
		return errors.New("the user roles are invalid")
	}

	return nil
}

func AccessTokenContextKey() string {
	ctxKey := env.String("JWT_ACCESS_TOKEN_CONTEXT_KEY")
	ctxKey = strings.TrimSpace(ctxKey)

	if len(ctxKey) < 1 {
		ctxKey = "access_token"
	}

	return ctxKey
}

func RefreshTokenContextKey() string {
	ctxKey := env.String("JWT_REFRESH_TOKEN_CONTEXT_KEY")
	ctxKey = strings.TrimSpace(ctxKey)

	if len(ctxKey) < 1 {
		ctxKey = "refresh_token"
	}

	return ctxKey
}

func ParseJWEClaims(token string) (*CustomJwtClaims, error) {
	if len(token) < 1 {
		err := errors.New("error parsing empty JWE")
		//sentry.CaptureException(err)
		return &CustomJwtClaims{}, err
	}

	// Parse JWE
	jwe, err := jose.ParseEncryptedCompact(token, []jose.KeyAlgorithm{jose.ECDH_ES_A256KW}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		//sentry.CaptureException(err)
		return &CustomJwtClaims{}, err
	}

	// Decrypt JWE
	decrypted, err := jwe.Decrypt(jwt.EncryptionKeys().Private)
	if err != nil {
		//sentry.CaptureException(err)
		return &CustomJwtClaims{}, err
	}

	// Verify and parse JWT
	parsedJWT, err := jose.ParseSigned(string(decrypted), []jose.SignatureAlgorithm{jose.SignatureAlgorithm(jwt.SigningKeys().Private.Algorithm)})
	if err != nil {
		//sentry.CaptureException(err)
		return &CustomJwtClaims{}, err
	}

	// Access the payload
	payload, err := parsedJWT.Verify(jwt.SigningKeys().Public)
	if err != nil {
		//sentry.CaptureException(err)
		return &CustomJwtClaims{}, err
	}

	claims := &CustomJwtClaims{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		//sentry.CaptureException(err)
		return &CustomJwtClaims{}, err
	}

	return claims, nil
}

func NewArgon2Config() argon2Config {
	return argon2Config{
		memory:      64 * 1024,
		iterations:  4,
		parallelism: 4,
		saltLength:  16,
		keyLength:   32,
	}
}

func HashString(p string) string {
	a := NewArgon2Config()
	a.memory = 32 * 1024

	s, err := generateRandomBytes(a.saltLength)
	if err != nil {
		//sentry.CaptureException(err)
		panic(fmt.Sprintf("Could not generate secure salt: %v", err))
	}

	h := argon2.IDKey([]byte(p), s, a.iterations, a.memory, a.parallelism, a.keyLength)
	sb64 := base64.RawStdEncoding.EncodeToString(s)
	hb64 := base64.RawStdEncoding.EncodeToString(h)

	return fmt.Sprintf("%s$%s", sb64, hb64)
}

func HashPassword(p string) string {
	a := NewArgon2Config()
	s, err := generateRandomBytes(a.saltLength)
	if err != nil {
		//sentry.CaptureException(err)
		panic(fmt.Sprintf("Could not generate secure salt: %v", err))
	}

	h := argon2.IDKey([]byte(p), s, a.iterations, a.memory, a.parallelism, a.keyLength)
	sb64 := base64.RawStdEncoding.EncodeToString(s)
	hb64 := base64.RawStdEncoding.EncodeToString(h)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, a.memory, a.iterations, a.parallelism, sb64, hb64)
}

func ComparePasswordHash(p string, h string) bool {
	config, salt, hash, err := decodeHash(h)
	if err != nil {
		//sentry.CaptureException(err)
		slog.Warn("Could not decode hash", slog.Any("error", err))

		return false
	}

	newHash := argon2.IDKey([]byte(p), salt, config.iterations, config.memory, config.parallelism, config.keyLength)

	return (subtle.ConstantTimeCompare(hash, newHash) == 1)
}

func MustRehashPassword(h string) bool {
	d := NewArgon2Config()

	config, _, _, err := decodeHash(h)
	if err != nil {
		//sentry.CaptureException(err)
		slog.Warn("Could not decode hash", slog.Any("error", err))

		return false
	}

	switch {
	case config.memory != d.memory,
		config.iterations != d.iterations,
		config.parallelism != d.parallelism,
		config.saltLength != d.saltLength,
		config.keyLength != d.keyLength:
		return true
	}

	return false
}

func decodeHash(h string) (argon2Config, []byte, []byte, error) {
	vals := strings.Split(h, "$")
	if len(vals) != 6 {
		return argon2Config{}, nil, nil, errors.New("invalid encoded hash format")
	}

	var av int
	if _, err := fmt.Sscanf(vals[2], "v=%d", &av); err != nil {
		//sentry.CaptureException(err)
		return argon2Config{}, nil, nil, errors.New("the version of the Argon2 algorithm is not compatible")
	}

	config := argon2Config{}
	if _, err := fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &config.memory, &config.iterations, &config.parallelism); err != nil {
		//sentry.CaptureException(err)
		return argon2Config{}, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		//sentry.CaptureException(err)
		return argon2Config{}, nil, nil, err
	}

	config.saltLength = uint32(len(salt)) //#nosec G115

	hash, err := base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		//sentry.CaptureException(err)
		return argon2Config{}, nil, nil, err
	}

	config.keyLength = uint32(len(hash)) //#nosec G115

	return config, salt, hash, nil
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		//sentry.CaptureException(err)
		return nil, err
	}

	return b, nil
}

func IsValidEmail(e string) bool {
	e = strings.TrimSpace(e)

	if len(e) < 1 {
		return false
	}

	if _, err := mail.ParseAddress(e); err != nil {
		//sentry.CaptureException(err)
		slog.Error("Could not parse email", slog.Any("error", err))
		return false
	}

	return true
}

func IsRealEmail(e string) bool {
	if !IsValidEmail(e) {
		return false
	}

	el := strings.Split(e, "@")

	d, err := GetApexDomain(el[1])
	if err != nil {
		//sentry.CaptureException(err)
		slog.Error("Could not get apex domain", slog.Any("error", err))
		return false
	}

	mx, err := net.LookupMX(d)
	if err != nil {
		//sentry.CaptureException(err)
		slog.Error("Could not read domain MX records", slog.Any("error", err))
		return false
	}

	return len(mx) > 0
}

func MinimumPasswordLength() int {
	passLen := env.Int("MIN_PASSWORD_LENGTH", defaultPassLen)
	passLen = max(passLen, minPassLen)
	passLen = min(passLen, maxPassLen)

	return passLen
}

func ValidatePasswordStrength(p string, i []string) (bool, error) {
	if len(p) < MinimumPasswordLength() {
		return false, csperrors.ErrAuthShortPassword
	}

	v := zxcvbn.PasswordStrength(p, i)

	if v.Score < minPassScore {
		return false, csperrors.ErrAuthWeakPassword
	}

	if v.Entropy <= minPassEntrophy {
		return false, csperrors.ErrAuthLowEntropyPassword
	}

	return true, nil
}

func RandomPassword(n int) (string, error) {
	n = max(n, defaultPassLen)
	n = min(n, maxPassLen)

	const charset string = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*_=+-"
	password := make([]byte, n)

	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			//sentry.CaptureException(err)
			return "", err
		}

		password[i] = charset[num.Int64()]
	}

	return string(password), nil
}

func GetJwtIssuer() (string, error) {
	d := env.String("APP_DOMAIN")

	if !env.IsProduction() {
		return GetDomainHostname(d)
	}

	return GetApexDomain(d)
}

func IsValidIssuer(iss string) bool {
	iss = strings.TrimSpace(iss)

	if len(iss) < 1 {
		slog.Warn("Empty issuer given.")
		return false
	}

	d, err := GetJwtIssuer()
	if err != nil || len(d) < 1 {
		if err != nil {
			//sentry.CaptureException(err)
			slog.Warn("Invalid issuer given.")
			return false
		}

		return false
	}

	return d == iss
}

func CanRegisterUsers() bool {
	return env.Bool("ENABLE_USER_REGISTER", false)
}
