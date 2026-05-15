package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/zeebo/xxh3"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
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
		return csperrors.ErrJwtInvalidIssuer
	}

	sub, err := uuid.Parse(c.Subject)
	if err != nil || !IsValidUuid(sub) {
		if err != nil {
			//sentry.CaptureException(err)
			return csperrors.ErrJwtInvalidSubject
		}

		return csperrors.ErrJwtInvalidSubject
	}

	if !IsValidUuid(c.User.ID) || sub != c.User.ID {
		return csperrors.ErrJwtInvalidUserID
	}

	if !IsValidEmail(c.User.Email) {
		return csperrors.ErrJwtInvalidUserEmail
	}

	if len(c.User.Roles) < 1 {
		return csperrors.ErrJwtInvalidUserRoles
	}

	return nil
}

func AccessTokenContextKey() string {
	return env.String("JWT_ACCESS_TOKEN_CONTEXT_KEY", "access_token")
}

func RefreshTokenContextKey() string {
	return env.String("JWT_REFRESH_TOKEN_CONTEXT_KEY", "refresh_token")
}

func ParseJWEClaims(token string) (*CustomJwtClaims, error) {
	if len(token) < 1 {
		err := csperrors.ErrJwtEmptyJwe
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
		return argon2Config{}, nil, nil, csperrors.ErrArgonInvalidHashFormat
	}

	var av int
	if _, err := fmt.Sscanf(vals[2], "v=%d", &av); err != nil {
		//sentry.CaptureException(err)
		return argon2Config{}, nil, nil, csperrors.ErrArgonInvalidAlgorithm
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

	for i := range n {
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

func XXHashString(input string) (string, error) {
	h := xxh3.New()

	if _, err := h.WriteString(input); err != nil {
		slog.Error("Error generating hash", slog.Any("error", err))
		return "", err
	}

	hash := h.Sum(nil)
	return hex.EncodeToString(hash), nil
}

func EncryptString(key []byte, p string) (string, error) {
	// AES block cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt
	ciphertext := gcm.Seal(nonce, nonce, []byte(p), nil)

	// Base64 encode for storage/transmission
	return base64.RawStdEncoding.EncodeToString(ciphertext), nil
}

func DecryptString(key []byte, e string) (string, error) {
	// Decode base64
	data, err := base64.RawStdEncoding.Strict().DecodeString(e)
	if err != nil {
		return "", err
	}

	// AES block cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()

	if len(data) < nonceSize {
		return "", csperrors.ErrDecryptShortCipherText
	}

	// Split nonce + ciphertext
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// Decrypt + authenticate
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func DeriveKey(key []byte) ([]byte, error) {
	h := hkdf.New(sha256.New, key, nil, []byte("AES-GCM key"))

	subkey := make([]byte, 32)

	if _, err := io.ReadFull(h, subkey); err != nil {
		return nil, err
	}

	return subkey, nil
}
