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
	"os"
	"strconv"
	"strings"

	"alfredoramos.mx/csp-reporter/jwt"
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

type Argon2Config struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
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
	User UserClaimData `json:"user,omitempty"`
}

func (c CustomJwtClaims) Validate() error {
	if !IsValidIssuer(c.Issuer) {
		return errors.New("The issuer is invalid.")
	}

	sub, err := uuid.Parse(c.Subject)
	if err != nil || !IsValidUuid(sub) {
		return errors.New("The subject is invalid.")
	}

	if !IsValidUuid(c.User.ID) || sub != c.User.ID {
		return errors.New("The user ID is invalid.")
	}

	if !IsValidEmail(c.User.Email) {
		return errors.New("The user email is invalid.")
	}

	if len(c.User.Roles) < 1 {
		return errors.New("The user roles are invalid.")
	}

	return nil
}

func TokenContextKey() string {
	ctxKey := os.Getenv("JWT_CONTEXT_KEY")
	ctxKey = strings.TrimSpace(ctxKey)

	if len(ctxKey) < 1 {
		ctxKey = "access_token"
	}

	return ctxKey
}

func ParseJWEClaims(token string) (*CustomJwtClaims, error) {
	// Parse JWE
	jwe, err := jose.ParseEncryptedCompact(token, []jose.KeyAlgorithm{jose.ECDH_ES_A256KW}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return &CustomJwtClaims{}, err
	}

	// Decrypt JWE
	decrypted, err := jwe.Decrypt(jwt.EncryptionKeys().Private)
	if err != nil {
		return &CustomJwtClaims{}, err
	}

	// Verify and parse JWT
	parsedJWT, err := jose.ParseSigned(string(decrypted), []jose.SignatureAlgorithm{jose.SignatureAlgorithm(jwt.SigningKeys().Private.Algorithm)})
	if err != nil {
		return &CustomJwtClaims{}, err
	}

	// Access the payload
	payload, err := parsedJWT.Verify(jwt.SigningKeys().Public)
	if err != nil {
		return &CustomJwtClaims{}, err
	}

	claims := &CustomJwtClaims{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return &CustomJwtClaims{}, err
	}

	return claims, nil
}

func NewArgon2Config() Argon2Config {
	return Argon2Config{
		Memory:      64 * 1024,
		Iterations:  4,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}
}

func HashString(p string) string {
	a := NewArgon2Config()
	a.Memory = 32 * 1024

	s, err := generateRandomBytes(a.SaltLength)
	if err != nil {
		panic(fmt.Sprintf("Could not generate secure salt: %v", err))
	}

	h := argon2.IDKey([]byte(p), s, a.Iterations, a.Memory, a.Parallelism, a.KeyLength)
	sb64 := base64.RawStdEncoding.EncodeToString(s)
	hb64 := base64.RawStdEncoding.EncodeToString(h)

	return fmt.Sprintf("%s$%s", sb64, hb64)
}

func HashPassword(p string) string {
	a := NewArgon2Config()
	s, err := generateRandomBytes(a.SaltLength)
	if err != nil {
		panic(fmt.Sprintf("Could not generate secure salt: %v", err))
	}

	h := argon2.IDKey([]byte(p), s, a.Iterations, a.Memory, a.Parallelism, a.KeyLength)
	sb64 := base64.RawStdEncoding.EncodeToString(s)
	hb64 := base64.RawStdEncoding.EncodeToString(h)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, a.Memory, a.Iterations, a.Parallelism, sb64, hb64)
}

func ComparePasswordHash(p string, h string) bool {
	config, salt, hash, err := decodeHash(h)
	if err != nil {
		slog.Warn(fmt.Sprintf("Could not decode hash: %v", err))

		return false
	}

	newHash := argon2.IDKey([]byte(p), salt, config.Iterations, config.Memory, config.Parallelism, config.KeyLength)

	return (subtle.ConstantTimeCompare(hash, newHash) == 1)
}

func decodeHash(h string) (Argon2Config, []byte, []byte, error) {
	vals := strings.Split(h, "$")
	if len(vals) != 6 {
		return Argon2Config{}, nil, nil, errors.New("Invalid encoded hash format.")
	}

	var av int
	if _, err := fmt.Sscanf(vals[2], "v=%d", &av); err != nil {
		return Argon2Config{}, nil, nil, errors.New("The version of the Argon2 algorithm is not compatible.")
	}

	config := Argon2Config{}
	if _, err := fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &config.Memory, &config.Iterations, &config.Parallelism); err != nil {
		return Argon2Config{}, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return Argon2Config{}, nil, nil, err
	}

	config.SaltLength = uint32(len(salt)) //#nosec G115

	hash, err := base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return Argon2Config{}, nil, nil, err
	}

	config.KeyLength = uint32(len(hash)) //#nosec G115

	return config, salt, hash, nil
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	return b, nil
}

func IsValidEmail(e string) bool {
	if len(e) < 1 {
		return false
	}

	if _, err := mail.ParseAddress(e); err != nil {
		slog.Error(fmt.Sprintf("Could not parse email: %v", err))
		return false
	}

	return true
}

// TODO: Extract only the apex domain to validate the MX records
func IsRealEmail(e string) bool {
	if !IsValidEmail(e) {
		return false
	}

	el := strings.Split(e, "@")
	mx, err := net.LookupMX(el[1])
	if err != nil {
		slog.Error(fmt.Sprintf("Could not read domain MX records: %v", err))
		return false
	}

	return err == nil && len(mx) > 0
}

func MinimumPasswordLength() int {
	passLen, err := strconv.Atoi(os.Getenv("MIN_PASSWORD_LENGTH"))
	if err != nil {
		passLen = defaultPassLen
	}

	if passLen < minPassLen {
		passLen = minPassLen
	}

	if passLen > maxPassLen {
		passLen = maxPassLen
	}

	return passLen
}

func ValidatePasswordStrength(p string, i []string) (bool, error) {
	if len(p) < MinimumPasswordLength() {
		return false, fmt.Errorf("The password needs to be at least %[1]d characters long. Please add %[2]d more characters.", MinimumPasswordLength(), MinimumPasswordLength()-len(p))
	}

	v := zxcvbn.PasswordStrength(p, i)

	if v.Score < minPassScore {
		return false, fmt.Errorf("The password is not strong enough. It must has a score equal or greater than %[1]d but you got %[2]d.", minPassScore, v.Score)
	}

	if v.Entropy <= minPassEntrophy {
		return false, fmt.Errorf("The password entropy is low. It must be equal or greater than %.2[1]f but you got %.2[2]f.", minPassEntrophy, v.Entropy)
	}

	return true, nil
}

func RandomPassword(n int) (string, error) {
	if n < MinimumPasswordLength() {
		n = defaultPassLen
	}

	if n > maxPassLen {
		n = maxPassLen
	}

	const charset string = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*_=+-"
	password := make([]byte, n)

	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}

		password[i] = charset[num.Int64()]
	}

	return string(password), nil
}

func GetJwtIssuer() (string, error) {
	d := os.Getenv("APP_DOMAIN")

	if IsDebug() {
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
		return false
	}

	return d == iss
}
