package middlewares

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"alfredoramos.mx/csp-reporter/app"
	"alfredoramos.mx/csp-reporter/helpers"
	"alfredoramos.mx/csp-reporter/jwt"
	"alfredoramos.mx/csp-reporter/utils"
	"github.com/getsentry/sentry-go"
	"github.com/go-jose/go-jose/v4"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/google/uuid"
	"github.com/redis/rueidis"
)

//nolint:cyclop
func ValidateJWT() fiber.Handler {
	return func(c *fiber.Ctx) error {
		accessJWE := c.Locals(utils.AccessTokenContextKey()).(string)

		if len(accessJWE) < 1 || len(c.Get("Authorization")) <= 7 {
			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"Invalid access token."},
			})
		}

		jwe := c.Get("Authorization")[7:]

		if accessJWE != jwe {
			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"Invalid provided access token."},
			})
		}

		accessClaims, err := utils.ParseJWEClaims(accessJWE)
		if err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Invalid access token claims: %v", err))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"Invalid access token."},
			})
		}

		if !utils.IsValidIssuer(accessClaims.Issuer) {
			slog.Error(fmt.Sprintf("Invalid access token issuer: %v", accessClaims.Issuer))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"The issuer is not valid."},
			})
		}

		isAccessRevoked, err := app.Cache().DoCache(context.Background(), app.Cache().B().Sismember().Key("access-tokens:revoked").Member(accessClaims.ID).Cache(), 5*time.Minute).AsBool()
		if err != nil && !errors.Is(err, rueidis.Nil) {
			slog.Error(fmt.Sprintf("Could not check token revocation '%s': %v", accessClaims.ID, err))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"Could not validate access token."},
			})
		}

		if len(accessClaims.ID) < 1 || isAccessRevoked {
			slog.Error(fmt.Sprintf("The access token is invalid or revoked '%s': %v", accessClaims.ID, err))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"Revoked access token."},
			})
		}

		now := time.Now().In(utils.DefaultLocation())

		if now.Before(accessClaims.IssuedAt.Time()) {
			slog.Error(fmt.Sprintf("Invalid issued at date: %v", accessClaims.IssuedAt.Time()))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"The access token is not valid yet."},
			})
		}

		if now.Before(accessClaims.NotBefore.Time()) {
			slog.Error(fmt.Sprintf("Invalid not before date: %v", accessClaims.NotBefore.Time()))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"The access token is not valid yet."},
			})
		}

		if now.After(accessClaims.Expiry.Time()) {
			slog.Error(fmt.Sprintf("Invalid expiration date: %v", accessClaims.Expiry.Time()))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"The access token is no longer valid."},
			})
		}

		if sub, err := uuid.Parse(accessClaims.Subject); err != nil || !utils.IsValidUuid(sub) || accessClaims.User.ID != sub {
			slog.Error(fmt.Sprintf("Invalid subject: %v", err))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"The subject is not valid."},
			})
		}

		if !helpers.UserExists(accessClaims.User.ID, accessClaims.User.Email) {
			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"The access token is not valid."},
			})
		}

		refreshJWE := c.Cookies(utils.RefreshTokenContextKey())
		if len(refreshJWE) < 1 {
			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"The refresh token is not valid."},
			})
		}

		refreshClaims, err := utils.ParseJWEClaims(refreshJWE)
		if err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Invalid refresh token claims: %v", err))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"Invalid refresh token."},
			})
		}

		if !utils.IsValidIssuer(refreshClaims.Issuer) {
			slog.Error(fmt.Sprintf("Invalid refresh token issuer: %v", refreshClaims.Issuer))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"The issuer is not valid."},
			})
		}

		isRefreshRevoked, err := app.Cache().DoCache(context.Background(), app.Cache().B().Sismember().Key("refresh-tokens:revoked").Member(refreshClaims.ID).Cache(), 5*time.Minute).AsBool()
		if err != nil && !errors.Is(err, rueidis.Nil) {
			slog.Error(fmt.Sprintf("Could not check token revocation '%s': %v", refreshClaims.ID, err))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"Could not validate refresh token."},
			})
		}

		if len(refreshClaims.ID) < 1 || isRefreshRevoked {
			slog.Error(fmt.Sprintf("The refresh token is invalid or revoked '%s': %v", refreshClaims.ID, err))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"Revoked refresh token."},
			})
		}

		if now.Before(refreshClaims.IssuedAt.Time()) || refreshClaims.IssuedAt.Time().Before(accessClaims.IssuedAt.Time()) {
			slog.Error(fmt.Sprintf("Invalid issued at date: %v", refreshClaims.IssuedAt.Time()))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"The refresh token is not valid yet."},
			})
		}

		if now.Before(refreshClaims.NotBefore.Time()) || refreshClaims.NotBefore.Time().Before(accessClaims.NotBefore.Time()) {
			slog.Error(fmt.Sprintf("Invalid not before date: %v", refreshClaims.NotBefore.Time()))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"The refresh token is not valid yet."},
			})
		}

		if now.After(refreshClaims.Expiry.Time()) || refreshClaims.Expiry.Time().Before(accessClaims.Expiry.Time()) {
			slog.Error(fmt.Sprintf("Invalid expiration date: %v", refreshClaims.Expiry.Time()))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"The refresh token is no longer valid."},
			})
		}

		if refreshSub, err := uuid.Parse(refreshClaims.Subject); err != nil || !utils.IsValidUuid(refreshSub) || refreshClaims.User.ID != refreshSub || accessClaims.User.ID != refreshClaims.User.ID {
			slog.Error(fmt.Sprintf("Invalid subject: %v", err))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"The subject is not valid."},
			})
		}

		return c.Next()
	}
}

func jwtError(c *fiber.Ctx, err error) error {
	sentry.CaptureException(err)
	slog.Error(fmt.Sprintf("Access token error: %v", err))
	return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{"error": []string{"Invalid or expired access token."}})
}

func jwtSuccess(c *fiber.Ctx) error {
	return c.Next()
}

func AuthProtected() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if len(c.Get("Authorization")) <= 7 {
			return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
				"error": []string{"Invalid access token."},
			})
		}

		tokenStr := c.Get("Authorization")[7:]

		jwe, err := jose.ParseEncryptedCompact(
			tokenStr,
			[]jose.KeyAlgorithm{jose.ECDH_ES_A256KW},
			[]jose.ContentEncryption{jose.A256GCM},
		)
		if err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Error parsing JWE: %v", err))
			return jwtError(c, err)
		}

		decrypted, err := jwe.Decrypt(jwt.EncryptionKeys().Private)
		if err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Error decrypting JWE: %v", err))
			return jwtError(c, err)
		}

		parsedJWT, err := jose.ParseSigned(string(decrypted), []jose.SignatureAlgorithm{jose.SignatureAlgorithm(jwt.SigningKeys().Private.Algorithm)})
		if err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Error parsing JWT: %v", err))
			return jwtError(c, err)
		}

		if _, err := parsedJWT.Verify(jwt.SigningKeys().Public); err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Error verifying JWT: %v", err))
			return jwtError(c, err)
		}

		jweStr, err := jwe.CompactSerialize()
		if err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Error generating JWE access token: %v", err))
			return jwtError(c, err)
		}

		c.Locals(utils.AccessTokenContextKey(), jweStr)

		return jwtSuccess(c)
	}
}

func CheckPermissions() fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := helpers.GetUserID(c)

		if helpers.HasPermission(id, c.Path(), c.Method()) {
			return c.Next()
		}

		return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
			"error": []string{"You are not allowed to access this resource."},
		})
	}
}

func AuthLimiter() fiber.Handler {
	cfg := limiter.Config{
		Max:        25,
		Expiration: 5 * time.Minute,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(&fiber.Map{"error": []string{"Too many requests received within a short amount of time."}})
		},
	}

	return limiter.New(cfg)
}
