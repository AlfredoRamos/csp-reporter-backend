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
	"github.com/go-jose/go-jose/v4"
	jose_jwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/google/uuid"
	"github.com/redis/rueidis"
)

func ValidateJWT() fiber.Handler {
	return func(c *fiber.Ctx) error {
		savedJWE := c.Locals(utils.TokenContextKey()).(string)

		if len(savedJWE) < 1 || len(c.Get("Authorization")) < 7 {
			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"Invalid access token."},
			})
		}

		jwe := c.Get("Authorization")[7:]

		if savedJWE != jwe {
			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"Invalid provided access token."},
			})
		}

		claims, err := utils.ParseJWEClaims(savedJWE)
		if err != nil {
			slog.Error(fmt.Sprintf("Invalid access token claims: %v", err))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"Invalid access token"},
			})
		}

		if !utils.IsValidIssuer(claims.Issuer) {
			slog.Error(fmt.Sprintf("Invalid access token issuer: %v", claims.Issuer))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"The issuer is not valid."},
			})
		}

		isRevoked, err := app.Cache().DoCache(context.Background(), app.Cache().B().Sismember().Key("access-tokens:revoked").Member(claims.ID).Cache(), 5*time.Minute).AsBool()
		if err != nil && !errors.Is(err, rueidis.Nil) {
			slog.Error(fmt.Sprintf("Could not check token revocation '%s': %v", claims.ID, err))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"Could not validate access token."},
			})
		}

		if len(claims.ID) < 1 || isRevoked {
			slog.Error(fmt.Sprintf("The access token is invalid or revoked '%s': %v", claims.ID, err))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"Revoked access token."},
			})
		}

		if sub, err := uuid.Parse(claims.Subject); err != nil || !utils.IsValidUuid(sub) || claims.User.ID != sub {
			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"The subject is not valid."},
			})
		}

		if !helpers.UserExists(claims.User.ID, claims.User.Email) {
			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"The access token is not valid."},
			})
		}

		return c.Next()
	}
}

func jwtError(c *fiber.Ctx, err error) error {
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

		token, err := jose_jwt.ParseSignedAndEncrypted(
			tokenStr,
			[]jose.KeyAlgorithm{jose.ECDH_ES_A256KW},
			[]jose.ContentEncryption{jose.A256GCM},
			[]jose.SignatureAlgorithm{jose.SignatureAlgorithm(jwt.SigningKeys().Public.Algorithm)},
		)
		if err != nil {
			return jwtError(c, err)
		}

		decrypted, err := token.Decrypt(jwt.EncryptionKeys().Private)
		if err != nil {
			return jwtError(c, err)
		}

		claims := map[string]interface{}{}

		if err := decrypted.Claims(jwt.SigningKeys().Private, &claims); err != nil {
			slog.Info(fmt.Sprintf("claims: %#v", claims))
			c.Locals(utils.TokenContextKey(), decrypted)
			return jwtSuccess(c)
		}

		return jwtError(c, fiber.ErrInternalServerError)
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
