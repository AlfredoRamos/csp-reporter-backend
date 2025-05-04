package middlewares

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"alfredoramos.mx/csp-reporter/internal/app"
	csperrors "alfredoramos.mx/csp-reporter/internal/errors"
	"alfredoramos.mx/csp-reporter/internal/helpers"
	"alfredoramos.mx/csp-reporter/internal/jwt"
	"alfredoramos.mx/csp-reporter/internal/models"
	"alfredoramos.mx/csp-reporter/internal/utils"
	"github.com/getsentry/sentry-go"
	"github.com/go-jose/go-jose/v4"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/google/uuid"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/pquerna/otp/totp"
	"github.com/valkey-io/valkey-go"
)

func AuthProtected() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if len(c.Get("Authorization")) <= 7 {
			return c.Status(fiber.StatusUnauthorized).JSON(&fiber.Map{
				"error": []string{app.Translate(&i18n.LocalizeConfig{
					DefaultMessage: &i18n.Message{
						ID:    "ErrorInvalidAccessToken",
						Other: "Invalid access token.",
					},
				}, c)},
			})
		}

		tokenStr := c.Get("Authorization")[7:]

		if len(tokenStr) < 1 {
			return jwtError(c, fiber.StatusUnauthorized, errors.New("empty access token"))
		}

		jwe, err := jose.ParseEncryptedCompact(
			tokenStr,
			[]jose.KeyAlgorithm{jose.ECDH_ES_A256KW},
			[]jose.ContentEncryption{jose.A256GCM},
		)
		if err != nil {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("error parsing JWE: %w", err))
		}

		decrypted, err := jwe.Decrypt(jwt.EncryptionKeys().Private)
		if err != nil {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("error decrypting JWE: %w", err))
		}

		parsedJWT, err := jose.ParseSigned(string(decrypted), []jose.SignatureAlgorithm{jose.SignatureAlgorithm(jwt.SigningKeys().Private.Algorithm)})
		if err != nil {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("error parsing JWT: %w", err))
		}

		if _, err := parsedJWT.Verify(jwt.SigningKeys().Public); err != nil {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("error verifying JWT: %w", err))
		}

		jweStr, err := jwe.CompactSerialize()
		if err != nil {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("error generating JWE access token: %w", err))
		}

		c.Locals(utils.AccessTokenContextKey(), jweStr)

		return jwtSuccess(c)
	}
}

func ValidateAccessToken() fiber.Handler {
	return func(c *fiber.Ctx) error {
		accessJWE := c.Locals(utils.AccessTokenContextKey()).(string)

		if len(accessJWE) < 1 || len(c.Get("Authorization")) <= 7 {
			return c.Status(fiber.StatusUnauthorized).JSON(&fiber.Map{
				"error": []string{app.Translate(&i18n.LocalizeConfig{
					DefaultMessage: &i18n.Message{
						ID:    "ErrorInvalidAccessToken",
						Other: "Invalid access token.",
					},
				}, c)},
			})
		}

		jwe := c.Get("Authorization")[7:]

		if len(jwe) < 1 {
			return jwtError(c, fiber.StatusUnauthorized, errors.New("empty access token"))
		}

		if accessJWE != jwe {
			return jwtError(c, fiber.StatusUnauthorized, errors.New("invalid provided access token"))
		}

		accessClaims, err := utils.ParseJWEClaims(accessJWE)
		if err != nil {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("invalid access token claims: %w", err))
		}

		if !utils.IsValidIssuer(accessClaims.Issuer) {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("invalid access token issuer: %v", accessClaims.Issuer))
		}

		isAccessRevoked, err := app.Cache().DoCache(context.Background(), app.Cache().B().Sismember().Key("access-tokens:revoked").Member(accessClaims.ID).Cache(), 5*time.Minute).AsBool()
		if err != nil && !errors.Is(err, valkey.Nil) {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("could not check token revocation '%v': %w", accessClaims.ID, err))
		}

		if len(accessClaims.ID) < 1 || isAccessRevoked {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("the access token is invalid or revoked '%v'", accessClaims.ID))
		}

		now := time.Now().In(utils.DefaultLocation())

		if now.Before(accessClaims.IssuedAt.Time()) {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("invalid issued at date: %v", accessClaims.IssuedAt.Time()))
		}

		if now.Before(accessClaims.NotBefore.Time()) {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("invalid not before date: %v", accessClaims.NotBefore.Time()))
		}

		if now.After(accessClaims.Expiry.Time()) {
			return jwtError(c, fiber.StatusUnauthorized, csperrors.ErrExpiredAccessToken)
		}

		if sub, err := uuid.Parse(accessClaims.Subject); err != nil || !utils.IsValidUuid(sub) || accessClaims.User.ID != sub {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("invalid subject: %w", err))
		}

		if !helpers.UserExists(accessClaims.User.ID, accessClaims.User.Email) {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("invalid user: [%s] %v", accessClaims.User.ID, accessClaims.User.Email))
		}

		return c.Next()
	}
}

func ValidateRefreshToken() fiber.Handler {
	return func(c *fiber.Ctx) error {
		accessJWE := c.Locals(utils.AccessTokenContextKey()).(string)

		if len(accessJWE) < 1 || len(c.Get("Authorization")) <= 7 {
			return c.Status(fiber.StatusUnauthorized).JSON(&fiber.Map{
				"error": []string{app.Translate(&i18n.LocalizeConfig{
					DefaultMessage: &i18n.Message{
						ID:    "ErrorInvalidAccessToken",
						Other: "Invalid access token.",
					},
				}, c)},
			})
		}

		jwe := c.Get("Authorization")[7:]

		if len(jwe) < 1 {
			return jwtError(c, fiber.StatusUnauthorized, errors.New("empty access token"))
		}

		if accessJWE != jwe {
			return jwtError(c, fiber.StatusUnauthorized, errors.New("invalid provided access token"))
		}

		accessClaims, err := utils.ParseJWEClaims(accessJWE)
		if err != nil {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("invalid access token claims: %w", err))
		}

		if !utils.IsValidIssuer(accessClaims.Issuer) {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("invalid access token issuer: %v", accessClaims.Issuer))
		}

		isAccessRevoked, err := app.Cache().DoCache(context.Background(), app.Cache().B().Sismember().Key("access-tokens:revoked").Member(accessClaims.ID).Cache(), 5*time.Minute).AsBool()
		if err != nil && !errors.Is(err, valkey.Nil) {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("could not check token revocation '%v': %w", accessClaims.ID, err))
		}

		if len(accessClaims.ID) < 1 || isAccessRevoked {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("the access token is invalid or revoked '%v'", accessClaims.ID))
		}

		refreshJWE := c.Cookies(utils.RefreshTokenContextKey())
		if len(refreshJWE) < 1 {
			return jwtError(c, fiber.StatusUnauthorized, errors.New("the refresh token is not valid"))
		}

		refreshClaims, err := utils.ParseJWEClaims(refreshJWE)
		if err != nil {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("invalid refresh token claims: %w", err))
		}

		if !utils.IsValidIssuer(refreshClaims.Issuer) {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("invalid refresh token issuer: %v", refreshClaims.Issuer))
		}

		isRefreshRevoked, err := app.Cache().DoCache(context.Background(), app.Cache().B().Sismember().Key("refresh-tokens:revoked").Member(refreshClaims.ID).Cache(), 5*time.Minute).AsBool()
		if err != nil && !errors.Is(err, valkey.Nil) {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("could not check token revocation '%v': %w", refreshClaims.ID, err))
		}

		if len(refreshClaims.ID) < 1 || isRefreshRevoked {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("the refresh token is invalid or revoked '%v': %w", refreshClaims.ID, err))
		}

		now := time.Now().In(utils.DefaultLocation())

		if now.Before(refreshClaims.IssuedAt.Time()) || refreshClaims.IssuedAt.Time().Before(accessClaims.IssuedAt.Time()) {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("invalid issued at date: %v", refreshClaims.IssuedAt.Time()))
		}

		if now.Before(refreshClaims.NotBefore.Time()) || refreshClaims.NotBefore.Time().Before(accessClaims.NotBefore.Time()) {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("invalid not before date: %v", refreshClaims.NotBefore.Time()))
		}

		if now.After(refreshClaims.Expiry.Time()) || refreshClaims.Expiry.Time().Before(accessClaims.Expiry.Time()) {
			return jwtError(c, fiber.StatusUnauthorized, csperrors.ErrExpiredRefreshToken)
		}

		if refreshSub, err := uuid.Parse(refreshClaims.Subject); err != nil || !utils.IsValidUuid(refreshSub) || refreshClaims.User.ID != refreshSub || accessClaims.User.ID != refreshClaims.User.ID {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("invalid subject: %w", err))
		}

		return c.Next()
	}
}

func ValidateIntermediateToken() fiber.Handler {
	return func(c *fiber.Ctx) error {
		intermediateJWE := c.Locals(utils.IntermediateTokenContextKey()).(string)

		if len(intermediateJWE) < 1 || len(c.Get("Authorization")) <= 7 {
			return c.Status(fiber.StatusUnauthorized).JSON(&fiber.Map{
				"error": []string{app.Translate(&i18n.LocalizeConfig{
					DefaultMessage: &i18n.Message{
						ID:    "ErrorInvalidIntermediateToken",
						Other: "Invalid intermediate token.",
					},
				}, c)},
			})
		}

		jwe := c.Get("Authorization")[7:]

		if len(jwe) < 1 {
			return jwtError(c, fiber.StatusUnauthorized, errors.New("empty intermediate token"))
		}

		if intermediateJWE != jwe {
			return jwtError(c, fiber.StatusUnauthorized, errors.New("invalid provided intermediate token"))
		}

		intermediateClaims, err := utils.ParseJWEClaims(intermediateJWE)
		if err != nil {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("invalid intermediate token claims: %w", err))
		}

		if intermediateClaims.User.Type == nil || intermediateClaims.User.Type != nil && strings.EqualFold(*intermediateClaims.User.Type, "intermediate") {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("invalid intermediate token type: %v", *intermediateClaims.User.Type))
		}

		if !utils.IsValidIssuer(intermediateClaims.Issuer) {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("invalid intermediate token issuer: %v", intermediateClaims.Issuer))
		}

		isIntermediateRevoked, err := app.Cache().DoCache(context.Background(), app.Cache().B().Sismember().Key("intermediate-tokens:revoked").Member(intermediateClaims.ID).Cache(), 5*time.Minute).AsBool()
		if err != nil && !errors.Is(err, valkey.Nil) {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("could not check token revocation '%v': %w", intermediateClaims.ID, err))
		}

		if len(intermediateClaims.ID) < 1 || isIntermediateRevoked {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("the intermediate token is invalid or revoked '%v'", intermediateClaims.ID))
		}

		now := time.Now().In(utils.DefaultLocation())

		if now.Before(intermediateClaims.IssuedAt.Time()) {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("invalid issued at date: %v", intermediateClaims.IssuedAt.Time()))
		}

		if now.Before(intermediateClaims.NotBefore.Time()) {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("invalid not before date: %v", intermediateClaims.NotBefore.Time()))
		}

		if now.After(intermediateClaims.Expiry.Time()) {
			return jwtError(c, fiber.StatusUnauthorized, csperrors.ErrExpiredAccessToken)
		}

		if sub, err := uuid.Parse(intermediateClaims.Subject); err != nil || !utils.IsValidUuid(sub) || intermediateClaims.User.ID != sub {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("invalid subject: %w", err))
		}

		if !helpers.UserExists(intermediateClaims.User.ID, intermediateClaims.User.Email) {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("invalid user: [%s] %v", intermediateClaims.User.ID, intermediateClaims.User.Email))
		}

		if !intermediateClaims.User.MFAEnabled {
			return jwtError(c, fiber.StatusUnauthorized, fmt.Errorf("invalid MFA status: %v", intermediateClaims.User.MFAEnabled))
		}

		return c.Next()
	}
}

func jwtError(c *fiber.Ctx, status int, err error) error { //nolint:unparam
	if err != nil {
		sentry.CaptureException(err)
		slog.Error(fmt.Sprintf("Access token error: %v", err))
	}

	if status < fiber.StatusBadRequest {
		status = fiber.StatusBadRequest
	}

	errs := fiber.Map{}

	if errors.Is(err, csperrors.ErrExpiredAccessToken) {
		errs = utils.AddError(errs, "error", app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorExpiredAccessToken",
				Other: "Expired access token.",
			},
		}, c))

		errs = utils.AddError(errs, "code", "access_token_expired")
	}

	if errors.Is(err, csperrors.ErrExpiredRefreshToken) {
		errs = utils.AddError(errs, "error", app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorExpiredRefreshToken",
				Other: "Expired refresh token.",
			},
		}, c))

		errs = utils.AddError(errs, "code", "refresh_token_expired")
	}

	if len(errs) > 0 {
		return c.Status(status).JSON(&errs)
	}

	return c.Status(status).JSON(&fiber.Map{"error": []string{app.Translate(&i18n.LocalizeConfig{
		DefaultMessage: &i18n.Message{
			ID:    "ErrorInvalidExpiredAccessToken",
			Other: "Invalid or expired access token.",
		},
	}, c)}})
}

func jwtSuccess(c *fiber.Ctx) error {
	return c.Next()
}

func CheckPermissions() fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := helpers.GetUserID(c)

		if helpers.HasPermission(id, c.Path(), c.Method()) {
			return c.Next()
		}

		return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorEndpointPermissions",
					Other: "You are not allowed to access this resource.",
				},
			}, c)},
		})
	}
}

func AuthLimiter() fiber.Handler {
	cfg := limiter.Config{
		Max:        25,
		Expiration: 5 * time.Minute,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(&fiber.Map{"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorEndpointRateLimited",
					Other: "Too many requests received within a short amount of time.",
				},
			}, c)}})
		},
	}

	return limiter.New(cfg)
}

func ValidateMFA() fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := helpers.GetUserID(c)
		user := &models.User{ID: userID}
		if err := app.DB().Where(&user).First(&user).Error; err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(&fiber.Map{
				"error": []string{app.Translate(&i18n.LocalizeConfig{
					DefaultMessage: &i18n.Message{
						ID:    "ErrorInvalidUserData",
						Other: "The user data is invalid.",
					},
				}, c)},
			})
		}

		if user.MFAEnabled {
			mfaCode := c.FormValue("mfa_code")
			if !totp.Validate(mfaCode, *user.MFASecret) {
				return c.Status(fiber.StatusUnauthorized).JSON(&fiber.Map{
					"error": []string{app.Translate(&i18n.LocalizeConfig{
						DefaultMessage: &i18n.Message{
							ID:    "ErrorInvalidMFACode",
							Other: "Invalid multi-factor authentication code.",
						},
					}, c)},
				})
			}
		}

		return c.Next()
	}
}
