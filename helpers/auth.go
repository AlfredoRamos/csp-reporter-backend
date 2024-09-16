package helpers

import (
	"fmt"
	"time"

	"alfredoramos.mx/csp-reporter/jwt"
	"alfredoramos.mx/csp-reporter/models"
	"alfredoramos.mx/csp-reporter/utils"
	"github.com/getsentry/sentry-go"
	jose_jwt "github.com/go-jose/go-jose/v4/jwt"
)

func NewAccessToken(u *models.User) (string, error) {
	roles, err := GetUserRoles(u.ID)
	if err != nil {
		sentry.CaptureException(err)
		return "", fmt.Errorf("User roles error: %w", err)
	}

	issuer, err := utils.GetJwtIssuer()
	if err != nil {
		sentry.CaptureException(err)
		return "", fmt.Errorf("Invalid access token issuer '%s': %w", issuer, err)
	}

	now := time.Now().In(utils.DefaultLocation())

	claims := &utils.CustomJwtClaims{
		Claims: jose_jwt.Claims{
			ID:        utils.HashString(u.ID.String()),
			Issuer:    issuer,
			Subject:   u.ID.String(),
			IssuedAt:  jose_jwt.NewNumericDate(now),
			NotBefore: jose_jwt.NewNumericDate(now),
			Expiry:    jose_jwt.NewNumericDate(now.Add(utils.AccessTokenExpiration())),
		},
		User: utils.UserClaimData{
			ID:        u.ID,
			FirstName: u.FirstName,
			LastName:  u.LastName,
			Email:     u.Email,
			Roles:     roles.Names(),
		},
	}

	jwtStr, err := jose_jwt.Signed(jwt.Signer()).Claims(claims).Serialize()
	if err != nil {
		sentry.CaptureException(err)
		return "", fmt.Errorf("Error generating JWT: %w", err)
	}

	jwe, err := jwt.Encrypter().Encrypt([]byte(jwtStr))
	if err != nil {
		sentry.CaptureException(err)
		return "", fmt.Errorf("Error generating JWE: %w", err)
	}

	jweStr, err := jwe.CompactSerialize()
	if err != nil {
		sentry.CaptureException(err)
		return "", fmt.Errorf("Error generating access token: %w", err)
	}

	return jweStr, nil
}

func NewRefreshToken(u *models.User) (string, error) {
	roles, err := GetUserRoles(u.ID)
	if err != nil {
		sentry.CaptureException(err)
		return "", fmt.Errorf("User roles error: %w", err)
	}

	issuer, err := utils.GetJwtIssuer()
	if err != nil {
		sentry.CaptureException(err)
		return "", fmt.Errorf("Invalid refresh token issuer '%s': %w", issuer, err)
	}

	now := time.Now().In(utils.DefaultLocation())

	claims := &utils.CustomJwtClaims{
		Claims: jose_jwt.Claims{
			ID:        utils.HashString(u.ID.String()),
			Issuer:    issuer,
			Subject:   u.ID.String(),
			IssuedAt:  jose_jwt.NewNumericDate(now),
			NotBefore: jose_jwt.NewNumericDate(now),
			Expiry:    jose_jwt.NewNumericDate(now.Add(utils.RefreshTokenExpiration())),
		},
		User: utils.UserClaimData{
			ID:    u.ID,
			Email: u.Email,
			Roles: roles.Names(),
		},
	}

	jwtStr, err := jose_jwt.Signed(jwt.Signer()).Claims(claims).Serialize()
	if err != nil {
		sentry.CaptureException(err)
		return "", fmt.Errorf("Error generating JWT: %w", err)
	}

	jwe, err := jwt.Encrypter().Encrypt([]byte(jwtStr))
	if err != nil {
		sentry.CaptureException(err)
		return "", fmt.Errorf("Error generating JWE: %w", err)
	}

	jweStr, err := jwe.CompactSerialize()
	if err != nil {
		sentry.CaptureException(err)
		return "", fmt.Errorf("Error generating refresh token: %w", err)
	}

	return jweStr, nil
}
