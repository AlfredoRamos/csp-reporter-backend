package controllers

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"time"

	"alfredoramos.mx/csp-reporter/internal/app"
	"alfredoramos.mx/csp-reporter/internal/cache"
	"alfredoramos.mx/csp-reporter/internal/env"
	csperrors "alfredoramos.mx/csp-reporter/internal/errors"
	"alfredoramos.mx/csp-reporter/internal/helpers"
	"alfredoramos.mx/csp-reporter/internal/models"
	"alfredoramos.mx/csp-reporter/internal/tasks"
	"alfredoramos.mx/csp-reporter/internal/utils"
	"github.com/getsentry/sentry-go"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/valkey-io/valkey-go"
	"gorm.io/gorm"
)

const maxRecoveryTries int = 3

type userLoginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"` // #nosec G117 -- Password is not stored
}

type userRegisterInput struct {
	FirstName       *string `json:"first_name,omitempty"`
	LastName        *string `json:"last_name,omitempty"`
	Email           string  `json:"email"`
	Password        string  `json:"password"` // #nosec G117 -- Password is hashed
	ConfirmPassword string  `json:"confirm_password"`
}

type userRecoveryInput struct {
	Hash            string `json:"hash"`
	Password        string `json:"password"` // #nosec G117 -- Password is hashed and not stored
	ConfirmPassword string `json:"confirm_password"`
}

// AuthLogin godoc
// @id api.auth.login
// @summary User login
// @tags Auth
// @accept json
// @produce json
// @success 204 {object} map[string]string
// @router /auth/login [post]
// @param email body string true "Email" SchemaExample({\r\n\t"email": "name@server.tld"\r\n})
// @param password body string true "Password" SchemaExample({\r\n\t"password": "4sUp3rS3cUr3P4$$w0rD"\r\n})
func AuthLogin(c *fiber.Ctx) error {
	input := &userLoginInput{}
	if err := c.BodyParser(&input); err != nil {
		slog.Error("Error parsing input data", slog.Any("error", err))

		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorInvalidUserData",
					Other: "The user data is invalid.",
				},
			}, c)},
		})
	}

	errs := fiber.Map{}

	if !utils.IsValidEmail(input.Email) {
		errs = utils.AddError(errs, "email", app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorInvalidEmail",
				Other: "Please, enter a valid email address.",
			},
		}, c))
	}

	if len(input.Password) < utils.MinimumPasswordLength() {
		errs = utils.AddError(errs, "password", app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorShortPassword",
				Other: "The password must be at least {{.MinLength}} characters long.",
			},
			TemplateData: map[string]any{
				"MinLength": utils.MinimumPasswordLength(),
			},
		}, c))
	}

	if len(errs) > 0 {
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": errs,
		})
	}

	active := true
	user := &models.User{Email: input.Email, Active: &active}
	if err := app.DB().Where(&user).First(&user).Error; err != nil || !utils.ComparePasswordHash(input.Password, user.Password) {
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorInvalidUserCredentials",
					Other: "The user credentials are invalid.",
				},
			}, c)},
		})
	}

	if utils.MustRehashPassword(user.Password) {
		user.Password = utils.HashPassword(input.Password)
		if err := app.DB().Where(&models.User{ID: user.ID, Email: user.Email}).Updates(&models.User{Password: user.Password}).Error; err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
				"error": []string{app.Translate(&i18n.LocalizeConfig{
					DefaultMessage: &i18n.Message{
						ID:    "ErrorPasswordUpdate",
						Other: "Could not update user password.",
					},
				}, c)},
			})
		}
	}

	accessToken, err := helpers.NewAccessToken(user)
	if err != nil {
		sentry.CaptureException(err)
		slog.Error("Error generating access token", slog.Any("error", err))
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorAccessTokenGeneration",
					Other: "Could not generate access token.",
				},
			}, c)},
		})
	}

	refreshToken, err := helpers.NewRefreshToken(user)
	if err != nil {
		sentry.CaptureException(err)
		slog.Error("Error generating refresh token", slog.Any("error", err))
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorRefreshTokenGeneration",
					Other: "Could not generate refresh token.",
				},
			}, c)},
		})
	}

	refreshClaims, err := utils.ParseJWEClaims(refreshToken)
	if err != nil {
		sentry.CaptureException(err)
		slog.Error("Invalid refresh token claims", slog.Any("error", err))

		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorInvalidRefreshToken",
					Other: "Invalid refresh token.",
				},
			}, c)},
		})
	}

	c.Cookie(&fiber.Cookie{
		Name:        utils.RefreshTokenContextKey(),
		Value:       refreshToken,
		Path:        "/",
		Domain:      env.String("COOKIE_DOMAIN"),
		Expires:     refreshClaims.Expiry.Time(),
		Secure:      env.IsProduction(),
		HTTPOnly:    true,
		SameSite:    "Strict",
		SessionOnly: true,
	})

	return c.Status(fiber.StatusOK).JSON(&fiber.Map{"access_token": accessToken})
}

// AuthCheck godoc
// @id api.auth.check
// @summary Check if user is valid
// @security bearerauth
// @tags Auth
// @accept json
// @produce json
// @success 204 {object} map[string]string
// @router /auth/check [post]
func AuthCheck(c *fiber.Ctx) error {
	// * Real validation is handled with middlewares
	return c.Status(fiber.StatusOK).JSON(&fiber.Map{
		"message": []string{app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "SuccessfulAuthCheck",
				Other: "Successful authentication.",
			},
		}, c)},
	})
}

// AuthRefresh godoc
// @id api.auth.refresh
// @summary Generate a new access token with a refresh token
// @security bearerauth
// @tags Auth
// @accept json
// @produce json
// @success 204 {object} map[string]string
// @router /auth/refresh [patch]
func AuthRefresh(c *fiber.Ctx) error {
	accessJWE := c.Locals(utils.AccessTokenContextKey()).(string)
	accessJWEClaims, err := utils.ParseJWEClaims(accessJWE)
	if err != nil {
		sentry.CaptureException(err)
		slog.Error("Invalid access token claims", slog.Any("error", err))

		return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorInvalidAccessToken",
					Other: "Invalid access token.",
				},
			}, c)},
		})
	}

	refreshJWE := c.Cookies(utils.RefreshTokenContextKey())
	refreshJWEClaims, err := utils.ParseJWEClaims(refreshJWE)
	if err != nil {
		sentry.CaptureException(err)
		slog.Error("Invalid refresh token claims", slog.Any("error", err))

		return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorInvalidRefreshToken",
					Other: "Invalid refresh token.",
				},
			}, c)},
		})
	}

	isRefreshRevoked, err := app.Cache().DoCache(context.Background(), app.Cache().B().Sismember().Key(cache.Key("refresh-tokens:revoked")).Member(refreshJWEClaims.ID).Cache(), 5*time.Minute).AsBool()
	if err != nil && !errors.Is(err, valkey.Nil) {
		sentry.CaptureException(err)
		slog.Error(
			"Could not check token revocation",
			slog.String("token-id", refreshJWEClaims.ID),
			slog.Any("error", err),
		)
	}

	if isRefreshRevoked {
		return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorRevokedRefreshToken",
					Other: "The refresh token has been revoked.",
				},
			}, c)},
		})
	}

	now := time.Now().In(utils.DefaultLocation())
	isProduction := env.IsProduction()

	if now.Before(refreshJWEClaims.IssuedAt.Time()) || now.Before(refreshJWEClaims.NotBefore.Time()) || now.After(refreshJWEClaims.Expiry.Time()) {
		defer c.Locals(utils.AccessTokenContextKey(), nil)
		c.ClearCookie(utils.RefreshTokenContextKey())
		c.Cookie(&fiber.Cookie{
			Name:        utils.RefreshTokenContextKey(),
			Path:        "/",
			Domain:      env.String("COOKIE_DOMAIN"),
			Expires:     time.Now().In(utils.DefaultLocation()).Add(-1 * time.Hour),
			Secure:      isProduction,
			HTTPOnly:    true,
			SameSite:    "Strict",
			SessionOnly: true,
		})

		return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorInvalidRefreshTokenTime",
					Other: "The refresh token is no longer valid.",
				},
			}, c)},
		})
	}

	userID := helpers.GetUserID(c)
	active := true
	user := &models.User{ID: userID, Active: &active}
	if err := app.DB().Where(&user).First(&user).Error; err != nil {
		slog.Error("Error getting user information", slog.Any("error", err))
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorInvalidUserData",
					Other: "The user data is invalid.",
				},
			}, c)},
		})
	}

	if !utils.IsValidUuid(refreshJWEClaims.User.ID) || refreshJWEClaims.User.ID != userID || refreshJWEClaims.User.ID != user.ID {
		return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorInvalidUserData",
					Other: "The user data is invalid.",
				},
			}, c)},
		})
	}

	errs := []error{}
	cmds := valkey.Commands{
		app.Cache().B().Sadd().Key(cache.Key("access-tokens:revoked")).Member(accessJWEClaims.ID).Build(),
		app.Cache().B().Sadd().Key(cache.Key("refresh-tokens:revoked")).Member(refreshJWEClaims.ID).Build(),
	}

	for _, res := range app.Cache().DoMulti(context.Background(), cmds...) {
		if err := res.Error(); err != nil && !errors.Is(err, valkey.Nil) {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		slog.Error("Error revoking access and refresh tokens", slog.Any("error", errors.Join(errs...)))
	}

	accessToken, err := helpers.NewAccessToken(user)
	if err != nil {
		sentry.CaptureException(err)
		slog.Error("Error generating access token", slog.Any("error", err))
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorAccessTokenGeneration",
					Other: "Could not generate access token.",
				},
			}, c)},
		})
	}

	refreshToken, err := helpers.NewRefreshToken(user)
	if err != nil {
		sentry.CaptureException(err)
		slog.Error("Error generating refresh token", slog.Any("error", err))
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorRefreshTokenGeneration",
					Other: "Could not generate refresh token.",
				},
			}, c)},
		})
	}

	refreshClaims, err := utils.ParseJWEClaims(refreshToken)
	if err != nil {
		sentry.CaptureException(err)
		slog.Error("Invalid refresh token claims", slog.Any("error", err))

		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorInvalidRefreshToken",
					Other: "Invalid refresh token.",
				},
			}, c)},
		})
	}

	c.Cookie(&fiber.Cookie{
		Name:        utils.RefreshTokenContextKey(),
		Value:       refreshToken,
		Path:        "/",
		Domain:      env.String("COOKIE_DOMAIN"),
		Expires:     refreshClaims.Expiry.Time(),
		Secure:      isProduction,
		HTTPOnly:    true,
		SameSite:    "Strict",
		SessionOnly: true,
	})

	return c.Status(fiber.StatusOK).JSON(&fiber.Map{"access_token": accessToken})
}

// AuthRegister godoc
// @id api.auth.register
// @summary User registration
// @tags Auth
// @accept json
// @produce json
// @success 204 {object} map[string]string
// @router /auth/register [post]
// @param first_name body string false "First name" SchemaExample({\r\n\t"first_name": "John"\r\n})
// @param last_name body string false "Last name" SchemaExample({\r\n\t"last_name": "Doe"\r\n})
// @param email body string true "Email" SchemaExample({\r\n\t"email": "name@server.tld"\r\n})
// @param password body string true "Password" SchemaExample({\r\n\t"password": "4sUp3rS3cUr3P4$$w0rD"\r\n})
// @param confirm_password body string true "Password confirmation" SchemaExample({\r\n\t"confirm_password": "4sUp3rS3cUr3P4$$w0rD"\r\n})
func AuthRegister(c *fiber.Ctx) error {
	if !utils.CanRegisterUsers() {
		return c.Status(fiber.StatusUnauthorized).JSON(&fiber.Map{"error": []string{app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorUserRegistrationDisabled",
				Other: "User registration is disabled.",
			},
		}, c)}})
	}

	input := &userRegisterInput{}
	if err := c.BodyParser(&input); err != nil {
		slog.Error("Error parsing input data", slog.Any("error", err))

		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorInvalidUserData",
					Other: "The user data is invalid.",
				},
			}, c)},
		})
	}

	errs := fiber.Map{}

	if !utils.IsValidEmail(input.Email) {
		errs = utils.AddError(errs, "email", app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorInvalidEmail",
				Other: "Please, enter a valid email address.",
			},
		}, c))
	}

	if !utils.IsRealEmail(input.Email) {
		errs = utils.AddError(errs, "email", app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorNotRealEmail",
				Other: "Please, enter a real email address.",
			},
		}, c))
	}

	user := &models.User{Email: input.Email}
	if err := app.DB().Unscoped().Where(&user).First(&user).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		slog.Error("Error creating user account", slog.Any("error", err))

		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{"error": []string{app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorUserRegistration",
				Other: "Could not create user account.",
			},
		}, c)}})
	}

	if utils.IsValidUuid(user.ID) {
		if deletedAt, _ := user.DeletedAt.Value(); deletedAt != nil {
			errs = utils.AddError(errs, "email", app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorInactiveUser",
					Other: "The requested user is inactive.",
				},
			}, c))
		} else if user.Active != nil && *user.Active {
			errs = utils.AddError(errs, "email", app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorUserEmailTaken",
					Other: "This email address has been taken.",
				},
			}, c))
		} else {
			errs = utils.AddError(errs, "email", app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorUserEmailPendingValidation",
					Other: "A user with this email address is already waiting for validation.",
				},
			}, c))
		}
	}

	if len(input.Password) < utils.MinimumPasswordLength() {
		errs = utils.AddError(errs, "password", app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorShortPassword",
				Other: "The password must be at least {{.MinLength}} characters long.",
			},
			TemplateData: map[string]any{
				"MinLength": utils.MinimumPasswordLength(),
			},
		}, c))
	} else if input.Password != input.ConfirmPassword {
		errs = utils.AddError(errs, "confirm_password", app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorPasswordDoNotMatch",
				Other: "The passwords do not match.",
			},
		}, c))
	}

	if strong, err := utils.ValidatePasswordStrength(input.Password, []string{strings.Split(input.Email, "@")[0]}); env.IsProduction() && !strong && err != nil {
		sentry.CaptureException(err)

		msg := ""

		switch {
		case errors.Is(err, csperrors.ErrAuthShortPassword):
			msg = app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorShortPassword",
					Other: "The password must be at least {{.MinLength}} characters long.",
				},
				TemplateData: map[string]any{
					"MinLength": utils.MinimumPasswordLength(),
				},
			}, c)

		case errors.Is(err, csperrors.ErrAuthWeakPassword):
			msg = app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorWeakPassword",
					Other: "The password strength score is low. Use lowercase and uppercase letters, numbers and symbols.",
				}}, c)

		case errors.Is(err, csperrors.ErrAuthLowEntropyPassword):
			msg = app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorLowEntropyPassword",
					Other: "The password entropy is low. Avoid using very common phrases and replace some letters with lowercase or uppercase letters, numbers and symbols.",
				}}, c)

		default: // ! Must not get here
			msg = app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorInvalidPassword",
					Other: "The password is invalid.",
				}}, c)
		}

		errs = utils.AddError(errs, "password", msg)
	}

	if input.FirstName != nil && len(*input.FirstName) > 100 {
		errs = utils.AddError(errs, "first_name", app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorLongFirstName",
				Other: "Your first name is longer than the length allowed.",
			},
		}, c))
	}

	if input.LastName != nil && len(*input.LastName) > 100 {
		errs = utils.AddError(errs, "last_name", app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorLongLastName",
				Other: "Your last name is longer than the length allowed.",
			},
		}, c))
	}

	if len(errs) > 0 {
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": errs,
		})
	}

	if err := app.DB().Transaction(func(tx *gorm.DB) error {
		user = &models.User{
			FirstName: input.FirstName,
			LastName:  input.LastName,
			Email:     input.Email,
			Password:  utils.HashPassword(input.Password),
		}
		if err := tx.Create(&user).Error; err != nil {
			return err
		}

		userActivation := &models.UserActivation{UserID: user.ID}
		if err := tx.Where(&userActivation).FirstOrCreate(&userActivation).Error; err != nil {
			return err
		}

		return nil
	}); err != nil {
		slog.Error("Error creating user account", slog.Any("error", err))

		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorUserRegistration",
					Other: "Could not create user account.",
				},
			}, c)},
		})
	}

	userName := user.GetFullName()

	timer := time.AfterFunc(3*time.Second, func() {
		if err := tasks.NewEmail(
			&helpers.EmailOpts{
				Subject: app.Translate(&i18n.LocalizeConfig{
					DefaultMessage: &i18n.Message{
						ID:    "EmailAdminNewRegistration",
						Other: "New user registration",
					},
				}, c),
				TemplateName: "signup_admin",
				ToList:       []string{utils.SupportEmail()},
				Locale:       helpers.ParseApiLocale(c),
			},
			map[string]any{
				"UserName":  userName,
				"UserEmail": user.Email,
			},
		); err != nil {
			sentry.CaptureException(err)
			slog.Error("Error sending email", slog.Any("error", err))
		}
	})
	defer timer.Stop()

	if err := tasks.NewEmail(
		&helpers.EmailOpts{
			Subject: app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "EmailUserNewRegistration",
					Other: "User account registration request",
				},
			}, c),
			TemplateName: "signup_user",
			ToList:       []string{user.Email},
			Locale:       helpers.ParseApiLocale(c),
		},
		map[string]any{
			"UserName": userName,
		},
	); err != nil {
		sentry.CaptureException(err)
		slog.Error("Error sending email", slog.Any("error", err))
	}

	return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
}

// AuthLogout godoc
// @id api.auth.logout
// @summary User logout
// @security bearerauth
// @tags Auth
// @accept json
// @produce json
// @success 204
// @router /auth/logout [post]
func AuthLogout(c *fiber.Ctx) error {
	accessJWE := c.Locals(utils.AccessTokenContextKey()).(string)
	accessJWEClaims, err := utils.ParseJWEClaims(accessJWE)
	if err != nil {
		sentry.CaptureException(err)
		slog.Error("Invalid access token claims", slog.Any("error", err))

		return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorInvalidAccessToken",
					Other: "Invalid access token.",
				},
			}, c)},
		})
	}

	refreshJWE := c.Cookies(utils.RefreshTokenContextKey())
	refreshJWEClaims, err := utils.ParseJWEClaims(refreshJWE)
	if err != nil {
		sentry.CaptureException(err)
		slog.Error("Invalid refresh token claims", slog.Any("error", err))

		return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorInvalidRefreshToken",
					Other: "Invalid refresh token.",
				},
			}, c)},
		})
	}

	defer c.Locals(utils.AccessTokenContextKey(), nil)
	c.ClearCookie(utils.RefreshTokenContextKey())
	c.Cookie(&fiber.Cookie{
		Name:        utils.RefreshTokenContextKey(),
		Path:        "/",
		Domain:      env.String("COOKIE_DOMAIN"),
		Expires:     time.Now().In(utils.DefaultLocation()).Add(-1 * time.Hour),
		Secure:      env.IsProduction(),
		HTTPOnly:    true,
		SameSite:    "Strict",
		SessionOnly: true,
	})

	errs := []error{}
	cmds := valkey.Commands{
		app.Cache().B().Sadd().Key(cache.Key("access-tokens:revoked")).Member(accessJWEClaims.ID).Build(),
		app.Cache().B().Sadd().Key(cache.Key("refresh-tokens:revoked")).Member(refreshJWEClaims.ID).Build(),
	}

	for _, res := range app.Cache().DoMulti(context.Background(), cmds...) {
		if err := res.Error(); err != nil && !errors.Is(err, valkey.Nil) {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		slog.Error("Error revoking access and refresh tokens", slog.Any("error", errors.Join(errs...)))
	}

	return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
}

// AuthRecover godoc
// @id api.auth.recover
// @summary Send password recovery email
// @tags Auth
// @accept json
// @produce json
// @success 204 {object} map[string]string
// @router /auth/recover [post]
// @param email body string true "User email" SchemaExample({\r\n\t"email": "name@server.tld"\r\n})
func AuthRecover(c *fiber.Ctx) error {
	input := &userLoginInput{}
	if err := c.BodyParser(&input); err != nil {
		slog.Error("Error parsing input data", slog.Any("error", err))

		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorInvalidUserData",
					Other: "The user data is invalid.",
				},
			}, c)},
		})
	}

	errs := fiber.Map{}

	if !utils.IsValidEmail(input.Email) {
		errs = utils.AddError(errs, "email", app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorInvalidEmail",
				Other: "Please, enter a valid email address.",
			},
		}, c))
	}

	if !utils.IsRealEmail(input.Email) {
		errs = utils.AddError(errs, "email", app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorNotRealEmail",
				Other: "Please, enter a real email address.",
			},
		}, c))
	}

	if len(errs) > 0 {
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{"error": errs})
	}

	now := time.Now().In(utils.DefaultLocation())

	if err := app.DB().Transaction(func(tx *gorm.DB) error {
		active := true
		user := &models.User{Email: input.Email, Active: &active}
		if err := tx.Where(&user).First(&user).Error; err != nil {
			return err
		}

		tries := []uuid.UUID{}
		if err := tx.Model(&models.AccountRecovery{}).Unscoped().
			Where("user_id = @user_id AND expires_at > @now", sql.Named("user_id", user.ID), sql.Named("now", now.Format("2006-01-02 15:04:05.000 -0700"))).
			Limit(maxRecoveryTries).Preload("User").Select("id").
			Find(&tries).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}

		lastChange := time.Duration(0)

		if user.LastPasswordChange != nil {
			lastChange = now.Sub(*user.LastPasswordChange)
		}

		if len(tries) >= maxRecoveryTries && lastChange.Hours() > 1 {
			password, err := utils.RandomPassword(35)
			if err != nil {
				return err
			}

			if err := tx.Model(&user).Updates(&models.User{
				Password:           utils.HashPassword(password),
				LastPasswordChange: &now,
			}).Error; err != nil {
				slog.Error("Error updating user account information", slog.Any("error", err))
				return err
			}
		}

		if err := tx.Model(&models.AccountRecovery{}).
			Where("id IN @recovery_list", sql.Named("recovery_list", tries)).
			Delete(&models.AccountRecovery{}).Error; err != nil {
			slog.Error("Error deleting previous recovery tries", slog.Any("error", err))
			return err
		}

		randomString, err := utils.RandomString(35)
		if err != nil || len(randomString) < 1 {
			slog.Error("Error generating random string", slog.Any("error", err))
			return err
		}

		recovery := &models.AccountRecovery{
			Hash:      randomString,
			UserID:    user.ID,
			ExpiresAt: now.Add(6 * time.Hour),
		}
		if err := tx.Create(&recovery).Error; err != nil {
			return err
		}

		if err := tasks.NewEmail(
			&helpers.EmailOpts{
				Subject: app.Translate(&i18n.LocalizeConfig{
					DefaultMessage: &i18n.Message{
						ID:    "EmailPasswordRecoveryRequest",
						Other: "Password change request",
					},
				}, c),
				TemplateName: "user_password_change_request",
				ToList:       []string{user.Email},
				Locale:       helpers.ParseApiLocale(c),
			},
			map[string]any{
				"UserName":    user.GetFullName(),
				"RecoveryURL": recovery.URL(),
			},
		); err != nil {
			sentry.CaptureException(err)
			slog.Error("Error sending email", slog.Any("error", err))
		}

		return nil
	}); err != nil {
		slog.Error("Error recovering user account", slog.Any("error", err))

		return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
	}

	return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
}

// AuthRecoverValidate godoc
// @id api.auth.recover.validate
// @summary Validate password recovery token
// @tags Auth
// @accept json
// @produce json
// @success 204 {object} map[string]string
// @router /auth/recover/validate [post]
// @param hash body string true "Recovery hash" SchemaExample({\r\n\t"hash": "xp7GESkD3Dzbm4Pb3Mtn8xc453KHJeXQvdN"\r\n})
func AuthRecoverValidate(c *fiber.Ctx) error {
	input := &userRecoveryInput{}
	if err := c.BodyParser(&input); err != nil {
		slog.Error("Error parsing input data", slog.Any("error", err))

		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorInvalidRecoveryData",
					Other: "The recovery data is invalid.",
				},
			}, c)},
		})
	}

	errs := fiber.Map{}

	if len(input.Hash) != 35 {
		errs = utils.AddError(errs, "hash", app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorInvalidRecoveryURL",
				Other: "The URL for account recovery is invalid.",
			},
		}, c))
	}

	if len(errs) > 0 {
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{"error": errs})
	}

	now := time.Now().In(utils.DefaultLocation())
	recovery := &models.AccountRecovery{Hash: input.Hash}
	active := true

	if err := app.DB().Model(&models.AccountRecovery{}).
		Joins("LEFT JOIN users u ON account_recoveries.user_id = u.id").
		Where(&recovery).
		Where("account_recoveries.expires_at > @now", sql.Named("now", now.Format("2006-01-02 15:04:05.000 -0700"))).
		Where("u.active = @active AND u.deleted_at IS NULL", sql.Named("active", &active)).
		Order("account_recoveries.created_at DESC").First(&recovery).Error; err != nil {
		slog.Error("Error validating hash for password recovery", slog.Any("error", err))
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{"error": fiber.Map{"hash": []string{app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorInvalidRecoveryURL",
				Other: "The URL for account recovery is invalid.",
			},
		}, c)}}})
	}

	return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
}

// AuthRecoverUpdate godoc
// @id api.auth.recover.update
// @summary Update user password
// @tags Auth
// @accept json
// @produce json
// @success 204 {object} map[string]string
// @router /auth/recover/update [patch]
// @param hash body string true "Recovery hash" SchemaExample({\r\n\t"hash": "xp7GESkD3Dzbm4Pb3Mtn8xc453KHJeXQvdN"\r\n})
// @param password body string true "Password" SchemaExample({\r\n\t"password": "4sUp3rS3cUr3P4$$w0rD"\r\n})
// @param confirm_password body string true "Password confirmation" SchemaExample({\r\n\t"confirm_password": "4sUp3rS3cUr3P4$$w0rD"\r\n})
func AuthRecoverUpdate(c *fiber.Ctx) error {
	input := &userRecoveryInput{}
	if err := c.BodyParser(&input); err != nil {
		slog.Error("Error parsing input data", slog.Any("error", err))

		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorInvalidRecoveryData",
					Other: "The recovery data is invalid.",
				},
			}, c)},
		})
	}

	errs := fiber.Map{}

	if len(input.Hash) != 35 {
		errs = utils.AddError(errs, "hash", app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorInvalidRecoveryURL",
				Other: "The URL for account recovery is invalid.",
			},
		}, c))
	}

	if len(errs) > 0 {
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{"error": errs})
	}

	recovery := &models.AccountRecovery{}
	now := time.Now().In(utils.DefaultLocation())
	active := true

	if err := app.DB().Model(&models.AccountRecovery{}).
		Joins("LEFT JOIN users u ON account_recoveries.user_id = u.id").
		Where(&models.AccountRecovery{Hash: input.Hash}).
		Where("account_recoveries.expires_at > @now", sql.Named("now", now.Format("2006-01-02 15:04:05.000 -0700"))).
		Where("u.active = @active AND u.deleted_at IS NULL", sql.Named("active", &active)).
		Order("account_recoveries.created_at DESC").Preload("User").First(&recovery).Error; err != nil {
		slog.Error("Error validating hash for password recovery", slog.Any("error", err))
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{"error": fiber.Map{"hash": []string{app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorInvalidRecoveryURL",
				Other: "The URL for account recovery is invalid.",
			},
		}, c)}}})
	}

	if len(input.Password) < utils.MinimumPasswordLength() {
		errs = utils.AddError(errs, "password", app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorShortPassword",
				Other: "The password must be at least {{.MinLength}} characters long.",
			},
			TemplateData: map[string]any{
				"MinLength": utils.MinimumPasswordLength(),
			},
		}, c))
	} else if input.Password != input.ConfirmPassword {
		errs = utils.AddError(errs, "confirm_password", app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorPasswordDoNotMatch",
				Other: "The passwords do not match.",
			},
		}, c))
	}

	if strong, err := utils.ValidatePasswordStrength(input.Password, []string{strings.Split(recovery.User.Email, "@")[0]}); env.IsProduction() && !strong && err != nil {
		sentry.CaptureException(err)

		msg := ""

		switch {
		case errors.Is(err, csperrors.ErrAuthShortPassword):
			msg = app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorShortPassword",
					Other: "The password must be at least {{.MinLength}} characters long.",
				},
				TemplateData: map[string]any{
					"MinLength": utils.MinimumPasswordLength(),
				},
			}, c)

		case errors.Is(err, csperrors.ErrAuthWeakPassword):
			msg = app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorWeakPassword",
					Other: "The password strength score is low. Use lowercase and uppercase letters, numbers and symbols.",
				}}, c)

		case errors.Is(err, csperrors.ErrAuthLowEntropyPassword):
			msg = app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorLowEntropyPassword",
					Other: "The password entropy is low. Avoid using very common phrases and replace some letters with lowercase or uppercase letters, numbers and symbols.",
				}}, c)

		default: // ! Must not get here
			msg = app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorInvalidPassword",
					Other: "The password is invalid.",
				}}, c)
		}

		errs = utils.AddError(errs, "password", msg)
	}

	if len(errs) > 0 {
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{"error": errs})
	}

	mustChangePass := false

	if err := app.DB().Transaction(func(tx *gorm.DB) error {
		if err := tx.Where(&models.User{ID: recovery.UserID, Email: recovery.User.Email}).Updates(&models.User{
			Password:           utils.HashPassword(input.Password),
			LastPasswordChange: &now,
			MustChangePassword: &mustChangePass,
		}).Error; err != nil {
			return err
		}

		if err := tx.Where(&models.AccountRecovery{Hash: recovery.Hash, UserID: recovery.UserID}).
			Delete(&models.AccountRecovery{}).Error; err != nil {
			return err
		}

		return nil
	}); err != nil {
		slog.Error("Error updating user password", slog.Any("error", err))

		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{"error": []string{app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorPasswordUpdate",
				Other: "Could not update user password.",
			},
		}, c)}})
	}

	if err := tasks.NewEmail(
		&helpers.EmailOpts{
			Subject: app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "EmailPasswordRecoveryConfirmation",
					Other: "Password change confirmation",
				},
			}, c),
			TemplateName: "user_password_changed",
			ToList:       []string{recovery.User.Email},
			Locale:       helpers.ParseApiLocale(c),
		},
		map[string]any{
			"UserName": recovery.User.GetFullName(),
		},
	); err != nil {
		sentry.CaptureException(err)
		slog.Error("Error sending email", slog.Any("error", err))
	}

	return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
}
