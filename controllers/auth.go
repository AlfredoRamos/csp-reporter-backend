package controllers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"alfredoramos.mx/csp-reporter/app"
	"alfredoramos.mx/csp-reporter/helpers"
	"alfredoramos.mx/csp-reporter/models"
	"alfredoramos.mx/csp-reporter/tasks"
	"alfredoramos.mx/csp-reporter/utils"
	"github.com/getsentry/sentry-go"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const maxRecoveryTries int = 3

type userLoginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type userRegisterInput struct {
	FirstName       *string `json:"first_name,omitempty"`
	LastName        *string `json:"last_name,omitempty"`
	Email           string  `json:"email"`
	Password        string  `json:"password"`
	ConfirmPassword string  `json:"confirm_password"`
}

type userRecoveryInput struct {
	Hash            string `json:"hash"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
}

func AuthLogin(c *fiber.Ctx) error {
	input := &userLoginInput{}
	if err := c.BodyParser(&input); err != nil {
		slog.Error(fmt.Sprintf("Error parsing input data: %v", err))

		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{"The user data is invalid."},
		})
	}

	errs := fiber.Map{}

	if !utils.IsValidEmail(input.Email) {
		errs = utils.AddError(errs, "email", "Please, enter a valid email address.")
	}

	if len(input.Password) < utils.MinimumPasswordLength() {
		errs = utils.AddError(errs, "password", fmt.Sprintf("The password must be at least %d characters long.", utils.MinimumPasswordLength()))
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
			"error": []string{"The user credentials are invalid."},
		})
	}

	jweStr, err := helpers.NewAccessToken(user)
	if err != nil {
		slog.Error(fmt.Sprintf("Error generating access token: %v", err))
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{"Could not generate access token."},
		})
	}

	return c.Status(fiber.StatusOK).JSON(&fiber.Map{"access_token": jweStr})
}

func AuthRegister(c *fiber.Ctx) error {
	if !utils.CanRegisterUsers() {
		return c.Status(fiber.StatusUnauthorized).JSON(&fiber.Map{"error": []string{"User registration is disabled."}})
	}

	input := &userRegisterInput{}
	if err := c.BodyParser(&input); err != nil {
		slog.Error(fmt.Sprintf("Error parsing input data: %v", err))

		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{"Invalid user registration data."},
		})
	}

	errs := fiber.Map{}

	if !utils.IsValidEmail(input.Email) {
		errs = utils.AddError(errs, "email", "Please, enter a valid email address.")
	}

	if !utils.IsRealEmail(input.Email) {
		errs = utils.AddError(errs, "email", "Please, enter a real email address.")
	}

	user := &models.User{Email: input.Email}
	if err := app.DB().Unscoped().Where(&user).First(&user).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		slog.Error(fmt.Sprintf("Error creating user account: %v", err))

		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{"error": []string{"Could not create user account."}})
	}

	if utils.IsValidUuid(user.ID) {
		if deletedAt, _ := user.DeletedAt.Value(); deletedAt != nil {
			errs = utils.AddError(errs, "email", "The requested user is inactive.")
		} else if user.Active != nil && *user.Active {
			errs = utils.AddError(errs, "email", "This email address has been taken.")
		} else {
			errs = utils.AddError(errs, "email", "A user with this email address is already waiting for validation.")
		}
	}

	if len(input.Password) < utils.MinimumPasswordLength() {
		errs = utils.AddError(errs, "password", fmt.Sprintf("The password must be at least %d characters long.", utils.MinimumPasswordLength()))
	} else if input.Password != input.ConfirmPassword {
		errs = utils.AddError(errs, "confirm_password", "The passwords do not match.")
	}

	if strong, err := utils.ValidatePasswordStrength(input.Password, []string{strings.Split(input.Email, "@")[0]}); !utils.IsDebug() && !strong && err != nil {
		sentry.CaptureException(err)
		errs = utils.AddError(errs, "password", err.Error())
	}

	if input.FirstName != nil && len(*input.FirstName) > 100 {
		errs = utils.AddError(errs, "first_name", "Your first name is longer than the length allowed.")
	}

	if input.LastName != nil && len(*input.LastName) > 100 {
		errs = utils.AddError(errs, "last_name", "Your last name is longer than the length allowed.")
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
		slog.Error(fmt.Sprintf("Error creating user account: %v", err))

		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{"Could not create user account."},
		})
	}

	userName := user.GetFullName()

	time.AfterFunc(3*time.Second, func() {
		if err := tasks.NewEmail(
			helpers.EmailOpts{
				Subject:      "New user registration",
				TemplateName: "signup_admin",
				ToList:       []string{utils.SupportEmail()},
			},
			map[string]interface{}{
				"UserName":  userName,
				"UserEmail": user.Email,
			},
		); err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Error sending email: %v", err))
		}
	})

	if err := tasks.NewEmail(
		helpers.EmailOpts{
			Subject:      "User account registration request",
			TemplateName: "signup_user",
			ToList:       []string{user.Email},
		},
		map[string]interface{}{
			"UserName": userName,
		},
	); err != nil {
		sentry.CaptureException(err)
		slog.Error(fmt.Sprintf("Error sending email: %v", err))
	}

	return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
}

func AuthRecover(c *fiber.Ctx) error {
	input := &userLoginInput{}
	if err := c.BodyParser(&input); err != nil {
		slog.Error(fmt.Sprintf("Error parsing input data: %v", err))

		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{"The user data is invalid."},
		})
	}

	errs := fiber.Map{}

	if !utils.IsValidEmail(input.Email) {
		errs = utils.AddError(errs, "email", "Please, enter a valid email address.")
	}

	if !utils.IsRealEmail(input.Email) {
		errs = utils.AddError(errs, "email", "Please, enter a real email address.")
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
				slog.Error(fmt.Sprintf("Error updating user account information: %v", err))
				return err
			}
		}

		if err := tx.Model(&models.AccountRecovery{}).
			Where("id IN @recovery_list", sql.Named("recovery_list", tries)).
			Delete(&models.AccountRecovery{}).Error; err != nil {
			slog.Error(fmt.Sprintf("Error deleting previous recovery tries: %v", err))
			return err
		}

		randomString, err := utils.RandomString(35)
		if err != nil || len(randomString) < 1 {
			slog.Error(fmt.Sprintf("Error generating random string: %v", err))
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
			helpers.EmailOpts{
				Subject:      "Password change request",
				TemplateName: "user_password_change_request",
				ToList:       []string{user.Email},
			},
			map[string]interface{}{
				"UserName":    user.GetFullName(),
				"RecoveryURL": recovery.URL(),
			},
		); err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Error sending email: %v", err))
		}

		return nil
	}); err != nil {
		slog.Error(fmt.Sprintf("Error recovering user account: %v", err))

		return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
	}

	return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
}

func AuthRecoverValidate(c *fiber.Ctx) error {
	input := &userRecoveryInput{}
	if err := c.BodyParser(&input); err != nil {
		slog.Error(fmt.Sprintf("Error parsing input data: %v", err))

		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{"The recovery data is invalid."},
		})
	}

	errs := fiber.Map{}

	if len(input.Hash) != 35 {
		errs = utils.AddError(errs, "hash", "The URL for account recovery is invalid.")
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
		slog.Error(fmt.Sprintf("Error validating hash for password recovery: %v", err))
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{"error": fiber.Map{"hash": []string{"The URL for account recovery is invalid."}}})
	}

	return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
}

func AuthRecoverUpdate(c *fiber.Ctx) error {
	input := &userRecoveryInput{}
	if err := c.BodyParser(&input); err != nil {
		slog.Error(fmt.Sprintf("Error parsing input data: %v", err))

		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{"The recovery data is invalid."},
		})
	}

	errs := fiber.Map{}

	if len(input.Hash) != 35 {
		errs = utils.AddError(errs, "hash", "The URL for account recovery is invalid.")
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
		slog.Error(fmt.Sprintf("Error validating hash for password recovery: %v", err))
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{"error": fiber.Map{"hash": []string{"The URL for account recovery is invalid."}}})
	}

	if len(input.Password) < utils.MinimumPasswordLength() {
		errs = utils.AddError(errs, "password", fmt.Sprintf("The password must be at least %d characters long.", utils.MinimumPasswordLength()))
	} else if input.Password != input.ConfirmPassword {
		errs = utils.AddError(errs, "confirm_password", "The passwords do not match.")
	}

	if strong, err := utils.ValidatePasswordStrength(input.Password, []string{strings.Split(recovery.User.Email, "@")[0]}); !utils.IsDebug() && !strong && err != nil {
		errs = utils.AddError(errs, "password", err.Error())
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
		slog.Error(fmt.Sprintf("Error updating user password: %v", err))

		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{"error": []string{"Could not update user password."}})
	}

	if err := tasks.NewEmail(
		helpers.EmailOpts{
			Subject:      "Password change confirmation",
			TemplateName: "user_password_changed",
			ToList:       []string{recovery.User.Email},
		},
		map[string]interface{}{
			"UserName": recovery.User.GetFullName(),
		},
	); err != nil {
		sentry.CaptureException(err)
		slog.Error(fmt.Sprintf("Error sending email: %v", err))
	}

	return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
}

func AuthCheck(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": []string{"Successful authentication."},
	})
}

func RevokeAccessToken(c *fiber.Ctx) error {
	if len(c.Get("Authorization")) <= 7 {
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{"Invalid access token."},
		})
	}

	tokenStr := c.Get("Authorization")[7:]

	claims, err := utils.ParseJWEClaims(tokenStr)
	if err != nil {
		sentry.CaptureException(err)
		slog.Error(fmt.Sprintf("Invalid access token claims: %v", err))

		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{"Invalid access token"},
		})
	}

	defer c.Locals(utils.TokenContextKey(), nil)

	if len(claims.ID) < 1 {
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{"Invalid access token."},
		})
	}

	if err := app.Cache().Do(context.Background(), app.Cache().B().Sadd().Key("access-tokens:revoked").Member(claims.ID).Build()).Error(); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{"Could not revoke access token."},
		})
	}

	return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
}
