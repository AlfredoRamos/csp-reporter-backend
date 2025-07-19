package controllers

import (
	"database/sql"
	"log/slog"

	"alfredoramos.mx/csp-reporter/internal/app"
	"alfredoramos.mx/csp-reporter/internal/helpers"
	"alfredoramos.mx/csp-reporter/internal/models"
	"alfredoramos.mx/csp-reporter/internal/tasks"
	"alfredoramos.mx/csp-reporter/internal/utils"
	"github.com/getsentry/sentry-go"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"gorm.io/gorm"
)

type userActivationInput struct {
	Approved *bool   `json:"approved"`
	Reason   *string `json:"reason"`
}

// GetAllInactiveUsers godoc
// @id api.activations.users.index
// @summary List all inactive users pending activation
// @security bearerauth
// @tags User activation
// @produce json
// @success 204 {object} map[string]string
// @router /activations/users/all [get]
func GetAllInactiveUsers(c *fiber.Ctx) error {
	users := []models.UserActivation{}
	query := app.DB().Model(&models.UserActivation{}).
		Joins("INNER JOIN users u ON user_activations.user_id = u.id").
		Where("u.deleted_at IS NULL").
		Preload("User").Preload("ReviewedBy")
	opts := helpers.PaginatedItemOpts{RouteName: "api.activations.users.index", TableAlias: helpers.GetModelSchema(&models.UserActivation{}).Table}

	return helpers.PaginateQuery(users, query, c, opts)
}

// GetAllInactiveUsers godoc
// @id api.activations.review
// @summary Review user activation
// @security bearerauth
// @tags User activation
// @produce json
// @success 204 {object} map[string]string
// @router /activations/review/{id} [patch]
// @param id path string true "User UUID"
func UpdateUserActivation(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil || !utils.IsValidUuid(id) {
		slog.Error("Error parsing ID", slog.Any("error", err))
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorInvalidUserData",
					Other: "The user data is invalid.",
				},
			}, c)},
		})
	}

	input := &userActivationInput{}
	if err := c.BodyParser(&input); err != nil {
		slog.Error("Error parsing input data", slog.Any("error", err))
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorInvalidActivationUserData",
					Other: "The activation user data is invalid.",
				},
			}, c)},
		})
	}

	user := &models.User{ID: id}
	if err := app.DB().Where(&user).First(&user).Error; err != nil {
		slog.Error("Error getting user", slog.Any("error", err))
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorInvalidUserData",
					Other: "The user data is invalid.",
				},
			}, c)},
		})
	}

	if utils.IsValidUuid(user.ID) && (user.Active != nil && *user.Active) {
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorAlreadyActiveUser",
					Other: "The requested user account is already active.",
				},
			}, c)},
		})
	}

	approved := input.Approved != nil && *input.Approved
	errs := fiber.Map{}

	if !approved && input.Reason != nil && len(*input.Reason) < 1 {
		errs = utils.AddError(errs, "reason", app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorInvalidRejectionReason",
				Other: "Please, provide a reason for rejection.",
			},
		}, c))
	}

	if len(errs) > 0 {
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": errs,
		})
	}

	userID := helpers.GetUserID(c)
	userActivation := &models.UserActivation{UserID: user.ID}

	if err := app.DB().Transaction(func(tx *gorm.DB) error {
		if err := tx.Where(&userActivation).Preload("User").First(&userActivation).Error; err != nil {
			slog.Error("Error getting user account pending activation", slog.Any("error", err))
			return err
		}

		if err := tx.Model(&userActivation).Updates(&models.UserActivation{Approved: &approved, ReviewedByID: &userID}).Error; err != nil {
			slog.Error("Error updating user account activation status", slog.Any("error", err))
			return err
		}

		if err := tx.Where(&models.User{ID: userActivation.User.ID}).Updates(&models.User{Active: &approved}).Error; err != nil {
			slog.Error("Error updating user account status", slog.Any("error", err))
			return err
		}

		if approved {
			role := &models.Role{}
			if err := tx.Where("unaccent(lower(name)) = unaccent(lower(@name))", sql.Named("name", "viewer")).First(&role).Error; err != nil {
				slog.Error("Error getting user role", slog.Any("error", err))
				return err
			}

			userRole := &models.UserRole{
				UserID:      userActivation.User.ID,
				RoleID:      role.ID,
				CreatedByID: userID,
				UpdatedByID: userID,
			}
			if err := tx.Where(&models.UserRole{UserID: userActivation.User.ID, RoleID: role.ID}).FirstOrCreate(&userRole).Error; err != nil {
				slog.Error("Error assigning user role", slog.Any("error", err))
				return err
			}
		} else {
			if err := tx.Delete(&userActivation.User).Error; err != nil {
				slog.Error("Error deleting user account", slog.Any("error", err))
				return err
			}

			if err := tx.Where(&models.UserRole{UserID: userActivation.UserID}).Delete(&models.UserRole{}).Error; err != nil {
				slog.Error("Error deleting user roles", slog.Any("error", err))
				return err
			}
		}

		return nil
	}); err != nil {
		slog.Error("Error activating user account", slog.Any("error", err))

		return c.Status(fiber.StatusInternalServerError).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorUserActivation",
					Other: "Could not activate user account.",
				},
			}, c)},
		})
	}

	data := map[string]interface{}{
		"UserName": user.GetFullName(),
		"Approved": approved,
	}

	if !approved {
		data["RejectionReason"] = userActivation.Reason
	}

	if err := tasks.NewEmail(&helpers.EmailOpts{
		Subject:      "User account registration status",
		TemplateName: "signup_user_status",
		ToList:       []string{userActivation.User.Email},
		Locale:       helpers.ParseApiLocale(c),
	}, data); err != nil {
		sentry.CaptureException(err)
		return err
	}

	return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
}
