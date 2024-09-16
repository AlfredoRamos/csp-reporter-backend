package controllers

import (
	"database/sql"
	"fmt"
	"log/slog"

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

type userActivationInput struct {
	Approved *bool   `json:"approved"`
	Reason   *string `json:"reason"`
}

func GetAllInactiveUsers(c *fiber.Ctx) error {
	users := []models.UserActivation{}
	query := app.DB().Model(&models.UserActivation{}).
		Joins("INNER JOIN users u ON user_activations.user_id = u.id").
		Where("u.deleted_at IS NULL").
		Preload("User").Preload("ReviewedBy")
	opts := helpers.PaginatedItemOpts{RouteName: "api.activations.users.index", TableAlias: helpers.GetModelSchema(&models.UserActivation{}).Table}

	return helpers.PaginateQuery(users, query, c, opts)
}

func UpdateUserActivation(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil || !utils.IsValidUuid(id) {
		slog.Error(fmt.Sprintf("Error parsing ID: %v", err))
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{"The requested user is invalid."},
		})
	}

	input := &userActivationInput{}
	if err := c.BodyParser(&input); err != nil {
		slog.Error(fmt.Sprintf("Error parsing input data: %v", err))
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{"Invalid user activation data."},
		})
	}

	user := &models.User{ID: id}
	if err := app.DB().Where(&user).First(&user).Error; err != nil {
		slog.Error(fmt.Sprintf("Error getting user: %v", err))
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{"The requested user is invalid."},
		})
	}

	if utils.IsValidUuid(user.ID) && (user.Active != nil && *user.Active) {
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{"The requested user account is already active."},
		})
	}

	approved := input.Approved != nil && *input.Approved
	errs := fiber.Map{}

	if !approved && input.Reason != nil && len(*input.Reason) < 1 {
		errs = utils.AddError(errs, "reason", "Please, provide a reason for rejection.")
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
			slog.Error(fmt.Sprintf("Error getting user account pending activation: %v", err))
			return err
		}

		if err := tx.Model(&userActivation).Updates(&models.UserActivation{Approved: &approved, ReviewedByID: &userID}).Error; err != nil {
			slog.Error(fmt.Sprintf("Error updating user account activation status: %v", err))
			return err
		}

		if err := tx.Where(&models.User{ID: userActivation.User.ID}).Updates(&models.User{Active: &approved}).Error; err != nil {
			slog.Error(fmt.Sprintf("Error updating user account status: %v", err))
			return err
		}

		if approved {
			role := &models.Role{}
			if err := tx.Where("unaccent(lower(name)) = unaccent(lower(@name))", sql.Named("name", "viewer")).First(&role).Error; err != nil {
				slog.Error(fmt.Sprintf("Error getting user role: %v", err))
				return err
			}

			userRole := &models.UserRole{
				UserID:      userActivation.User.ID,
				RoleID:      role.ID,
				CreatedByID: userID,
				UpdatedByID: userID,
			}
			if err := tx.Where(&models.UserRole{UserID: userActivation.User.ID, RoleID: role.ID}).FirstOrCreate(&userRole).Error; err != nil {
				slog.Error(fmt.Sprintf("Error assigning user role: %v", err))
				return err
			}
		} else {
			if err := tx.Delete(&userActivation.User).Error; err != nil {
				slog.Error(fmt.Sprintf("Error deleting user account: %v", err))
				return err
			}

			if err := tx.Where(&models.UserRole{UserID: userActivation.UserID}).Delete(&models.UserRole{}).Error; err != nil {
				slog.Error(fmt.Sprintf("Error deleting user roles: %v", err))
				return err
			}
		}

		return nil
	}); err != nil {
		slog.Error(fmt.Sprintf("Error activating user account: %v", err))

		return c.Status(fiber.StatusInternalServerError).JSON(&fiber.Map{
			"error": []string{"Could not activate user account."},
		})
	}

	userName := user.GetFullName()
	opts := helpers.EmailOpts{
		Subject:      "User account registration status",
		TemplateName: "signup_user_status",
		ToList:       []string{userActivation.User.Email},
	}
	data := map[string]interface{}{
		"UserName": userName,
		"Approved": approved,
	}

	if !approved {
		data["RejectionReason"] = userActivation.Reason
	}

	if err := tasks.NewEmail(opts, data); err != nil {
		sentry.CaptureException(err)
		return err
	}

	return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
}
