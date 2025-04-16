package controllers

import (
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"alfredoramos.mx/csp-reporter/internal/app"
	"alfredoramos.mx/csp-reporter/internal/helpers"
	"alfredoramos.mx/csp-reporter/internal/models"
	"alfredoramos.mx/csp-reporter/internal/tasks"
	"alfredoramos.mx/csp-reporter/internal/utils"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/nicksnyder/go-i18n/v2/i18n"
)

func GetAllCSPReports(c *fiber.Ctx) error {
	reports := []models.Report{}
	query := app.DB().Model(&models.Report{}).Preload("Site")
	opts := helpers.PaginatedItemOpts{RouteName: "api.csp.reports.index"}

	return helpers.PaginateQuery(reports, query, c, opts)
}

func GetCSPReport(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil || !utils.IsValidUuid(id) {
		slog.Error(fmt.Sprintf("Error parsing ID: %v", err))
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorInvalidCSPReport",
					Other: "Invalid Content Security Policy report.",
				},
			}, c)},
		})
	}

	report := &models.Report{ID: id}
	if err := app.DB().Where(&report).Preload("Site").First(&report).Error; err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{"error": []string{app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorInvalidCSPReport",
				Other: "Invalid Content Security Policy report.",
			},
		}, c)}})
	}

	return c.Status(fiber.StatusOK).JSON(&fiber.Map{"data": report})
}

func PostCSPReport(c *fiber.Ctx) error {
	allowedMimeTypes := []string{"application/csp-report", "application/json"}
	accept := c.Accepts(allowedMimeTypes...)
	defaultErr := c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{"errors": []string{app.Translate(&i18n.LocalizeConfig{
		DefaultMessage: &i18n.Message{
			ID:    "ErrorInvalidCSPReport",
			Other: "Invalid Content Security Policy report.",
		},
	}, c)}})

	if !slices.Contains(allowedMimeTypes, accept) {
		slog.Error(fmt.Sprintf("The MIME type '%s' for the 'Accept' header is invalid.", accept))
		return defaultErr
	}

	if strings.EqualFold(string(c.Request().Header.ContentType()), "application/csp-report") {
		c.Request().Header.SetContentType("application/json")
	}

	contentType := string(c.Request().Header.ContentType())

	if !slices.Contains(allowedMimeTypes, contentType) {
		slog.Error(fmt.Sprintf("The MIME type '%s' of the request is invalid.", contentType))
		return defaultErr
	}

	input := helpers.CspReport{}
	if err := c.BodyParser(&input); err != nil {
		slog.Error(fmt.Sprintf("Error parsing input data: %v", err))
		return defaultErr
	}

	if err := tasks.NewCspReport(input); err != nil {
		slog.Error(fmt.Sprintf("Error saving CSP Report: %v", err))
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{"error": []string{app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorCSPReportCreation",
				Other: "Could not register CSP report.",
			},
		}, c)}})
	}

	return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
}
