package controllers

import (
	"time"

	"alfredoramos.mx/csp-reporter/internal/app"
	"alfredoramos.mx/csp-reporter/internal/models"
	"github.com/gofiber/fiber/v2"
	"github.com/nicksnyder/go-i18n/v2/i18n"
)

type apiReportsByDirective struct {
	Year      int        `json:"year"`
	Month     time.Month `json:"month"`
	Directive string     `json:"directive"`
	Total     int        `json:"total"`
}

func GetDashboardReportsByEffectiveDirective(c *fiber.Ctx) error {
	data := []apiReportsByDirective{}

	if err := app.DB().Model(&models.Report{}).
		Select("DISTINCT ON (effective_directive) reports.effective_directive AS directive, EXTRACT(YEAR FROM created_at) AS year, EXTRACT(MONTH FROM created_at) AS month, COUNT(*) AS total").
		Where("created_at >= date_trunc('month', CURRENT_DATE) - INTERVAL '11 months'").
		Group("directive, year, month").
		Order("directive ASC, year ASC, month ASC").
		Find(&data).Error; err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{"error": []string{app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorDashboardReportsByDirective",
				Other: "Could not get report stats by directive.",
			},
		}, c)}})
	}

	return c.Status(fiber.StatusOK).JSON(&fiber.Map{"data": data})
}
