package controllers

import (
	"database/sql"
	"fmt"
	"log/slog"

	"alfredoramos.mx/csp-reporter/internal/app"
	"alfredoramos.mx/csp-reporter/internal/helpers"
	"alfredoramos.mx/csp-reporter/internal/models"
	"alfredoramos.mx/csp-reporter/internal/utils"
	"github.com/gofiber/fiber/v2"
	"github.com/nicksnyder/go-i18n/v2/i18n"
)

type siteInput struct {
	Title  *string `json:"title"`
	Domain string  `json:"domain"`
}

func GetAllSites(c *fiber.Ctx) error {
	sites := []models.Site{}
	query := app.DB().Model(&models.Site{})
	opts := helpers.PaginatedItemOpts{RouteName: "api.sites.index"}

	return helpers.PaginateQuery(sites, query, c, opts)
}

func PostSite(c *fiber.Ctx) error {
	input := siteInput{}
	if err := c.BodyParser(&input); err != nil {
		slog.Error(fmt.Sprintf("Error parsing input data: %v", err))
		return c.Status(fiber.StatusOK).JSON(&fiber.Map{"error": []string{app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorInvalidSiteData",
				Other: "The site data is invalid.",
			},
		}, c)}})
	}

	errs := fiber.Map{}

	if len(input.Domain) < 1 {
		errs = utils.AddError(errs, "domain", "Please, enter a domain.")
	} else {
		d, err := utils.GetApexDomain(input.Domain)
		if err != nil {
			slog.Error(fmt.Sprintf("Error getting apex domain: %v", err))
			errs = utils.AddError(errs, "domain", app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorInvalidDomain",
					Other: "Please, enter a valid domain.",
				},
			}, c))
		}

		input.Domain = d
	}

	if len(errs) > 0 {
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": errs,
		})
	}

	site := &models.Site{Title: input.Title, Domain: input.Domain}
	if err := app.DB().Where("unaccent(lower(domain)) = unaccent(lower(@domain))", sql.Named("domain", input.Domain)).
		FirstOrCreate(&site).Error; err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{"error": []string{app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorSiteCreation",
				Other: "Could not register site.",
			},
		}, c)}})
	}

	return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
}
