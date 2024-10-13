package controllers

import (
	"database/sql"
	"fmt"
	"log/slog"

	"alfredoramos.mx/csp-reporter/app"
	"alfredoramos.mx/csp-reporter/helpers"
	"alfredoramos.mx/csp-reporter/models"
	"alfredoramos.mx/csp-reporter/utils"
	"github.com/gofiber/fiber/v2"
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
		return c.Status(fiber.StatusOK).JSON(&fiber.Map{"error": []string{"The site data is invalid."}})
	}

	errs := fiber.Map{}

	if len(input.Domain) < 1 {
		errs = utils.AddError(errs, "domain", "Please, enter a domain.")
	} else {
		d, err := utils.GetApexDomain(input.Domain)
		if err != nil {
			slog.Error(fmt.Sprintf("Error getting apex domain: %v", err))
			errs = utils.AddError(errs, "domain", "Please, enter a valid domain.")
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
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{"error": []string{"Could not register site."}})
	}

	return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
}
