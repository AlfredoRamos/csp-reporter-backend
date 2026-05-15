package controllers

import (
	"database/sql"
	"log/slog"

	"alfredoramos.mx/csp-reporter/internal/app"
	"alfredoramos.mx/csp-reporter/internal/helpers"
	"alfredoramos.mx/csp-reporter/internal/models"
	"alfredoramos.mx/csp-reporter/internal/utils"
	"github.com/gofiber/fiber/v3"
	"github.com/nicksnyder/go-i18n/v2/i18n"
)

type siteInput struct {
	Title  *string `json:"title"`
	Domain string  `json:"domain"`
}

// GetAllSites godoc
// @id api.sites.index
// @summary List all allowed sites
// @security bearerauth
// @tags Sites
// @produce json
// @success 204 {object} map[string]string
// @router /sites/all [get]
func GetAllSites(c fiber.Ctx) error {
	sites := []models.Site{}
	query := app.DB().Model(&models.Site{})
	opts := helpers.PaginatedItemOpts{RouteName: "api.sites.index"}

	return helpers.PaginateQuery(sites, query, c, opts)
}

// PostSite godoc
// @id api.sites.add
// @summary Add a new allowed site
// @security bearerauth
// @tags Sites
// @accept json
// @produce json
// @success 204 {object} map[string]string
// @router /sites/add [post]
// @param title body string false "Title" SchemaExample({\r\n\t"title": "Example Website"\r\n})
// @param domain body string true "Domain" SchemaExample({\r\n\t"domain": "server.tld"\r\n})
func PostSite(c fiber.Ctx) error {
	input := siteInput{}
	if err := c.Bind().Body(&input); err != nil {
		slog.Error("Error parsing input data", slog.Any("error", err))
		return c.Status(fiber.StatusOK).JSON(&fiber.Map{"error": []string{app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorInvalidSiteData",
				Other: "The site data is invalid.",
			},
		}, c)}})
	}

	errs := fiber.Map{}

	d, err := utils.GetApexDomain(input.Domain)
	if err != nil {
		slog.Error("Error getting apex domain", slog.Any("error", err))
		errs = utils.AddError(errs, "domain", app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorInvalidDomain",
				Other: "Please, enter a valid domain.",
			},
		}, c))
	}

	if len(errs) > 0 {
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": errs,
		})
	}

	input.Domain = d

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
