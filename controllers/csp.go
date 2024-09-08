package controllers

import (
	"database/sql"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"alfredoramos.mx/csp-reporter/app"
	"alfredoramos.mx/csp-reporter/helpers"
	"alfredoramos.mx/csp-reporter/models"
	"alfredoramos.mx/csp-reporter/tasks"
	"alfredoramos.mx/csp-reporter/utils"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

type cspReport struct {
	BlockedURI         string  `json:"blocked-uri"`
	Disposition        string  `json:"disposition"`
	DocumentURI        string  `json:"document-uri"`
	EffectiveDirective string  `json:"effective-directive"`
	OriginalPolicy     string  `json:"original-policy"`
	Referrer           *string `json:"referrer"`
	StatusCode         int     `json:"status-code"`
	ViolatedDirective  string  `json:"violated-directive"`
	ScriptSample       *string `json:"script-sample"`
	SourceFile         *string `json:"source-file"`
	LineNumber         *int64  `json:"line-number"`
	ColumnNumber       *int64  `json:"column-number"`
}

type cspReportInput struct {
	Report cspReport `json:"csp-report"`
}

func GetAllCSPReports(c *fiber.Ctx) error {
	reports := []models.Report{}
	query := app.DB().Model(&models.Report{}).Preload("Site")
	opts := helpers.PaginatedItemOpts{RouteName: "api.csp.reports.index"}

	return helpers.PaginateQuery(reports, query, c, opts)
}

func PostCSPReport(c *fiber.Ctx) error {
	allowedMimeTypes := []string{"application/csp-report", "application/json"}
	accept := c.Accepts(allowedMimeTypes...)
	defaultErr := c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{"errors": []string{"Invalid Content Security Policy Report."}})

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

	input := cspReportInput{}
	if err := c.BodyParser(&input); err != nil {
		slog.Error(fmt.Sprintf("Error parsing input data: %v", err))
		return defaultErr
	}

	domain, err := utils.GetApexDomain(input.Report.DocumentURI)
	if err != nil || len(domain) < 1 || !helpers.IsAllowedDomain(domain) {
		if err != nil {
			slog.Error(fmt.Sprintf("Could not get the document URI hostname: %v", err))
		}

		if !helpers.IsAllowedDomain(domain) {
			slog.Error(fmt.Sprintf("The document URI '%s' is not within the allowed domains.", domain))
		}

		return defaultErr
	}

	slog.Warn(fmt.Sprintf("CSP violation report: %#v", input))

	now := time.Now().In(utils.DefaultLocation())

	if err := app.DB().Transaction(func(tx *gorm.DB) error {
		site := &models.Site{}
		if err := tx.Model(&models.Site{}).
			Where("unaccent(lower(domain)) = unaccent(lower(@domain))", sql.Named("domain", domain)).
			First(&site).Error; err != nil {
			slog.Error(fmt.Sprintf("Error getting site: %v", err))
			return err
		}

		report := &models.Report{
			SiteID:             site.ID,
			BlockedURI:         input.Report.BlockedURI,
			Disposition:        input.Report.Disposition,
			DocumentURI:        input.Report.DocumentURI,
			EffectiveDirective: input.Report.EffectiveDirective,
			OriginalPolicy:     input.Report.OriginalPolicy,
			Referrer:           input.Report.Referrer,
			StatusCode:         input.Report.StatusCode,
			ViolatedDirective:  input.Report.ViolatedDirective,
			ScriptSample:       input.Report.ScriptSample,
			SourceFile:         input.Report.SourceFile,
			LineNumber:         input.Report.LineNumber,
			ColumnNumber:       input.Report.ColumnNumber,
		}
		if err := tx.Where(&report).FirstOrCreate(&report).Error; err != nil {
			slog.Error(fmt.Sprintf("Error saving CSP Report: %v", err))
			return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{"error": []string{"Could not regisger CSP report."}})
		}

		if err := tasks.NewEmail(
			helpers.EmailOpts{
				Subject:      "Content Security Policy violation report",
				TemplateName: "csp_report",
				IsInternal:   true,
				ToList:       []string{utils.InternalStaffEmail()},
			},
			map[string]interface{}{
				"ReportDateTime":     now.Format("2006-01-02 15:04:05 -07:00"),
				"BlockedURI":         report.BlockedURI,
				"Disposition":        report.Disposition,
				"DocumentURI":        report.DocumentURI,
				"EffectiveDirective": report.EffectiveDirective,
				"OriginalPolicy":     report.OriginalPolicy,
				"Referrer":           report.Referrer,
				"StatusCode":         report.StatusCode,
				"ViolatedDirective":  report.ViolatedDirective,
				"ScriptSample":       report.ScriptSample,
				"SourceFile":         report.SourceFile,
				"LineNumber":         report.LineNumber,
				"ColumnNumber":       report.ColumnNumber,
			},
		); err != nil {
			slog.Error(fmt.Sprintf("Error sending email: %v", err))
		}

		return nil
	}); err != nil {
		slog.Error(fmt.Sprintf("Error saving CSP Report: %v", err))
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{"error": []string{"Could not regisger CSP report."}})
	}

	return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
}
