package controllers

import (
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"alfredoramos.mx/csp-reporter/helpers"
	"alfredoramos.mx/csp-reporter/tasks"
	"alfredoramos.mx/csp-reporter/utils"
	"github.com/gofiber/fiber/v2"
)

type cspReport struct {
	BlockedURI         string `json:"blocked-uri"`
	Disposition        string `json:"disposition"`
	DocumentURI        string `json:"document-uri"`
	EffectiveDirective string `json:"effective-directive"`
	OriginalPolicy     string `json:"original-policy"`
	Referrer           string `json:"referrer"`
	StatusCode         int    `json:"status-code"`
	ViolatedDirective  string `json:"violated-directive"`
	ScriptSample       string `json:"script-sample"`
	SourceFile         string `json:"source-file"`
	LineNumber         int64  `json:"line-number"`
	ColumnNumber       int64  `json:"column-number"`
}

type cspReportInput struct {
	Report cspReport `json:"csp-report"`
}

func PostCSPReport(c *fiber.Ctx) error {
	slog.Warn(fmt.Sprintf("CSP violation raw data: %#v", c.Body()))

	allowedMimeTypes := []string{"application/csp-report", "application/json"}
	accept := c.Accepts(allowedMimeTypes...)
	defaultErr := c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{"errors": []string{"Invalid Content Security Policy Report."}})

	issuer, err := utils.GetJwtIssuer()
	if err != nil || len(issuer) < 1 {
		slog.Error(fmt.Sprintf("Error getting application domain: %v", err))
		return defaultErr
	}

	if !c.IsFromLocal() && !strings.EqualFold(c.Hostname(), issuer) {
		slog.Error(fmt.Sprintf("The host '%s' does not match the one from the '%s'.", c.Hostname(), issuer))
		return defaultErr
	}

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

	blockedUri, err := utils.GetDomainHostname(input.Report.BlockedURI)
	if err != nil || !strings.EqualFold(issuer, blockedUri) {
		if err != nil {
			slog.Error(fmt.Sprintf("Could not get the hostname from the bloqued URI: %v", err))
		}

		if !strings.EqualFold(issuer, blockedUri) {
			slog.Error(fmt.Sprintf("The bloqued URI '%s' does not match the current domain '%s'.", blockedUri, issuer))
		}

		return defaultErr
	}

	documentUri, err := utils.GetDomainHostname(input.Report.DocumentURI)
	if err != nil || len(documentUri) < 1 || !strings.EqualFold(issuer, documentUri) {
		if err != nil {
			slog.Error(fmt.Sprintf("Could not get the document URI hostname: %v", err))
		}

		if !strings.EqualFold(issuer, documentUri) {
			slog.Error(fmt.Sprintf("The document URI '%s' does not match the current domain '%s'.", documentUri, issuer))
		}

		return defaultErr
	}

	slog.Warn(fmt.Sprintf("CSP violation report: %#v", input))

	now := time.Now().In(utils.DefaultLocation())

	// TODO: Save to database

	// TODO: Send after saving to database
	if err := tasks.NewEmail(
		helpers.EmailOpts{
			Subject:      "Content Security Policy violation report",
			TemplateName: "csp_report",
			IsInternal:   true,
			ToList:       []string{utils.InternalStaffEmail()},
		},
		map[string]interface{}{
			"ReportDateTime":     now.Format("2006-01-02 15:04:05 -07:00"),
			"BlockedURI":         input.Report.BlockedURI,
			"Disposition":        input.Report.Disposition,
			"DocumentURI":        input.Report.DocumentURI,
			"EffectiveDirective": input.Report.EffectiveDirective,
			"OriginalPolicy":     input.Report.OriginalPolicy,
			"Referrer":           input.Report.Referrer,
			"StatusCode":         input.Report.StatusCode,
			"ViolatedDirective":  input.Report.ViolatedDirective,
			"ScriptSample":       input.Report.ScriptSample,
			"SourceFile":         input.Report.SourceFile,
			"LineNumber":         input.Report.LineNumber,
			"ColumnNumber":       input.Report.ColumnNumber,
		},
	); err != nil {
		slog.Error(fmt.Sprintf("Error sending email: %v", err))
	}

	return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
}
