package helpers

import (
	"database/sql"
	"fmt"
	"log/slog"

	"alfredoramos.mx/csp-reporter/app"
	"alfredoramos.mx/csp-reporter/models"
	"alfredoramos.mx/csp-reporter/utils"
	"github.com/getsentry/sentry-go"
	"gorm.io/gorm"
)

type cspReportFields struct {
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

type CspReport struct {
	Report cspReportFields `json:"csp-report"`
}

func NewCspReport(d CspReport) error {
	domain, err := utils.GetApexDomain(d.Report.DocumentURI)
	if err != nil {
		sentry.CaptureException(err)
		slog.Error(fmt.Sprintf("Could not get the document URI hostname: %v", err))
		return err
	}

	if !IsAllowedDomain(domain) {
		err := fmt.Errorf("The document URI '%s' is not within the allowed domains.", domain)
		sentry.CaptureException(err)
		return err
	}

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
			BlockedURI:         d.Report.BlockedURI,
			Disposition:        d.Report.Disposition,
			DocumentURI:        d.Report.DocumentURI,
			EffectiveDirective: d.Report.EffectiveDirective,
			OriginalPolicy:     d.Report.OriginalPolicy,
			Referrer:           d.Report.Referrer,
			StatusCode:         d.Report.StatusCode,
			ViolatedDirective:  d.Report.ViolatedDirective,
			ScriptSample:       d.Report.ScriptSample,
			SourceFile:         d.Report.SourceFile,
			LineNumber:         d.Report.LineNumber,
			ColumnNumber:       d.Report.ColumnNumber,
		}
		if err := tx.Where(&report).Preload("Site").FirstOrCreate(&report).Error; err != nil {
			slog.Error(fmt.Sprintf("Error saving CSP Report: %v", err))
			return err
		}

		return nil
	}); err != nil {
		slog.Error(fmt.Sprintf("Error saving CSP Report: %v", err))
		return err
	}

	return nil
}
