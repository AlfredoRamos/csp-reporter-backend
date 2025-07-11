package helpers

import (
	"database/sql"
	"fmt"
	"log/slog"

	"alfredoramos.mx/csp-reporter/internal/app"
	"alfredoramos.mx/csp-reporter/internal/models"
	"alfredoramos.mx/csp-reporter/internal/utils"
	"github.com/getsentry/sentry-go"
	"gorm.io/gorm"
)

type cspReportFields struct {
	BlockedURI         string  `json:"blocked-uri"`
	Disposition        *string `json:"disposition,omitempty"`
	DocumentURI        string  `json:"document-uri"`
	EffectiveDirective string  `json:"effective-directive"`
	OriginalPolicy     string  `json:"original-policy"`
	Referrer           *string `json:"referrer,omitempty"`
	StatusCode         *int    `json:"status-code,omitempty"`
	ViolatedDirective  string  `json:"violated-directive"`
	ScriptSample       *string `json:"script-sample,omitempty"`
	SourceFile         *string `json:"source-file,omitempty"`
	LineNumber         *int64  `json:"line-number,omitempty"`
	ColumnNumber       *int64  `json:"column-number,omitempty"`
}

type CspReport struct {
	Report cspReportFields `json:"csp-report"`
}

func NewCspReport(d CspReport) error {
	domain, err := utils.GetApexDomain(d.Report.DocumentURI)
	if err != nil {
		sentry.CaptureException(err)
		slog.Error("Could not get the document URI hostname", slog.Any("error", err))
		return err
	}

	if !IsAllowedDomain(domain) {
		err := fmt.Errorf("the document URI '%s' is not within the allowed domains", domain)
		sentry.CaptureException(err)
		return err
	}

	if err := app.DB().Transaction(func(tx *gorm.DB) error {
		site := &models.Site{}
		if err := tx.Model(&models.Site{}).
			Where("unaccent(lower(domain)) = unaccent(lower(@domain))", sql.Named("domain", domain)).
			First(&site).Error; err != nil {
			slog.Error("Error getting site", slog.Any("error", err))
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
			slog.Error("Error saving CSP Report", slog.Any("error", err))
			return err
		}

		return nil
	}); err != nil {
		slog.Error("Error saving CSP Report", slog.Any("error", err))
		return err
	}

	return nil
}
