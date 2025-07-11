package helpers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"alfredoramos.mx/csp-reporter/internal/app"
	"alfredoramos.mx/csp-reporter/internal/models"
	"alfredoramos.mx/csp-reporter/internal/utils"
	"github.com/getsentry/sentry-go"
	"github.com/google/uuid"
	"github.com/valkey-io/valkey-go"
)

func IsAllowedDomain(d string) bool {
	domain, err := utils.GetApexDomain(d)
	if err != nil {
		sentry.CaptureException(err)
		slog.Error("Could not get app domain", slog.Any("error", err))
		return false
	}

	cacheKey := utils.CacheKey(fmt.Sprintf("domain:%s", domain))
	cachedDomain, err := app.Cache().DoCache(context.Background(), app.Cache().B().Get().Key(cacheKey).Cache(), 5*time.Minute).ToString()
	if err != nil && !errors.Is(err, valkey.Nil) {
		sentry.CaptureException(err)
		slog.Warn("Could not get cached domain", slog.Any("error", err))
	}

	if len(cachedDomain) > 0 {
		siteID, err := uuid.Parse(cachedDomain)
		if err != nil {
			sentry.CaptureException(err)
		}

		if utils.IsValidUuid(siteID) {
			return true
		}
	}

	site := &models.Site{}
	if err := app.DB().Model(&models.Site{}).
		Where("unaccent(lower(domain)) = unaccent(lower(@domain))", sql.Named("domain", domain)).
		First(&site).Error; err != nil {
		return false
	}

	if utils.IsValidUuid(site.ID) {
		if err := app.Cache().Do(context.Background(), app.Cache().B().Set().Key(cacheKey).Value(site.ID.String()).Ex(time.Hour).Build()).Error(); err != nil {
			sentry.CaptureException(err)
			slog.Error("Could not save user to cache", slog.Any("error", err))
		}

		return true
	}

	return false
}
