package helpers

import (
	"database/sql"
	"fmt"
	"log/slog"
	"strings"

	"alfredoramos.mx/csp-reporter/app"
	"alfredoramos.mx/csp-reporter/models"
	"alfredoramos.mx/csp-reporter/utils"
)

func IsAllowedDomain(d string) bool {
	d = strings.TrimSpace(d)

	if len(d) < 1 {
		return false
	}

	s := &models.Site{}

	if err := app.DB().Model(&models.Site{}).
		Where("unaccent(lower(domain)) = unaccent(lower(@domain))", sql.Named("domain", d)).
		First(&s).Error; err != nil {
		slog.Error(fmt.Sprintf("Error checking allowed domain: %v", err))
		return false
	}

	return utils.IsValidUuid(s.ID)
}
