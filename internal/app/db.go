package app

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"alfredoramos.mx/csp-reporter/internal/env"
	"alfredoramos.mx/csp-reporter/internal/models"
	"alfredoramos.mx/csp-reporter/internal/utils"
	"github.com/getsentry/sentry-go"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	db     *gorm.DB
	onceDB sync.Once
)

func DB() *gorm.DB {
	onceDB.Do(func() {
		port := env.Int("DB_PORT", 5432)
		dsn := fmt.Sprintf(
			"postgres://%[4]s:%[5]s@%[1]s:%[2]d/%[3]s",
			env.String("DB_HOST", ""),
			port,
			env.String("DB_NAME", ""),
			env.String("DB_USER", ""),
			env.String("DB_PASS", ""),
		)

		logLevel := logger.Warn

		if env.IsDebug() {
			logLevel = logger.Info
		}

		database, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
			SkipDefaultTransaction: true,
			PrepareStmt:            true,
			Logger:                 logger.Default.LogMode(logLevel),
		})
		if err != nil {
			sentry.CaptureException(err)
			slog.Error("Could not connect to PostgreSQL", slog.Any("error", err))
			os.Exit(1)
		}

		if err := database.Exec("CREATE EXTENSION IF NOT EXISTS unaccent").Error; err != nil {
			sentry.CaptureException(err)
			slog.Error("Could not load unaccent extension", slog.Any("error", err))
		}

		if err := database.AutoMigrate(
			&models.User{},
			&models.Role{},
			&models.UserRole{},
			&models.UserActivation{},
			&models.AccountRecovery{},
			&models.Report{},
			&models.Site{},
		); err != nil {
			sentry.CaptureException(err)
			slog.Error("Could not migrate models", slog.Any("error", err))
			os.Exit(1)
		}

		db = database
	})

	return db
}

func setupRoles() {
	roles := []models.Role{
		{Name: "superadmin", Title: "Super administrator"},
		{Name: "admin", Title: "Administrator"},
		{Name: "manager", Title: "Manager"},
		{Name: "viewer", Title: "Viewer"},
		{Name: "user", Title: "User"},
	}

	for _, r := range roles {
		role := &models.Role{}

		if err := DB().Where(&models.Role{Name: r.Name}).FirstOrCreate(&role).Error; err != nil {
			slog.Error(
				"Could not create role",
				slog.String("name", r.Name),
				slog.Any("error", err),
			)
			continue
		}
	}
}

func setupSites() {
	isProduction := env.IsProduction()

	domain, err := utils.GetApexDomain(env.String("APP_DOMAIN", ""))
	if err != nil && isProduction {
		sentry.CaptureException(err)
		slog.Error("Could not get app domain", slog.Any("error", err))
		return
	}

	if len(domain) < 1 && !isProduction {
		domain = "localhost"
	}

	sites := []models.Site{
		{
			Title:  utils.ToStringPtr(env.String("APP_NAME", "")),
			Domain: domain,
		},
	}

	if len(utils.CorsOrigins()) > 0 {
		origins := strings.Split(utils.CorsOrigins(), ",")

		for _, orig := range origins {
			domain, err := utils.GetApexDomain(orig)
			if err != nil {
				slog.Error(
					"Could not get apex domain",
					slog.String("origin", orig),
					slog.Any("error", err),
				)
				continue
			}

			sites = append(sites, models.Site{Domain: domain})
		}
	}

	for _, s := range sites {
		if err := DB().Model(&models.Site{}).
			Where("unaccent(lower(domain)) = unaccent(lower(@domain))", sql.Named("domain", s.Domain)).
			FirstOrCreate(&s).Error; err != nil {
			slog.Error("Could not create default site", slog.Any("error", err))
		}
	}
}

func SetupDefaultData() {
	setupRoles()
	setupSites()
}
