package app

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"

	"alfredoramos.mx/csp-reporter/models"
	"alfredoramos.mx/csp-reporter/utils"
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
		port, err := strconv.Atoi(os.Getenv("DB_PORT"))
		if err != nil {
			port = 5432
		}

		dsn := fmt.Sprintf(
			"postgres://%[4]s:%[5]s@%[1]s:%[2]d/%[3]s",
			os.Getenv("DB_HOST"),
			port,
			os.Getenv("DB_NAME"),
			os.Getenv("DB_USER"),
			os.Getenv("DB_PASS"),
		)

		logLevel := logger.Warn

		if utils.IsDebug() {
			logLevel = logger.Info
		}

		database, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
			SkipDefaultTransaction: true,
			PrepareStmt:            true,
			Logger:                 logger.Default.LogMode(logLevel),
		})
		if err != nil {
			slog.Error(fmt.Sprintf("Could not connect to PostgreSQL: %v", err))
			os.Exit(1)
		}

		if err := database.Exec("CREATE EXTENSION IF NOT EXISTS unaccent").Error; err != nil {
			slog.Error(fmt.Sprintf("Could not load unaccent extension: %v", err))
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
			slog.Error(fmt.Sprintf("Could not migrate models: %v", err))
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

		if err := DB().Where(&models.Role{Name: r.Name, Title: r.Title}).FirstOrCreate(&role).Error; err != nil {
			slog.Error(fmt.Sprintf("Could not create %s role: %v", r.Name, err))
			continue
		}
	}
}

func SetupDefaultData() {
	setupRoles()
}
