package app

import (
	"fmt"
	"log/slog"
	"os"

	"alfredoramos.mx/csp-reporter/utils"
	"github.com/getsentry/sentry-go"
)

func SetupSentry() {
	isDebug := utils.IsDebug()
	env := "production"

	if isDebug {
		env = "development"
	}

	if err := sentry.Init(sentry.ClientOptions{
		Dsn:                os.Getenv("SENTRY_DSN"),
		Debug:              isDebug,
		EnableTracing:      true,
		TracesSampleRate:   1.0,
		ProfilesSampleRate: 1.0,
		ServerName:         os.Getenv("APP_NAME"),
		Environment:        env,
	}); err != nil {
		slog.Error(fmt.Sprintf("Sentry initialization failed: %v", err))
	}
}
