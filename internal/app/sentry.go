package app

import (
	"log/slog"
	"os"

	"alfredoramos.mx/csp-reporter/internal/utils"
	"github.com/getsentry/sentry-go"
)

func SetupSentry() {
	if err := sentry.Init(sentry.ClientOptions{
		Dsn:              os.Getenv("SENTRY_DSN"),
		Debug:            utils.IsDebug(),
		EnableTracing:    true,
		TracesSampleRate: 1.0,
		ServerName:       os.Getenv("APP_NAME"),
		Release:          Version(),
		Environment:      utils.AppEnv(),
	}); err != nil {
		sentry.CaptureException(err)
		slog.Error("Sentry initialization failed", slog.Any("error", err))
	}
}
