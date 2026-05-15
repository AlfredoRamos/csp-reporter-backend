package app

import (
	"log/slog"

	"alfredoramos.mx/csp-reporter/internal/env"
	"github.com/getsentry/sentry-go"
)

func SetupSentry() {
	if err := sentry.Init(sentry.ClientOptions{
		Dsn:              env.String("SENTRY_DSN"),
		Debug:            env.IsDebug(),
		EnableTracing:    true,
		TracesSampleRate: 1.0,
		ServerName:       env.String("APP_NAME"),
		Release:          Version(),
		Environment:      env.Name(),
	}); err != nil {
		//sentry.CaptureException(err)
		slog.Error("Sentry initialization failed", slog.Any("error", err))
	}
}
