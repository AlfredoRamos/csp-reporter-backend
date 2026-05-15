package utils

import (
	"log/slog"
	"os"
	"path/filepath"

	"alfredoramos.mx/csp-reporter/internal/env"
	"github.com/wneessen/go-mail"
	"github.com/wneessen/go-mail-middleware/dkim"
)

func NewDkimMiddleware() *dkim.Middleware {
	d, err := GetApexDomain(env.String("APP_DOMAIN"))
	if err != nil {
		//sentry.CaptureException(err)
		slog.Error("Could not get application domain", slog.Any("error", err))
		return &dkim.Middleware{}
	}

	sc, err := dkim.NewConfig(d, DkimSelector(),
		dkim.WithHeaderFields(
			mail.HeaderMessageID.String(),
			mail.HeaderDate.String(),
			mail.HeaderFrom.String(),
			mail.HeaderTo.String(),
			mail.HeaderSubject.String(),
		),
	)
	if err != nil {
		//sentry.CaptureException(err)
		slog.Error("Could not create DKIM config", slog.Any("error", err))
		return &dkim.Middleware{}
	}

	rsaKey, err := os.ReadFile(filepath.Clean(filepath.Join("internal", "keys", "dkim.key")))
	if err != nil {
		//sentry.CaptureException(err)
		slog.Error("Could not read private key for DKIM", slog.Any("error", err))
		return &dkim.Middleware{}
	}

	mw, err := dkim.NewFromRSAKey(rsaKey, sc)
	if err != nil {
		//sentry.CaptureException(err)
		slog.Error("Could not create DKIM middleware", slog.Any("error", err))
		return &dkim.Middleware{}
	}

	return mw
}
