package utils

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/getsentry/sentry-go"
	"github.com/wneessen/go-mail"
	"github.com/wneessen/go-mail-middleware/dkim"
)

func NewDkimMiddleware() *dkim.Middleware {
	d, err := GetApexDomain(os.Getenv("APP_DOMAIN"))
	if err != nil {
		sentry.CaptureException(err)
		slog.Error(fmt.Sprintf("Could not get application domain: %v", err))
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
		sentry.CaptureException(err)
		slog.Error(fmt.Sprintf("Could not create DKIM config: %v", err))
		return &dkim.Middleware{}
	}

	rsaKey, err := os.ReadFile(filepath.Clean(filepath.Join("internal", "keys", "dkim.key")))
	if err != nil {
		sentry.CaptureException(err)
		slog.Error(fmt.Sprintf("Could not read private key for DKIM: %v", err))
		return &dkim.Middleware{}
	}

	mw, err := dkim.NewFromRSAKey(rsaKey, sc)
	if err != nil {
		sentry.CaptureException(err)
		slog.Error(fmt.Sprintf("Could not create DKIM middleware: %v", err))
		return &dkim.Middleware{}
	}

	return mw
}
