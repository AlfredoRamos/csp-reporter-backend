package app

import (
	"log/slog"
	"os"
	"sync"

	"alfredoramos.mx/csp-reporter/internal/env"
	"github.com/getsentry/sentry-go"
	"github.com/wneessen/go-mail"
)

var (
	email     *mail.Client
	onceEmail sync.Once
)

func SMTP() *mail.Client {
	onceEmail.Do(func() {
		tlsPolicy := mail.TLSMandatory
		smtpAuth := mail.SMTPAuthCramMD5
		useTls := env.Bool("EMAIL_TLS", true)

		if !useTls {
			tlsPolicy = mail.TLSOpportunistic
			smtpAuth = mail.SMTPAuthLogin
		}

		client, err := mail.NewClient(
			env.String("EMAIL_HOST"),
			mail.WithSMTPAuth(smtpAuth),
			mail.WithTLSPortPolicy(tlsPolicy),
			mail.WithPort(env.Int("EMAIL_PORT", mail.DefaultPortTLS)),
			mail.WithUsername(env.String("EMAIL_USERNAME")),
			mail.WithPassword(env.String("EMAIL_PASSWORD")),
		)
		if err != nil {
			sentry.CaptureException(err)
			slog.Error("Could not create email client", slog.Any("error", err))
			os.Exit(1)
		}

		email = client
	})

	return email
}
