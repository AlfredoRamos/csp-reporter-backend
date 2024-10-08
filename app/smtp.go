package app

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"

	"github.com/getsentry/sentry-go"
	"github.com/wneessen/go-mail"
)

var (
	email     *mail.Client
	onceEmail sync.Once
)

func SMTP() *mail.Client {
	onceEmail.Do(func() {
		port, err := strconv.Atoi(os.Getenv("EMAIL_PORT"))
		if err != nil {
			sentry.CaptureException(err)
			port = mail.DefaultPortTLS
			slog.Warn(fmt.Sprintf("The SMTP port '%s' is invalid. The port %d will be used instead.", os.Getenv("EMAIL_PORT"), port))
		}

		tlsPolicy := mail.TLSMandatory
		smtpAuth := mail.SMTPAuthCramMD5

		useTls, err := strconv.ParseBool(os.Getenv("EMAIL_TLS"))
		if err != nil {
			sentry.CaptureException(err)
			useTls = true
		}

		if !useTls {
			tlsPolicy = mail.TLSOpportunistic
			smtpAuth = mail.SMTPAuthLogin
		}

		client, err := mail.NewClient(
			os.Getenv("EMAIL_HOST"),
			mail.WithSMTPAuth(smtpAuth),
			mail.WithTLSPortPolicy(tlsPolicy),
			mail.WithPort(port),
			mail.WithUsername(os.Getenv("EMAIL_USERNAME")),
			mail.WithPassword(os.Getenv("EMAIL_PASSWORD")),
		)
		if err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Could not create email client: %v", err))
			os.Exit(1)
		}

		email = client
	})

	return email
}
