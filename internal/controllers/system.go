package controllers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"alfredoramos.mx/csp-reporter/internal/app"
	"alfredoramos.mx/csp-reporter/internal/tasks"
	"github.com/getsentry/sentry-go"
	"github.com/gofiber/fiber/v2"
	"github.com/valkey-io/valkey-go"
)

func PurgeCache(c *fiber.Ctx) error {
	if err := tasks.NewPurgeCachePattern("roles:*"); err != nil {
		sentry.CaptureException(err)
		slog.Error(fmt.Sprintf("Error purging user roles from cache: %v", err))
	}

	if err := tasks.NewPurgeCachePattern("user:*"); err != nil {
		sentry.CaptureException(err)
		slog.Error(fmt.Sprintf("Error purging user info from cache: %v", err))
	}

	// ! Do not purge tokens
	errs := []error{}
	cmds := valkey.Commands{
		app.Cache().B().Del().Key("email:superadmin:list").Build(),
	}

	for _, res := range app.Cache().DoMulti(context.Background(), cmds...) {
		if err := res.Error(); err != nil && !errors.Is(err, valkey.Nil) {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		slog.Error(fmt.Sprintf("Error purging cache: %v", errors.Join(errs...)))
	}

	return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
}

func GetCsrf(c *fiber.Ctx) error {
	// * Used only to generate CSRF cookie
	return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
}
