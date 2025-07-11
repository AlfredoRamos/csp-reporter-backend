package controllers

import (
	"context"
	"errors"
	"log/slog"

	"alfredoramos.mx/csp-reporter/internal/app"
	"alfredoramos.mx/csp-reporter/internal/tasks"
	"alfredoramos.mx/csp-reporter/internal/utils"
	"github.com/getsentry/sentry-go"
	"github.com/gofiber/fiber/v2"
	"github.com/valkey-io/valkey-go"
)

func PurgeCache(c *fiber.Ctx) error {
	if err := tasks.NewPurgeCachePattern("roles:*"); err != nil {
		sentry.CaptureException(err)
		slog.Error("Error purging user roles from cache", slog.Any("error", err))
	}

	if err := tasks.NewPurgeCachePattern("user:*"); err != nil {
		sentry.CaptureException(err)
		slog.Error("Error purging user info from cache", slog.Any("error", err))
	}

	// ! Do not purge tokens
	errs := []error{}
	cmds := valkey.Commands{
		app.Cache().B().Del().Key(utils.CacheKey("email:superadmin:list")).Build(),
	}

	for _, res := range app.Cache().DoMulti(context.Background(), cmds...) {
		if err := res.Error(); err != nil && !errors.Is(err, valkey.Nil) {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		slog.Error("Error purging cache", slog.Any("error", errors.Join(errs...)))
	}

	return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
}

func GetCsrf(c *fiber.Ctx) error {
	// * Used only to generate CSRF cookie
	return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
}
