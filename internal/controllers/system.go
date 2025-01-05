package controllers

import (
	"context"
	"fmt"
	"log/slog"

	"alfredoramos.mx/csp-reporter/internal/app"
	"alfredoramos.mx/csp-reporter/internal/tasks"
	"github.com/getsentry/sentry-go"
	"github.com/gofiber/fiber/v2"
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
	// TODO: Show errors
	app.Cache().DoMulti(
		context.Background(),
		app.Cache().B().Del().Key("email:superadmin:list").Build(),
	)

	return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
}

func GetCsrf(c *fiber.Ctx) error {
	// * Used only to generate CSRF cookie
	return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
}
