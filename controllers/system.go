package controllers

import (
	"context"

	"alfredoramos.mx/csp-reporter/app"
	"github.com/gofiber/fiber/v2"
)

func PurgeCache(c *fiber.Ctx) error {
	if err := app.Cache().Do(context.Background(), app.Cache().B().Flushall().Async().Build()).Error(); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{"error": []string{"Could not purge cache."}})
	}

	return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
}

func GetCsrf(c *fiber.Ctx) error {
	return c.Status(fiber.StatusNoContent).JSON(&fiber.Map{})
}
