package routes

import "github.com/gofiber/fiber/v2"

func RegisterHealthCheckRoutes(g fiber.Router) {
	g.Get("/health", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(&fiber.Map{"healthy": true})
	})
}
