package routes

import "github.com/gofiber/fiber/v2"

func RegisterErrorHandlers(g fiber.Router) {
	// 404 Handler
	g.Use(func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusNotFound).JSON(&fiber.Map{"error": []string{"The requested resource could not be found."}})
	})
}
