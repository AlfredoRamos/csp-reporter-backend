package routes

import (
	"alfredoramos.mx/csp-reporter/internal/app"
	"github.com/gofiber/fiber/v2"
	"github.com/nicksnyder/go-i18n/v2/i18n"
)

func RegisterErrorHandlers(g fiber.Router) {
	// 404 Handler
	g.Use(func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusNotFound).JSON(&fiber.Map{"error": []string{app.Translate(&i18n.LocalizeConfig{
			DefaultMessage: &i18n.Message{
				ID:    "ErrorEndpointNotFound",
				Other: "The requested resource could not be found.",
			},
		}, c)}})
	})
}
