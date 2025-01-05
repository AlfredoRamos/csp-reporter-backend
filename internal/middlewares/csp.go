package middlewares

import (
	"alfredoramos.mx/csp-reporter/internal/app"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/nicksnyder/go-i18n/v2/i18n"
)

func CSPReportLimiter() fiber.Handler {
	cfg := limiter.Config{
		Max: 100,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(&fiber.Map{"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorEndpointRateLimited",
					Other: "Too many requests received within a short amount of time.",
				},
			}, c)}})
		},
	}

	return limiter.New(cfg)
}
