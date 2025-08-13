package routes

import (
	"log/slog"
	"time"

	cspapp "alfredoramos.mx/csp-reporter/internal/app"
	"alfredoramos.mx/csp-reporter/internal/env"
	"alfredoramos.mx/csp-reporter/internal/utils"
	"github.com/getsentry/sentry-go"
	sentryfiber "github.com/getsentry/sentry-go/fiber"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/csrf"
	"github.com/gofiber/fiber/v2/middleware/encryptcookie"
	"github.com/gofiber/fiber/v2/middleware/idempotency"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/nicksnyder/go-i18n/v2/i18n"
)

func SetupRoutes(app *fiber.App) {
	isProduction := env.IsProduction()

	sentryConfig := sentryfiber.Options{Timeout: 3 * time.Second}

	recoverConfig := recover.Config{
		EnableStackTrace: env.IsDebug(),
	}

	corsConfig := cors.Config{
		AllowOrigins:     utils.CorsOrigins(),
		AllowCredentials: true,
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization, X-Requested-With, X-CSRF-Token",
	}

	encryptedCookieConfig := encryptcookie.Config{
		Key: env.String("COOKIE_SECRET_KEY"),
	}

	sessionConfig := session.Config{
		CookieDomain:      env.String("COOKIE_DOMAIN"),
		CookiePath:        "/",
		CookieSecure:      isProduction,
		CookieHTTPOnly:    true,
		CookieSameSite:    "Strict",
		CookieSessionOnly: true,
	}

	csrfConfig := csrf.Config{
		KeyLookup:         "cookie:csrf_",
		CookieName:        "csrf_",
		CookieDomain:      env.String("COOKIE_DOMAIN"),
		CookiePath:        "/",
		CookieSecure:      isProduction,
		CookieHTTPOnly:    true,
		CookieSessionOnly: true,
		Session:           session.New(sessionConfig),
		SessionKey:        "csrf.token",
		CookieSameSite:    "Strict",
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			sentry.CaptureException(err)
			slog.Error("CSRF error", slog.Any("error", err))
			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{"error": []string{cspapp.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorEndpointPermissions",
					Other: "You are not allowed to access this resource.",
				},
			}, c)}})
		},
	}

	maxRequests := env.Int("LIMIT_REQUESTS_MAX", 100)

	limiterConfig := limiter.Config{
		Max: maxRequests,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(&fiber.Map{"error": []string{cspapp.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorEndpointRateLimited",
					Other: "Too many requests received within a short amount of time.",
				},
			}, c)}})
		},
	}

	loggerConfig := logger.Config{
		Format:     "[${time}] ${locals:requestid} ${status} ${method} ${path}\n",
		TimeFormat: "2006-01-02 15:04:05 -07:00",
		TimeZone:   utils.DefaultTimeZone(),
	}

	compressConfig := compress.Config{
		Level: compress.LevelBestCompression,
	}

	// Overwrite configuration in development environment
	if !isProduction {
		corsConfig.AllowOrigins = "*"
		corsConfig.AllowCredentials = false
		csrfConfig.Next = func(c *fiber.Ctx) bool { //nolint:unused
			return true
		}
		limiterConfig.Max = 25
	}

	app.Use(sentryfiber.New(sentryConfig))
	app.Use(recover.New(recoverConfig))
	app.Use(cors.New(corsConfig))
	app.Use(encryptcookie.New(encryptedCookieConfig))
	app.Use(csrf.New(csrfConfig))
	app.Use(limiter.New(limiterConfig))
	app.Use(idempotency.New())
	app.Use(requestid.New())
	app.Use(logger.New(loggerConfig))
	app.Use(compress.New(compressConfig))

	api := app.Group("/api")
	v1 := api.Group("/v1")

	// System
	RegisterSystemRoutes(v1.Group("/system"))

	// Auth
	RegisterAuthRoutes(v1.Group("/auth"))

	// Sites
	RegisterSiteRoutes(v1.Group("/sites"))

	// CSP Report
	RegisterCSPReportRoutes(v1.Group("/csp"))

	// User activations
	RegisterUserActivationRoutes(v1.Group("/activations"))

	// Health check
	RegisterHealthCheckRoutes(api)

	// Error handlers
	// Must be the last one!
	RegisterErrorHandlers(app)
}
