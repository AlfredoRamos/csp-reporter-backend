package routes

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"alfredoramos.mx/csp-reporter/utils"
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
)

func SetupRoutes(app *fiber.App) {
	isDebug := utils.IsDebug()

	recoverConfig := recover.Config{
		EnableStackTrace: isDebug,
	}

	corsConfig := cors.Config{
		AllowOrigins:     os.Getenv("APP_DOMAIN"),
		AllowCredentials: true,
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization, X-Requested-With, X-CSRF-Token",
	}

	encryptedCookieConfig := encryptcookie.Config{
		Key: os.Getenv("COOKIE_SECRET_KEY"),
	}

	sessionConfig := session.Config{
		CookieDomain:      os.Getenv("COOKIE_DOMAIN"),
		CookiePath:        "/",
		CookieSecure:      !isDebug,
		CookieHTTPOnly:    true,
		CookieSameSite:    "Strict",
		CookieSessionOnly: true,
	}

	csrfConfig := csrf.Config{
		KeyLookup:         "cookie:csrf_",
		CookieName:        "csrf_",
		CookieDomain:      os.Getenv("COOKIE_DOMAIN"),
		CookiePath:        "/",
		CookieSecure:      !isDebug,
		CookieHTTPOnly:    true,
		CookieSessionOnly: true,
		Session:           session.New(sessionConfig),
		SessionKey:        "csrf.token",
		CookieSameSite:    "Strict",
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			slog.Error(fmt.Sprintf("CSRF error: %v", err))
			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{"error": []string{"You do not have permission to access this resource."}})
		},
	}

	maxRequests, err := strconv.Atoi(os.Getenv("LIMIT_REQUESTS_MAX"))
	if err != nil {
		maxRequests = 5
	}

	limiterConfig := limiter.Config{
		Max: maxRequests,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(&fiber.Map{"error": []string{"Too many requests received within a short amount of time."}})
		},
	}

	loggerConfig := logger.Config{
		Format:     "[${time}] ${locals:requestid} ${status} ${method} ${path}\n",
		TimeFormat: "2006-01-02 15:04:05 -07:00",
		TimeZone:   utils.DefaultTimeZone(),
	}

	// Overwrite configuration when in DEBUG mode
	if isDebug {
		corsConfig.AllowOrigins = "*"
		corsConfig.AllowCredentials = false
		csrfConfig.Next = func(c *fiber.Ctx) bool { //nolint:unused
			return isDebug
		}
		limiterConfig.Max = 25
	}

	app.Use(recover.New(recoverConfig))
	app.Use(cors.New(corsConfig))
	app.Use(encryptcookie.New(encryptedCookieConfig))
	app.Use(csrf.New(csrfConfig))
	app.Use(limiter.New(limiterConfig))
	app.Use(idempotency.New())
	app.Use(requestid.New())
	app.Use(logger.New(loggerConfig))
	app.Use(compress.New(compress.Config{
		Level: compress.LevelBestSpeed,
	}))

	api := app.Group("/api")
	v1 := api.Group("/v1")

	// System
	RegisterSystemRoutes(v1.Group("/system"))

	// Auth
	RegisterAuthRoutes(v1.Group("/auth"))

	// CSP Report
	RegisterCSPReportRoutes(v1.Group("/csp"))

	// Health check
	RegisterHealthCheckRoutes(api)

	// Error handlers
	// Must be the last one!
	RegisterErrorHandlers(app)
}
