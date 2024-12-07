package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"alfredoramos.mx/csp-reporter/internal/app"
	"alfredoramos.mx/csp-reporter/internal/routes"
	"alfredoramos.mx/csp-reporter/internal/tasks"
	"alfredoramos.mx/csp-reporter/internal/utils"
	"github.com/getsentry/sentry-go"
	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		sentry.CaptureException(err)
		slog.Error(fmt.Sprintf("Could not load .env file: %v", err))
		os.Exit(1)
	}

	// Set default timezone
	time.Local = utils.DefaultLocation()

	// Sentry
	app.SetupSentry()
	defer sentry.Flush(3 * time.Second)

	// Application initialization
	app.SetupDefaultData()
	defer func() {
		db, err := app.DB().DB()
		if err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Could not get database interface: %v", err))
		}

		if err := db.Close(); err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Error closing database connection: %v", err))
		}
	}()

	// Setup app
	http := fiber.New(fiber.Config{
		StrictRouting: true,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Application error handler: %v", err))

			code := fiber.StatusInternalServerError
			msg := "The server has encountered an error that cannot be handled."

			var e *fiber.Error
			if errors.As(err, &e) {
				code = e.Code
				msg = e.Message
			}

			return c.Status(code).JSON(&fiber.Map{"error": []string{msg}})
		},
		AppName:     strings.TrimSpace(fmt.Sprintf("%s v%s", os.Getenv("APP_NAME"), app.Version())),
		JSONEncoder: json.Marshal,
		JSONDecoder: json.Unmarshal,
	})

	// Setup routes
	routes.SetupRoutes(http)

	// Asynq server
	go func() {
		queue := tasks.AsynqServer()
		mux := tasks.AsynqServeMux()

		if err := queue.Run(mux); err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Could not run queue server: %v", err))
		}
	}()
	defer func() {
		defer app.SMTP().Close()
		defer app.Cache().Close()

		if err := tasks.AsynqClient().Close(); err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Could not close Asynq client: %v", err))
		}
	}()

	// Periodic tasks
	go func() {
		manager := tasks.AsynqPeriodicTaskManager()

		if err := manager.Run(); err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Could not run periodic tasks manager: %v", err))
		}
	}()
	defer tasks.AsynqPeriodicTaskManager().Shutdown()

	// Setup server
	if err := http.Listen(os.Getenv("APP_ADDRESS")); err != nil {
		sentry.CaptureException(err)
		slog.Error(fmt.Sprintf("Could not start HTTP server: %v", err))
		os.Exit(1)
	}

	defer func() {
		if err := http.Shutdown(); err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Could not close HTTP server: %v", err))
		}
	}()
}
