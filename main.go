package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"alfredoramos.mx/csp-reporter/app"
	"alfredoramos.mx/csp-reporter/routes"
	"alfredoramos.mx/csp-reporter/tasks"
	"alfredoramos.mx/csp-reporter/utils"
	"github.com/getsentry/sentry-go"
	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
)

func main() {
	// Set default timezone
	time.Local = utils.DefaultLocation()

	// Load environment variables
	if err := godotenv.Load(); err != nil {
		slog.Error(fmt.Sprintf("Could not load .env file: %v", err))
		os.Exit(1)
	}

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
	app := fiber.New(fiber.Config{
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
		AppName:     os.Getenv("APP_NAME"),
		JSONEncoder: json.Marshal,
		JSONDecoder: json.Unmarshal,
	})

	// Setup routes
	routes.SetupRoutes(app)

	// Asynq server
	go func() {
		queue := tasks.AsynqServer()
		mux := tasks.AsynqServeMux()

		if err := queue.Run(mux); err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Could not run queue server: %v", err))
			os.Exit(1)
		}
	}()
	defer func() {
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

	// Setup server
	if err := app.Listen(os.Getenv("APP_ADDRESS")); err != nil {
		sentry.CaptureException(err)
		slog.Error(fmt.Sprintf("Could not setup server: %v", err))
		os.Exit(1)
	}
}
