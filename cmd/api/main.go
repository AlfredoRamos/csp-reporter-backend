package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"alfredoramos.mx/csp-reporter/internal/app"
	"alfredoramos.mx/csp-reporter/internal/routes"
	"alfredoramos.mx/csp-reporter/internal/tasks"
	"alfredoramos.mx/csp-reporter/internal/utils"
	"github.com/getsentry/sentry-go"
	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
)

func main() {
	// Setup shutdown and signal channel
	wg := sync.WaitGroup{}
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

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

	// Asynq server
	wg.Add(1)
	go func() {
		defer wg.Done()

		queue := tasks.AsynqServer()
		mux := tasks.AsynqServeMux()

		if err := queue.Run(mux); err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Could not run queue server: %v", err))
		}
	}()
	defer func() {
		app.Cache().Close()

		if err := app.SMTP().Close(); err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Could not close SMTP server: %v", err))
		}

		if err := tasks.AsynqClient().Close(); err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Could not close Asynq client: %v", err))
		}

		tasks.AsynqServer().Shutdown()
	}()

	// Periodic tasks
	wg.Add(1)
	go func() {
		defer wg.Done()

		manager := tasks.AsynqPeriodicTaskManager()

		if err := manager.Run(); err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Could not run periodic tasks manager: %v", err))
		}
	}()
	// defer tasks.AsynqPeriodicTaskManager().Shutdown()

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

	// Setup server
	wg.Add(1)
	go func() {
		defer wg.Done()

		if err := http.Listen(os.Getenv("APP_ADDRESS")); err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Could not start HTTP server: %v", err))
		}
	}()

	// Listen to signals
	sig := <-sigChan
	slog.Info(fmt.Sprintf("Received signal: %v", sig))

	// Shutdown server
	wg.Add(1)
	go func() {
		defer wg.Done()

		if err := http.Shutdown(); err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Could not close HTTP server: %v", err))
		}
	}()

	// Graceful shutdown
	wg.Wait()
	slog.Info("Gracefully shutting down the application.")
}
