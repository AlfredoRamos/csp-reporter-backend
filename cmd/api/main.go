package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "alfredoramos.mx/csp-reporter/docs"
	"alfredoramos.mx/csp-reporter/internal/app"
	"alfredoramos.mx/csp-reporter/internal/cache"
	"alfredoramos.mx/csp-reporter/internal/env"
	"alfredoramos.mx/csp-reporter/internal/routes"
	"alfredoramos.mx/csp-reporter/internal/tasks"
	"alfredoramos.mx/csp-reporter/internal/utils"
	"github.com/gofiber/fiber/v3"
	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// @title CSP Reporter API
// @version [[API_VERSION]]
// @description RESTful API backend for CSP Reporter

// @contact.name Alfredo Ramos
// @contact.url https://alfredoramos.mx
// @contact.email alfredoramos@duck.com

// @license.name AGPL-3.0-or-later
// @license.url https://spdx.org/licenses/AGPL-3.0-or-later.html

// @servers.url http://localhost:3000/api/v1
// @servers.description Development

// @securityDefinitions.bearerauth
func main() {
	// Setup shutdown and signal channel
	wg := sync.WaitGroup{}
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Set default timezone
	time.Local = utils.DefaultLocation()

	// Sentry
	//app.SetupSentry()
	//defer sentry.Flush(3 * time.Second)

	cachePrefix, err := cache.Prefix()
	if err != nil {
		slog.Error("Could not generate cache prefix", slog.Any("error", err))
	}

	slog.Info("Setup cache", slog.String("prefix", cachePrefix))

	// Application initialization
	app.SetupDefaultData()
	defer func() {
		db, err := app.DB().DB()
		if err != nil {
			//sentry.CaptureException(err)
			slog.Error("Could not get database interface", slog.Any("error", err))
		}

		if err := db.Close(); err != nil {
			//sentry.CaptureException(err)
			slog.Error("Error closing database connection", slog.Any("error", err))
		}
	}()

	// Asynq server
	wg.Go(func() {
		queue := tasks.AsynqServer()
		mux := tasks.AsynqServeMux()

		if err := queue.Run(mux); err != nil {
			//sentry.CaptureException(err)
			slog.Error("Could not run queue server", slog.Any("error", err))
		}
	})
	defer func() {
		app.Cache().Close()

		if err := app.SMTP().Close(); err != nil {
			//sentry.CaptureException(err)
			slog.Error("Could not close SMTP server", slog.Any("error", err))
		}

		if err := tasks.AsynqClient().Close(); err != nil {
			//sentry.CaptureException(err)
			slog.Error("Could not close Asynq client", slog.Any("error", err))
		}

		tasks.AsynqServer().Shutdown()
	}()

	// Periodic tasks
	wg.Go(func() {
		manager := tasks.AsynqPeriodicTaskManager()

		if err := manager.Run(); err != nil {
			//sentry.CaptureException(err)
			slog.Error("Could not run periodic tasks manager", slog.Any("error", err))
		}
	})
	// defer tasks.AsynqPeriodicTaskManager().Shutdown()

	// Setup app
	http := fiber.New(fiber.Config{
		StrictRouting: true,
		ErrorHandler: func(c fiber.Ctx, err error) error {
			//sentry.CaptureException(err)
			slog.Error("Application error handler", slog.Any("error", err))

			code := fiber.StatusInternalServerError
			msg := app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorServerInternal",
					Other: "The server has encountered an error that cannot be handled.",
				},
			}, c)

			e := &fiber.Error{}
			if errors.As(err, &e) {
				code = e.Code
				msg = e.Message
			}

			return c.Status(code).JSON(&fiber.Map{"error": []string{msg}})
		},
		AppName:     strings.TrimSpace(fmt.Sprintf("%s v%s", env.String("APP_NAME"), app.Version())),
		JSONEncoder: json.Marshal,
		JSONDecoder: json.Unmarshal,
	})

	// Setup routes
	routes.SetupRoutes(http)

	// Setup server
	wg.Go(func() {
		if err := http.Listen(env.String("APP_ADDRESS")); err != nil {
			//sentry.CaptureException(err)
			slog.Error("Could not start HTTP server", slog.Any("error", err))
		}
	})

	// Listen to signals
	sig := <-sigChan
	slog.Info("Received", slog.Any("signal", sig))

	// Shutdown server
	wg.Go(func() {
		if err := http.Shutdown(); err != nil {
			//sentry.CaptureException(err)
			slog.Error("Could not close HTTP server", slog.Any("error", err))
		}
	})

	// Graceful shutdown
	wg.Wait()
	slog.Info("Gracefully shutting down the application")
}
