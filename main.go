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

	// Application initialization
	app.SetupDefaultData()

	// Setup app
	app := fiber.New(fiber.Config{
		StrictRouting: true,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
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
			slog.Error(fmt.Sprintf("Could not run queue server: %v", err))
			os.Exit(1)
		}
	}()

	// Periodic tasks
	go func() {
		manager := tasks.AsynqPeriodicTaskManager()

		if err := manager.Run(); err != nil {
			slog.Error(fmt.Sprintf("Could not run periodic tasks manager: %v", err))
		}
	}()

	// Setup server
	if err := app.Listen(os.Getenv("APP_ADDRESS")); err != nil {
		slog.Error(fmt.Sprintf("Could not setup server: %v", err))
		os.Exit(1)
	}
}
