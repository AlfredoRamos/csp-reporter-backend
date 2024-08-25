package routes

import (
	"alfredoramos.mx/csp-reporter/controllers"
	"github.com/gofiber/fiber/v2"
)

func RegisterCSPReportRoutes(g fiber.Router) {
	// Public
	g.Post("/report", controllers.PostCSPReport).Name("api.csp.report")
}
