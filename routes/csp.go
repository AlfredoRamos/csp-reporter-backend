package routes

import (
	"alfredoramos.mx/csp-reporter/controllers"
	"alfredoramos.mx/csp-reporter/middlewares"
	"github.com/gofiber/fiber/v2"
)

func RegisterCSPReportRoutes(g fiber.Router) {
	// Public
	g.Post("/reports/add", controllers.PostCSPReport).Name("api.csp.reports.add")

	// Private
	g.Use(middlewares.AuthProtected(), middlewares.ValidateJWT(), middlewares.CheckPermissions())
	g.Get("/reports/all", controllers.GetAllCSPReports).Name("api.csp.reports.index")
}
