package routes

import (
	"alfredoramos.mx/csp-reporter/internal/controllers"
	"alfredoramos.mx/csp-reporter/internal/middlewares"
	"github.com/gofiber/fiber/v2"
)

func RegisterCSPReportRoutes(g fiber.Router) {
	// Public
	g.Post("/reports/add", controllers.PostCSPReport).Name("api.csp.reports.add")

	// Private
	g.Use(middlewares.AuthProtected(), middlewares.ValidateAccessToken(), middlewares.CheckPermissions())
	g.Get("/reports/all", controllers.GetAllCSPReports).Name("api.csp.reports.index")
	g.Get("/reports/get/:id<guid>", controllers.GetCSPReport).Name("api.csp.reports.get")
}
