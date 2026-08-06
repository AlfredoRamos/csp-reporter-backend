package routes

import (
	"alfredoramos.mx/csp-reporter/internal/controllers"
	"alfredoramos.mx/csp-reporter/internal/middlewares"
	"github.com/gofiber/fiber/v2"
)

func RegisterDashboardRoutes(g fiber.Router) {
	// Private
	g.Use(middlewares.AuthProtected(), middlewares.ValidateAccessToken(), middlewares.CheckPermissions())
	g.Get("/reports/effective-directive", controllers.GetDashboardReportsByEffectiveDirective).Name("api.dashboard.reports.effective-directory")
}
