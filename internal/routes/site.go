package routes

import (
	"alfredoramos.mx/csp-reporter/internal/controllers"
	"alfredoramos.mx/csp-reporter/internal/middlewares"
	"github.com/gofiber/fiber/v2"
)

func RegisterSiteRoutes(g fiber.Router) {
	// Private
	g.Use(middlewares.AuthProtected(), middlewares.ValidateAccessToken(), middlewares.CheckPermissions())
	g.Get("/all", controllers.GetAllSites).Name("api.sites.index")
	g.Post("/add", controllers.PostSite).Name("api.sites.add")
}
