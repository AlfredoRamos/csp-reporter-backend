package routes

import (
	"alfredoramos.mx/csp-reporter/controllers"
	"alfredoramos.mx/csp-reporter/middlewares"
	"github.com/gofiber/fiber/v2"
)

func RegisterSystemRoutes(g fiber.Router) {
	// Public
	g.Get("/csrf", controllers.GetCsrf).Name("api.system.csrf")

	// Private
	g.Use(middlewares.AuthProtected(), middlewares.ValidateAccessToken(), middlewares.CheckPermissions())
	g.Post("/cache/purge", controllers.PurgeCache).Name("api.system.cache.purge")
}
