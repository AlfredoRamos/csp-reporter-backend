package routes

import (
	"alfredoramos.mx/csp-reporter/controllers"
	"alfredoramos.mx/csp-reporter/middlewares"
	"github.com/gofiber/fiber/v2"
)

func RegisterUserActivationRoutes(g fiber.Router) {
	// Private
	g.Use(middlewares.AuthProtected(), middlewares.ValidateJWT(), middlewares.CheckPermissions())
	g.Get("/users/all", controllers.GetAllInactiveUsers).Name("api.user-activations.index")
	g.Patch("/review/:id<guid>", controllers.UpdateUserActivation).Name("api.users.activation.update")
}
