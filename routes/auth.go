package routes

import (
	"alfredoramos.mx/csp-reporter/controllers"
	"alfredoramos.mx/csp-reporter/middlewares"
	"github.com/gofiber/fiber/v2"
)

func RegisterAuthRoutes(g fiber.Router) {
	// Auth
	g.Use(middlewares.AuthLimiter())

	// Public
	g.Post("/login", middlewares.CaptchaProtected(), controllers.AuthLogin)
	g.Post("/register", middlewares.CaptchaProtected(), controllers.AuthRegister)
	g.Post("/recover", middlewares.CaptchaProtected(), controllers.AuthRecover)
	g.Post("/recover/validate", controllers.AuthRecoverValidate) // Without captcha protection
	g.Patch("/recover/update", middlewares.CaptchaProtected(), controllers.AuthRecoverUpdate)

	// Private
	g.Use(middlewares.AuthProtected(), middlewares.ValidateAccessToken(), middlewares.CheckPermissions())
	g.Post("/check", controllers.AuthCheck)
	g.Post("/logout", controllers.AuthLogout)
	g.Patch("/refresh", middlewares.ValidateRefreshToken(), controllers.AuthRefresh)
}
