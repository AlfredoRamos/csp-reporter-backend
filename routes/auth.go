package routes

import (
	"alfredoramos.mx/csp-reporter/controllers"
	"alfredoramos.mx/csp-reporter/middlewares"
	"github.com/gofiber/fiber/v2"
)

func RegisterAuthRoutes(g fiber.Router) {
	// Public
	g.Post("/login", middlewares.AuthLimiter(), middlewares.CaptchaProtected(), controllers.AuthLogin)
	g.Post("/register", middlewares.AuthLimiter(), middlewares.CaptchaProtected(), controllers.AuthRegister)
	g.Post("/recover", middlewares.AuthLimiter(), middlewares.CaptchaProtected(), controllers.AuthRecover)
	g.Post("/recover/validate", middlewares.AuthLimiter(), controllers.AuthRecoverValidate) // Without captcha protection
	g.Patch("/recover/update", middlewares.AuthLimiter(), middlewares.CaptchaProtected(), controllers.AuthRecoverUpdate)

	// Private
	g.Use(middlewares.AuthProtected(), middlewares.ValidateJWT(), middlewares.CheckPermissions())
	g.Post("/check", controllers.AuthCheck)
	g.Post("/logout", controllers.AuthLogout)
	g.Patch("/refresh", middlewares.AuthLimiter(), controllers.AuthRefresh)
}
