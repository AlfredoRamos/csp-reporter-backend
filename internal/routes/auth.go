package routes

import (
	"alfredoramos.mx/csp-reporter/internal/controllers"
	"alfredoramos.mx/csp-reporter/internal/middlewares"
	"github.com/gofiber/fiber/v3"
)

func RegisterAuthRoutes(g fiber.Router) {
	// Auth
	g.Use(middlewares.AuthLimiter())

	// Public
	g.Post("/login", middlewares.HCaptchaProtected(), controllers.AuthLogin).Name("api.auth.login")
	g.Post("/register", middlewares.HCaptchaProtected(), controllers.AuthRegister).Name("api.auth.register")
	g.Post("/recover", middlewares.HCaptchaProtected(), controllers.AuthRecover).Name("api.auth.recover")
	g.Post("/recover/validate", controllers.AuthRecoverValidate).Name("api.auth.recover.validate") // Without captcha protection
	g.Patch("/recover/update", middlewares.HCaptchaProtected(), controllers.AuthRecoverUpdate).Name("api.auth.recover.update")

	// Private
	g.Patch("/refresh", middlewares.AuthProtected(), middlewares.ValidateRefreshToken(), middlewares.CheckPermissions(), controllers.AuthRefresh).Name("api.auth.refresh")

	// Private
	g.Use(middlewares.AuthProtected(), middlewares.ValidateAccessToken(), middlewares.CheckPermissions())
	g.Post("/check", controllers.AuthCheck).Name("api.auth.check")
	g.Post("/logout", controllers.AuthLogout).Name("api.auth.logout")
}
