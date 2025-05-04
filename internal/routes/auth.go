package routes

import (
	"alfredoramos.mx/csp-reporter/internal/controllers"
	"alfredoramos.mx/csp-reporter/internal/middlewares"
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
	g.Patch("/refresh", middlewares.AuthProtected(), middlewares.ValidateRefreshToken(), middlewares.CheckPermissions(), controllers.AuthRefresh)
	g.Post("/mfa/verify", middlewares.AuthProtected(), middlewares.ValidateIntermediateToken(), middlewares.CheckPermissions(), controllers.AuthMFAVerify)

	// Private
	g.Use(middlewares.AuthProtected(), middlewares.ValidateAccessToken(), middlewares.CheckPermissions())
	g.Post("/check", controllers.AuthCheck)
	g.Post("/logout", controllers.AuthLogout)
	g.Post("/mfa/enable", controllers.AuthMFAEnable)
	g.Delete("/mfa/disable", controllers.AuthMFADisable)
}
