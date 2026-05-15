package middlewares

import (
	"log/slog"
	"strconv"
	"strings"

	"alfredoramos.mx/csp-reporter/internal/app"
	"alfredoramos.mx/csp-reporter/internal/env"
	"alfredoramos.mx/csp-reporter/internal/utils"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/client"
	"github.com/google/uuid"
	"github.com/nicksnyder/go-i18n/v2/i18n"
)

type turnstileRequest struct {
	Response string `json:"captcha"`
}

type turnstileResponse struct {
	Success       bool     `json:"success"`
	ChallengeTime string   `json:"challenge_ts,omitempty"`
	Hostname      string   `json:"hostname,omitempty"`
	Errors        []string `json:"error-codes,omitempty"`
	Action        string   `json:"action,omitempty"`
	CData         string   `json:"cdata,omitempty"`
	Metadata      struct {
		EphemeralID string `json:"ephemeral_id,omitempty"`
	} `json:"metadata,omitzero"`
}

func TurnstileProtected() fiber.Handler {
	return func(c fiber.Ctx) error {
		if !env.IsProduction() {
			disableEnv := env.Bool("CAPTCHA_DISABLE", false)

			disableHeader, err := strconv.ParseBool(c.Get("X-Disable-Captcha"))
			if err != nil {
				disableHeader = false
			}

			if disableEnv && disableHeader {
				slog.Warn("Ignoring captcha middleware.")
				return c.Next()
			}
		}

		input := turnstileRequest{}
		if err := c.Bind().Body(&input); err != nil {
			slog.Error("Error parsing input data", slog.Any("error", err))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{app.Translate(&i18n.LocalizeConfig{
					DefaultMessage: &i18n.Message{
						ID:    "ErrorInvalidCaptchaData",
						Other: "Invalid captcha data.",
					},
				}, c)},
			})
		}

		errs := fiber.Map{}

		if len(input.Response) < 1 {
			errs = utils.AddError(errs, "captcha", app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorInvalidCaptchaResponse",
					Other: "The captcha response is invalid.",
				},
			}, c))
		}

		if len(errs) > 0 {
			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": errs,
			})
		}

		client := client.New()
		client.SetBaseURL("https://challenges.cloudflare.com/turnstile/v0")
		client.SetUserAgent(c.Get("User-Agent"))

		request := client.R()
		request.SetFormData("secret", env.String("TURNSTILE_SECRET_KEY"))
		request.SetFormData("response", input.Response)
		request.SetFormData("remoteip", c.IP())
		request.SetFormData("idempotency_key", uuid.NewString())

		response, err := request.Post("/siteverify")
		if err != nil {
			//sentry.CaptureException(err)
			slog.Error(
				"Could not read response body and got invalid HTTP status code",
				slog.Int("status", response.StatusCode()),
				slog.Any("error", err),
			)
			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{app.Translate(&i18n.LocalizeConfig{
					DefaultMessage: &i18n.Message{
						ID:    "ErrorVerifyCaptchaResponse",
						Other: "Could not verify captcha data.",
					},
				}, c)},
			})
		}

		defer response.Close()

		res := &turnstileResponse{}
		if err := response.JSON(&res); err != nil {
			slog.Error("Could not decode response", slog.Any("error", err))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{app.Translate(&i18n.LocalizeConfig{
					DefaultMessage: &i18n.Message{
						ID:    "ErrorValidateCaptchaResponse",
						Other: "Could not validate captcha response.",
					},
				}, c)},
			})
		}

		if res.Success {
			return c.Next()
		} else if !res.Success && len(res.Errors) > 0 {
			slog.Error("Could not verify captcha response", slog.Any("error", strings.Join(res.Errors, "\n")))
			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{app.Translate(&i18n.LocalizeConfig{
					DefaultMessage: &i18n.Message{
						ID:    "ErrorInvalidCaptchaResponse",
						Other: "The captcha response is invalid.",
					},
				}, c)},
			})
		}

		return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
			"error": []string{app.Translate(&i18n.LocalizeConfig{
				DefaultMessage: &i18n.Message{
					ID:    "ErrorValidateCaptchaResponse",
					Other: "Could not validate captcha response.",
				},
			}, c)},
		})
	}
}
