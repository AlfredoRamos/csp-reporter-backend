package middlewares

import (
	"errors"
	"log/slog"
	"strconv"
	"strings"

	"alfredoramos.mx/csp-reporter/internal/app"
	"alfredoramos.mx/csp-reporter/internal/env"
	"alfredoramos.mx/csp-reporter/internal/utils"
	"github.com/getsentry/sentry-go"
	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/nicksnyder/go-i18n/v2/i18n"
)

const hcaptchaApiUrl string = "https://api.hcaptcha.com/siteverify"

type CaptchaRequest struct {
	Response string `json:"captcha"`
}

type CaptchaResponse struct {
	Success       bool     `json:"success"`
	Credit        bool     `json:"credit,omitempty"`
	Hostname      string   `json:"hostname,omitempty"`
	ChallengeTime string   `json:"challenge_ts,omitempty"`
	Errors        []string `json:"error-codes,omitempty"`
}

func CaptchaProtected() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !env.IsProduction() {
			disableEnv := env.Bool("HCAPTCHA_DISABLE", false)

			disableHeader, err := strconv.ParseBool(c.Get("X-Disable-Captcha"))
			if err != nil {
				disableHeader = false
			}

			if disableEnv && disableHeader {
				slog.Warn("Ignoring captcha middleware.")
				return c.Next()
			}
		}

		input := CaptchaRequest{}
		if err := c.BodyParser(&input); err != nil {
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

		agent := fiber.AcquireAgent()
		agent.Request().Header.SetMethod("POST")
		agent.Request().SetRequestURI(hcaptchaApiUrl)
		agent.Request().Header.SetUserAgent(c.Get("User-Agent"))

		if err := agent.Parse(); err != nil {
			sentry.CaptureException(err)
			slog.Error("Could not parse agent", slog.Any("error", err))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{app.Translate(&i18n.LocalizeConfig{
					DefaultMessage: &i18n.Message{
						ID:    "ErrorValidateCaptchaResponse",
						Other: "Could not validate captcha response.",
					},
				}, c)},
			})
		}

		args := fiber.AcquireArgs()
		args.Set("sitekey", env.String("HCAPTCHA_SITE_KEY"))
		args.Set("secret", env.String("HCAPTCHA_SECRET_KEY"))
		args.Set("response", input.Response)
		args.Set("remoteip", c.IP())

		agent.Form(args)
		defer fiber.ReleaseArgs(args)

		status, body, errList := agent.Bytes()
		if len(errList) > 0 {
			sentry.CaptureException(errors.Join(errList...))
			slog.Error(
				"Could not read response body and got invalid HTTP status code",
				slog.Int("status", status),
				slog.Any("error", errList),
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

		defer fiber.ReleaseAgent(agent)

		response := &CaptchaResponse{}
		if err := json.Unmarshal(body, &response); err != nil {
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

		if response.Success {
			return c.Next()
		} else if !response.Success && len(response.Errors) > 0 {
			slog.Error("Could not verify captcha response", slog.Any("error", strings.Join(response.Errors, "\n")))
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
