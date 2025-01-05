package middlewares

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"alfredoramos.mx/csp-reporter/internal/app"
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
		if !utils.IsProduction() {
			disableEnv, err := strconv.ParseBool(os.Getenv("HCAPTCHA_DISABLE"))
			if err != nil {
				disableEnv = false
			}

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
			slog.Error(fmt.Sprintf("Error parsing input data: %v", err))

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
			slog.Error(fmt.Sprintf("Could not parse agent: %v", err))

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
		args.Set("sitekey", os.Getenv("HCAPTCHA_SITE_KEY"))
		args.Set("secret", os.Getenv("HCAPTCHA_SECRET_KEY"))
		args.Set("response", input.Response)
		args.Set("remoteip", c.IP())

		agent.Form(args)
		defer fiber.ReleaseArgs(args)

		status, body, errList := agent.Bytes()
		if len(errList) > 0 {
			sentry.CaptureException(errors.Join(errList...))
			slog.Error(fmt.Sprintf("Could not read response body and got HTTP '%d' status code: %v", status, errList))
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
			slog.Error(fmt.Sprintf("Could not decode response: %v", err))

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
			slog.Error(fmt.Sprintf("Could not verify captcha response: %v", response.Errors))
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
