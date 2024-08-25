package middlewares

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"alfredoramos.mx/csp-reporter/utils"
	"github.com/gofiber/fiber/v2"
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
		if utils.IsDebug() {
			disableEnv, err := strconv.ParseBool(os.Getenv("HCAPTCHA_DISABLE"))
			if err != nil {
				disableEnv = false
			}

			disableHeader, err := strconv.ParseBool(c.Get("X-Disable-Captcha"))
			if err != nil {
				disableHeader = false
			}

			if disableEnv && disableHeader {
				return c.Next()
			}
		}

		input := CaptchaRequest{}
		if err := c.BodyParser(&input); err != nil {
			slog.Error(fmt.Sprintf("Error parsing input data: %v", err))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"Invalid captcha data."},
			})
		}

		errs := fiber.Map{}

		if len(input.Response) < 1 {
			errs = utils.AddError(errs, "captcha", "The captcha response is invalid.")
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
			slog.Error(fmt.Sprintf("Could not parse agent: %v", err))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"Could not validate captcha response."},
			})
		}

		args := fiber.AcquireArgs()
		args.Set("sitekey", os.Getenv("HCAPTCHA_SITE_KEY"))
		args.Set("secret", os.Getenv("HCAPTCHA_SECRET_KEY"))
		args.Set("response", input.Response)
		args.Set("remoteip", c.IP())

		agent.Form(args)
		fiber.ReleaseArgs(args)

		status, body, errList := agent.Bytes()
		if len(errList) > 0 {
			slog.Error(fmt.Sprintf("Could not read response body and got HTTP '%d' status code.", status))
			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": errList,
			})
		}

		fiber.ReleaseAgent(agent)

		response := &CaptchaResponse{}
		if err := json.Unmarshal(body, &response); err != nil {
			slog.Error(fmt.Sprintf("Could not decode response: %v", err))

			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": []string{"Could not validate captcha response."},
			})
		}

		if response.Success {
			return c.Next()
		} else if !response.Success && len(response.Errors) > 0 {
			return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
				"error": response.Errors,
			})
		}

		return c.Status(fiber.StatusForbidden).JSON(&fiber.Map{
			"error": []string{"Could not validate captcha response."},
		})
	}
}
