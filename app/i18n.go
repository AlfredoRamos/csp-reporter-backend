package app

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"alfredoramos.mx/csp-reporter/utils"
	"github.com/BurntSushi/toml"
	"github.com/getsentry/sentry-go"
	"github.com/gofiber/fiber/v2"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

var (
	bundle        *i18n.Bundle
	allowedLangs  string
	onceLocalizer sync.Once
)

func Localizer(c *fiber.Ctx) *i18n.Localizer {
	onceLocalizer.Do(func() {
		defaultLang := strings.TrimSpace(os.Getenv("I18N_DEFAULT_LANG"))
		if len(defaultLang) < 1 {
			defaultLang = "en"
			slog.Warn(fmt.Sprintf("Default language not specified. Using fallback language '%s'.", defaultLang))
		}

		bundle = i18n.NewBundle(language.English)
		bundle.RegisterUnmarshalFunc("toml", toml.Unmarshal)

		allowedLangs = strings.TrimSpace(os.Getenv("I18N_ALLOWED_LANGS"))

		if len(allowedLangs) < 1 {
			allowedLangs = defaultLang
			slog.Warn(fmt.Sprintf("Allowed languages not specified. Using default language '%s'.", defaultLang))
		}

		langList := utils.CleanStringList(utils.SplitAny(allowedLangs, utils.SplitChars))

		for _, lang := range langList {
			lang = strings.ToLower(strings.TrimSpace(lang))

			langFile, err := filepath.Abs(filepath.Clean(filepath.Join("i18n", fmt.Sprintf("active.%s.toml", lang))))
			if err != nil {
				sentry.CaptureException(err)
				slog.Error(fmt.Sprintf("Could not read translation file at %s: %v", langFile, err))
				continue
			}

			if _, err := bundle.LoadMessageFile(langFile); err != nil {
				sentry.CaptureException(err)
				slog.Error(fmt.Sprintf("Could not load translation file: %v", err))
				continue
			}
		}
	})

	langs := []string{}
	lang := utils.CleanString(c.Query("lang"))
	accept := utils.CleanString(c.Get("Accept-Language"))

	if len(lang) > 0 {
		langs = append(langs, lang)
	}

	if len(accept) > 0 {
		langs = append(langs, accept)
	}

	return i18n.NewLocalizer(bundle, langs...)
}

func Translate(c *fiber.Ctx, conf *i18n.LocalizeConfig) string {
	return Localizer(c).MustLocalize(conf)
}
