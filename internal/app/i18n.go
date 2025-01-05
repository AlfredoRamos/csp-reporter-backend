package app

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"alfredoramos.mx/csp-reporter/internal/utils"
	"github.com/BurntSushi/toml"
	"github.com/getsentry/sentry-go"
	"github.com/gofiber/fiber/v2"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

var (
	bundle               *i18n.Bundle
	defaultLanguage      string
	allowedLangs         []string
	onceLanguageBundle   sync.Once
	onceDefaultLang      sync.Once
	onceAllowedLanguages sync.Once
)

func DefaultLanguage() string {
	onceDefaultLang.Do(func() {
		defaultLanguage = os.Getenv("I18N_DEFAULT_LANG")
		if len(defaultLanguage) < 1 {
			defaultLanguage = "en"
			slog.Warn(fmt.Sprintf("Default language not specified. Using fallback language '%s'.", defaultLanguage))
		}
	})

	return defaultLanguage
}

func AllowedLanguages() []string {
	onceAllowedLanguages.Do(func() {
		defaultLang := DefaultLanguage()
		allowedLangsStr := strings.TrimSpace(os.Getenv("I18N_ALLOWED_LANGS"))

		if len(allowedLangsStr) < 1 {
			allowedLangsStr = defaultLang
			slog.Warn(fmt.Sprintf("Allowed languages not specified. Using default language '%s'.", defaultLang))
		}

		langList := utils.CleanStringList(utils.SplitAny(allowedLangsStr, utils.SplitChars))
		langBundle := languageBundle()

		for _, lang := range langList {
			lang = strings.ToLower(strings.TrimSpace(lang))
			langFile, err := filepath.Abs(filepath.Clean(filepath.Join("internal", "i18n", fmt.Sprintf("active.%s.toml", lang))))
			if err != nil {
				sentry.CaptureException(err)
				slog.Error(fmt.Sprintf("Could not read translation file at %s: %v", langFile, err))
				continue
			}

			if _, err := langBundle.LoadMessageFile(langFile); err != nil {
				sentry.CaptureException(err)
				slog.Error(fmt.Sprintf("Could not load translation file: %v", err))
				continue
			}

			if !slices.Contains(allowedLangs, lang) {
				allowedLangs = append(allowedLangs, lang)
			}
		}

		if !slices.Contains(allowedLangs, defaultLang) || len(allowedLangs) < 1 {
			allowedLangs = append([]string{defaultLang}, allowedLangs...)
		}
	})

	return allowedLangs
}

func languageBundle() *i18n.Bundle {
	onceLanguageBundle.Do(func() {
		defaultLang := DefaultLanguage()

		langTag, err := language.Parse(defaultLang)
		if err != nil {
			sentry.CaptureException(err)
			langTag = language.English
			slog.Error(fmt.Sprintf("Could not get tag from default language '%v'. Using fallback '%s'.", err, langTag.String()))
		}

		bundle = i18n.NewBundle(langTag)
		bundle.RegisterUnmarshalFunc("toml", toml.Unmarshal)
	})

	return bundle
}

func GetLanguages(langList ...string) []string {
	allowed := AllowedLanguages()
	langs := []string{}

	if len(langList) > 0 {
		langs = append(langs, langList...)
	}

	langs = append(langs, allowed...)
	langs = utils.RemoveDuplicated(langs)

	return langs
}

func GetApiLanguages(c *fiber.Ctx, langList ...string) []string {
	if c == nil {
		return GetLanguages(langList...)
	}

	allowed := AllowedLanguages()
	langs := []string{}

	lang := utils.CleanString(c.Query("lang"))
	accept := utils.CleanString(c.Get("Accept-Language"))

	if len(lang) > 0 && slices.Contains(allowed, lang) {
		langs = append(langs, lang)
	}

	if len(accept) > 0 && slices.Contains(allowed, accept) {
		langs = append(langs, accept)
	}

	return langs
}

func Translate(conf *i18n.LocalizeConfig, c *fiber.Ctx, langs ...string) string {
	return i18n.NewLocalizer(languageBundle(), GetApiLanguages(c, langs...)...).MustLocalize(conf)
}
