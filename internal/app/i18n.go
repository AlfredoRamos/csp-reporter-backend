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
	defaultLanguage      language.Tag
	allowedLangs         []language.Tag
	onceLanguageBundle   sync.Once
	onceDefaultLang      sync.Once
	onceAllowedLanguages sync.Once
)

func DefaultLanguage() language.Tag {
	onceDefaultLang.Do(func() {
		lang := os.Getenv("I18N_LANG")
		if len(lang) < 1 {
			lang = "en-US"
			slog.Warn(fmt.Sprintf("Default language not specified. Using fallback language '%s'.", lang))
		}

		var err error
		defaultLanguage, err = language.Parse(lang)
		if err != nil {
			sentry.CaptureException(err)
			defaultLanguage = language.AmericanEnglish
			slog.Error(fmt.Sprintf("Could not get tag from default language: '%v'. Using fallback '%s'.", err, defaultLanguage.String()))
		}
	})

	return defaultLanguage
}

func AllowedLanguages() []language.Tag {
	onceAllowedLanguages.Do(func() {
		defaultLang := DefaultLanguage()
		allowedLangsStr := strings.TrimSpace(os.Getenv("I18N_ALLOWED_LANGS"))

		if len(allowedLangsStr) > 0 {
			langList := utils.CleanStringList(utils.SplitAny(allowedLangsStr, utils.SplitChars))
			langBundle := languageBundle()

			for _, lang := range langList {
				lang = strings.ToLower(strings.TrimSpace(lang))
				langTag, err := language.Parse(lang)
				if err != nil {
					sentry.CaptureException(err)
					slog.Error(fmt.Sprintf("Could not get allowed tag from '%s' language: %v", lang, err))
				}

				baseLang, confidence := langTag.Base()
				if confidence < language.Low {
					continue
				}

				langFile, err := filepath.Abs(filepath.Clean(filepath.Join("internal", "i18n", fmt.Sprintf("active.%s.toml", baseLang))))
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

				if !slices.Contains(allowedLangs, langTag) {
					allowedLangs = append(allowedLangs, langTag)
				}
			}
		}

		if !slices.Contains(allowedLangs, defaultLang) || len(allowedLangs) < 1 {
			allowedLangs = append([]language.Tag{defaultLang}, allowedLangs...)
		}
	})

	return allowedLangs
}

func languageBundle() *i18n.Bundle {
	onceLanguageBundle.Do(func() {
		bundle = i18n.NewBundle(DefaultLanguage())
		bundle.RegisterUnmarshalFunc("toml", toml.Unmarshal)
	})

	return bundle
}

func GetLanguages(langList ...string) []language.Tag {
	allowed := AllowedLanguages()

	if len(langList) < 1 {
		return allowed
	}

	langs := []language.Tag{}

	for _, lang := range langList {
		langTag, err := language.Parse(lang)
		if err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Could not get context tag from '%s' language: %v", lang, err))
			continue
		}

		if !slices.Contains(allowed, langTag) {
			continue
		}

		langs = append([]language.Tag{langTag}, langs...)
	}

	langs = append(langs, allowed...)
	langs = utils.RemoveDuplicated(langs)

	return langs
}

func GetApiLanguages(c *fiber.Ctx, langList ...string) []language.Tag {
	langs := GetLanguages(langList...)

	if c == nil {
		return langs
	}

	allowed := AllowedLanguages()

	// Use ?lang=<lang> query
	lang := utils.CleanString(c.Query("lang"))
	if len(lang) > 0 {
		langTag, err := language.Parse(lang)
		if err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Could not get lang API tag from '%s' language: %v", lang, err))
		}

		if slices.Contains(allowed, langTag) {
			langs = append([]language.Tag{langTag}, langs...)
		}
	}

	// Use Accept-Language header
	accept := utils.CleanString(c.Get("Accept-Language"))
	if len(accept) > 0 {
		acceptTag, err := language.Parse(accept)
		if err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Could not get Accept-Language API tag from '%s' language: %v", accept, err))
		}

		if slices.Contains(allowed, acceptTag) {
			langs = append([]language.Tag{acceptTag}, langs...)
		}
	}

	// ! Must not get here
	if len(langs) < 1 {
		langs = allowed
	}

	return langs
}

func Translate(conf *i18n.LocalizeConfig, c *fiber.Ctx, langs ...string) string {
	langList := []string{}

	for _, tag := range GetApiLanguages(c, langs...) {
		base, confidence := tag.Base()
		if confidence < language.Low {
			continue
		}

		langList = append(langList, base.String())
	}

	return i18n.NewLocalizer(languageBundle(), langList...).MustLocalize(conf)
}
