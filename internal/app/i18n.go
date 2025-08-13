package app

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"alfredoramos.mx/csp-reporter/internal/env"
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
		lang := env.String("I18N_DEFAULT_LANG", "en-US")

		var err error
		defaultLanguage, err = language.Parse(lang)
		if err != nil {
			sentry.CaptureException(err)
			defaultLanguage = language.AmericanEnglish
			slog.Error(
				"Could not get tag from default language",
				slog.String("lang", defaultLanguage.String()),
				slog.Any("error", err),
			)
		}
	})

	return defaultLanguage
}

func AllowedLanguages() []language.Tag {
	onceAllowedLanguages.Do(func() {
		defaultLang := DefaultLanguage()
		allowedLangsStr := env.String("I18N_ALLOWED_LANGS", env.String("I18N_DEFAULT_LANG", "en-US"))

		if len(allowedLangsStr) > 0 {
			langList := utils.CleanStringList(utils.SplitAny(allowedLangsStr, utils.SplitChars))
			langBundle := languageBundle()

			for _, lang := range langList {
				lang = strings.ToLower(strings.TrimSpace(lang))
				langTag, err := language.Parse(lang)
				if err != nil {
					sentry.CaptureException(err)
					slog.Error(
						"Could not get allowed tag from language",
						slog.String("lang", lang),
						slog.Any("error", err),
					)
				}

				baseLang, confidence := langTag.Base()
				if confidence < language.Low {
					continue
				}

				langFile, err := filepath.Abs(filepath.Clean(filepath.Join("internal", "i18n", fmt.Sprintf("active.%s.toml", baseLang))))
				if err != nil {
					sentry.CaptureException(err)
					slog.Error(
						"Could not read translation",
						slog.String("file", langFile),
						slog.Any("error", err),
					)
					continue
				}

				if _, err := langBundle.LoadMessageFile(langFile); err != nil {
					sentry.CaptureException(err)
					slog.Error("Could not load translation", slog.Any("error", err))
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
			slog.Error(
				"Could not get context tag from language",
				slog.String("lang", lang),
				slog.Any("error", err),
			)
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
			slog.Error(
				"Could not get lang API tag from language",
				slog.String("lang", lang),
				slog.Any("error", err),
			)
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
			slog.Error(
				"Could not get Accept-Language API tag from language",
				slog.String("lang", accept),
				slog.Any("error", err),
			)
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
		langList = append(langList, tag.String())
	}

	return i18n.NewLocalizer(languageBundle(), langList...).MustLocalize(conf)
}
