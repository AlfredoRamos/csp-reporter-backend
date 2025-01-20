package helpers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
	"time"

	html_tpl "html/template"
	text_tpl "text/template"

	"alfredoramos.mx/csp-reporter/internal/app"
	"alfredoramos.mx/csp-reporter/internal/models"
	"alfredoramos.mx/csp-reporter/internal/utils"
	"github.com/getsentry/sentry-go"
	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/valkey-io/valkey-go"
	"github.com/wneessen/go-mail"
	"golang.org/x/text/language"
)

const (
	mibMultiplier int64 = 1024 * 1024
	maxFileSize   int64 = 3 * mibMultiplier
)

type MessageLocale struct {
	language string
	region   *string
}

// Custom marshaling for MessageLocale
func (m *MessageLocale) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"language": m.Language(),
		"region":   m.Region(),
	})
}

// Custom unmarshaling for MessageLocale
func (m *MessageLocale) UnmarshalJSON(data []byte) error {
	temp := struct {
		Language string  `json:"language"`
		Region   *string `json:"region"`
	}{}

	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	m.language = temp.Language
	m.region = temp.Region
	return nil
}

func (l *MessageLocale) Language() string {
	return l.language
}

func (l *MessageLocale) Region() *string {
	if l.region != nil {
		l.region = utils.ToStringPtr(strings.ToUpper(*l.region))
	}

	return l.region
}

func (l *MessageLocale) String() string {
	loc := l.Language()

	if l.Region() != nil && len(*l.Region()) > 0 {
		loc += "-" + *l.Region()
	}

	return strings.TrimSpace(loc)
}

func (l *MessageLocale) IsValid() bool {
	return len(l.language) > 0 && (l.region == nil || (l.region != nil && len(*l.region) > 0))
}

type EmailOpts struct {
	Subject        string                  `json:"subject"`
	TemplateName   string                  `json:"template_name"`
	ToList         []string                `json:"to_list"`
	CCList         []string                `json:"cc_list"`
	BCCList        []string                `json:"bcc_list"`
	AttachmentList []*multipart.FileHeader `json:"attachment_list,omitempty"`
	IsInternal     bool                    `json:"is_internal"`
	Locale         *MessageLocale          `json:"locale"`
}

func (e *EmailOpts) IsValid() bool {
	return len(e.Subject) > 0 && len(e.TemplateName) > 0 && len(e.ToList) > 0
}

func SendEmail(opts *EmailOpts, data map[string]interface{}) error {
	if !utils.IsValidEmail(os.Getenv("EMAIL_FROM")) {
		return errors.New("The from email address is invalid.")
	}

	if !opts.IsValid() {
		return errors.New("Missing information to send email.")
	}

	if opts.Locale == nil || !opts.Locale.IsValid() {
		opts.Locale = DefaultLocale()
	}

	lang := opts.Locale.Language()
	tplBase := filepath.Clean(filepath.Join("internal", "templates", "email", lang, opts.TemplateName))

	htmlTplFile := filepath.Clean(tplBase + ".html")
	htmlTpl, err := html_tpl.New(filepath.Base(htmlTplFile)).ParseFiles(htmlTplFile)
	if err != nil {
		sentry.CaptureException(err)
		return fmt.Errorf("Error loading the HTML template: %w", err)
	}

	textTplFile := filepath.Clean(tplBase + ".txt")
	textTpl, err := text_tpl.New(filepath.Base(textTplFile)).ParseFiles(textTplFile)
	if err != nil {
		sentry.CaptureException(err)
		return fmt.Errorf("Error loading the TEXT template: %w", err)
	}

	// Init message
	msg := mail.NewMsg(mail.WithNoDefaultUserAgent(), mail.WithMiddleware(utils.NewDkimMiddleware()))
	msg.SetMessageID()
	msg.SetDate()
	msg.SetBulk()
	msg.Subject(opts.Subject + " • " + os.Getenv("APP_NAME"))
	msg.SetGenHeader(mail.HeaderContentLang, lang)

	if !utils.IsValidEmail(os.Getenv("EMAIL_FROM")) {
		err := errors.New("The from email address is invalid.")
		sentry.CaptureException(err)
		return err
	}

	if err := msg.FromFormat(os.Getenv("APP_NAME"), os.Getenv("EMAIL_FROM")); err != nil {
		sentry.CaptureException(err)
		return fmt.Errorf("Could not set the from email address: %w", err)
	}

	if !opts.IsInternal && len(utils.SupportEmail()) > 0 {
		if err := msg.ReplyTo(utils.SupportEmail()); err != nil {
			sentry.CaptureException(err)
			return fmt.Errorf("Could not set the reply-to email address: %w", err)
		}
	}

	// Default values
	data["Lang"] = lang
	data["AppName"] = os.Getenv("APP_NAME")
	data["AppDescription"] = os.Getenv("APP_DESCRIPTION")
	data["AppLogo"] = os.Getenv("APP_LOGO")
	data["AppDomain"] = os.Getenv("APP_DOMAIN")
	data["CompanyName"] = os.Getenv("COMPANY_NAME")
	data["CompanyURL"] = os.Getenv("COMPANY_URL")
	data["Subject"] = opts.Subject
	data["Now"] = time.Now().In(utils.DefaultLocation())

	if err := msg.SetBodyHTMLTemplate(htmlTpl, data); err != nil {
		sentry.CaptureException(err)
		return fmt.Errorf("Error setting HTML template: %w", err)
	}

	if err := msg.AddAlternativeTextTemplate(textTpl, data); err != nil {
		sentry.CaptureException(err)
		return fmt.Errorf("Error setting TEXT template: %w", err)
	}

	msg.ToIgnoreInvalid(opts.ToList...)

	if len(opts.CCList) > 0 {
		msg.CcIgnoreInvalid(opts.CCList...)
	}

	opts.BCCList = GetSuperAdminEmails()

	if len(opts.BCCList) > 0 {
		msg.BccIgnoreInvalid(opts.BCCList...)
	}

	if len(opts.AttachmentList) > 0 {
		validMIMETypes := []string{"application/pdf"}

		for _, f := range opts.AttachmentList {
			fileSize := f.Size / mibMultiplier

			if !utils.HasValidMimeType(f, validMIMETypes) || fileSize > maxFileSize {
				slog.Warn(fmt.Sprintf("Ignoring invalid document: ['%s', '%s', %d MiB].", f.Filename, f.Header.Get("Content-Type"), fileSize))
				continue
			}

			msg.AttachFile(f.Filename, mail.WithFileName(f.Filename))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return app.SMTP().DialAndSendWithContext(ctx, msg)
}

func GetSuperAdminEmails() []string {
	e := []string{}

	// Try to load from cache
	ce, err := app.Cache().DoCache(context.Background(), app.Cache().B().Get().Key("email:superadmin:list").Cache(), 5*time.Minute).ToString()
	if err != nil && !errors.Is(err, valkey.Nil) {
		sentry.CaptureException(err)
		slog.Warn(fmt.Sprintf("Could not get cached superadministrator email list: %v", err))
	}

	if len(ce) > 0 {
		if err := json.Unmarshal([]byte(ce), &e); err != nil {
			slog.Error(fmt.Sprintf("Could not decode cached superadministrator email list: %v", err))
		} else {
			return e
		}
	}

	if err := app.DB().Model(&models.UserRole{}).
		Joins("INNER JOIN roles r ON user_roles.role_id = r.id").
		Joins("INNER JOIN users u ON user_roles.user_id = u.id").
		Select("u.email").
		Where("r.name = @role_name AND user_roles.deleted_at IS NULL AND r.deleted_at IS NULL AND u.active = @user_active AND u.deleted_at IS NULL", sql.Named("role_name", "superadmin"), sql.Named("user_active", true)).
		Limit(5).Find(&e).Error; err != nil {
		slog.Error(fmt.Sprintf("Could not get superadministrator emails: %v", err))
	}

	re, err := json.Marshal(e)
	if err != nil {
		slog.Error(fmt.Sprintf("Could not serialize superadministrator email list for cache: %v", err))
	}

	if err := app.Cache().Do(context.Background(), app.Cache().B().Set().Key("email:superadmin:list").Value(string(re)).Ex(15*time.Minute).Build()).Error(); err != nil {
		sentry.CaptureException(err)
		slog.Error(fmt.Sprintf("Could not save superadministrator email list to cache: %v", err))
	}

	return e
}

func DefaultLocale() *MessageLocale {
	loc, err := ParseLocale(utils.ToStringPtr(app.DefaultLanguage().String()))
	if err != nil {
		sentry.CaptureException(err)
		slog.Error(fmt.Sprintf("Could not parse locale: %v", err))
		return &MessageLocale{}
	}

	return loc
}

func ParseLocale(locale *string) (*MessageLocale, error) {
	if locale == nil {
		return &MessageLocale{}, errors.New("Invalid message locale.")
	}

	// * Custom locale overwrite
	switch *locale {
	case "es":
		locale = utils.ToStringPtr("es-MX")
	case "en":
		locale = utils.ToStringPtr("en-US")
	}

	tag, err := language.Parse(*locale)
	if err != nil {
		sentry.CaptureException(err)
		slog.Error(fmt.Sprintf("Could not parse locale: %v", err))
		return &MessageLocale{}, err
	}

	sl := &MessageLocale{}

	base, confidence := tag.Base()
	if confidence >= language.High {
		sl.language = base.String()
	}

	region, confidence := tag.Region()
	if confidence >= language.High {
		sl.region = utils.ToStringPtr(region.String())
	}

	// ! Must not get here
	if !sl.IsValid() {
		err := errors.New("Could not generate valid message locale.")
		sentry.CaptureException(err)
		slog.Error(err.Error())
		return &MessageLocale{}, err
	}

	return sl, nil
}

func ParseApiLocale(c *fiber.Ctx) *MessageLocale {
	defaultLocale := DefaultLocale()

	if c == nil {
		err := errors.New("Invalid context for API locale. Falling back to default locale.")
		sentry.CaptureException(err)
		slog.Error(err.Error())
		return defaultLocale
	}

	langs := app.GetApiLanguages(c)

	if len(langs) < 1 {
		err := errors.New("Invalid language list from API context. Falling back to default locale.")
		sentry.CaptureException(err)
		slog.Error(err.Error())
		return defaultLocale
	}

	loc, err := ParseLocale(utils.ToStringPtr(langs[0].String()))
	if err != nil {
		sentry.CaptureException(err)
		slog.Error(fmt.Sprintf("Could not parse locale from API context. Falling back to default locale: %v", err))
		return defaultLocale
	}

	return loc
}
