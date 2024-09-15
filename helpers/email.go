package helpers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime/multipart"
	"os"
	"path/filepath"
	"time"

	html_tpl "html/template"
	text_tpl "text/template"

	"alfredoramos.mx/csp-reporter/app"
	"alfredoramos.mx/csp-reporter/models"
	"alfredoramos.mx/csp-reporter/utils"
	"github.com/redis/rueidis"
	"github.com/wneessen/go-mail"
)

const (
	mibMultiplier int64 = 1024 * 1024
	maxFileSize   int64 = 3 * mibMultiplier
)

type EmailOpts struct {
	Subject        string                  `json:"subject"`
	TemplateName   string                  `json:"template_name"`
	ToList         []string                `json:"to_list"`
	CCList         []string                `json:"cc_list"`
	BCCList        []string                `json:"bcc_list"`
	AttachmentList []*multipart.FileHeader `json:"attachment_list"`
	IsInternal     bool                    `json:"is_internal"`
}

func (e EmailOpts) IsValid() bool {
	return len(e.Subject) > 0 && len(e.TemplateName) > 0 && len(e.ToList) > 0
}

func SendEmail(opts EmailOpts, data map[string]interface{}) error {
	if len(os.Getenv("EMAIL_FROM")) < 1 {
		return errors.New("The from email address is invalid.")
	}

	if !opts.IsValid() {
		return errors.New("Missing information to send email.")
	}

	tplBase := filepath.Clean(filepath.Join("templates", "email", opts.TemplateName))

	htmlTplFile := filepath.Clean(tplBase + ".html")
	htmlTpl, err := html_tpl.New(filepath.Base(htmlTplFile)).ParseFiles(htmlTplFile)
	if err != nil {
		return fmt.Errorf("Error loading the HTML template: %w", err)
	}

	textTplFile := filepath.Clean(tplBase + ".txt")
	textTpl, err := text_tpl.New(filepath.Base(textTplFile)).ParseFiles(textTplFile)
	if err != nil {
		return fmt.Errorf("Error loading the TEXT template: %w", err)
	}

	// Init message
	msg := mail.NewMsg()
	msg.SetMessageID()
	msg.SetDate()
	msg.SetBulk()
	msg.Subject(opts.Subject + " • " + os.Getenv("APP_NAME"))

	if err := msg.FromFormat(os.Getenv("APP_NAME"), os.Getenv("EMAIL_FROM")); err != nil {
		return fmt.Errorf("Could not set the from email address: %w", err)
	}

	if !opts.IsInternal && len(utils.SupportEmail()) > 0 {
		if err := msg.ReplyTo(utils.SupportEmail()); err != nil {
			return fmt.Errorf("Could not set the reply-to email address: %w", err)
		}
	}

	// Default values
	data["Lang"] = utils.EmailLang()
	data["AppName"] = os.Getenv("APP_NAME")
	data["AppDescription"] = os.Getenv("APP_DESCRIPTION")
	data["AppLogo"] = os.Getenv("APP_LOGO")
	data["AppDomain"] = os.Getenv("APP_DOMAIN")
	data["CompanyName"] = os.Getenv("COMPANY_NAME")
	data["CompanyURL"] = os.Getenv("COMPANY_URL")
	data["Subject"] = opts.Subject
	data["Now"] = time.Now().In(utils.DefaultLocation())

	if err := msg.SetBodyHTMLTemplate(htmlTpl, data); err != nil {
		return fmt.Errorf("Error setting HTML template: %w", err)
	}

	if err := msg.AddAlternativeTextTemplate(textTpl, data); err != nil {
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
	if err != nil && !errors.Is(err, rueidis.Nil) {
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
		slog.Error(fmt.Sprintf("Could not save superadministrator email list to cache: %v", err))
	}

	return e
}
