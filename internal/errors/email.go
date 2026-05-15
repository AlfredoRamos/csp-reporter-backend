package errors

import "errors"

var (
	ErrEmailInvalidFromAddress = errors.New("the from email address is invalid")
	ErrEmailMissingData        = errors.New("missing information to send email")
	ErrEmailInvalidLocale      = errors.New("invalid message locale")
)
