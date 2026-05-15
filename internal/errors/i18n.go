package errors

import "errors"

var (
	ErrI18nInvalidContext      = errors.New("invalid context for API locale")
	ErrI18nInvalidLanguageList = errors.New("invalid language list from API context")
)
