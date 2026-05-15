package errors

import "errors"

var (
	ErrInvalidEnvKey        = errors.New("invalid environment key")
	ErrTooManyDefaultValues = errors.New("too many default values passed")
	ErrInvalidAppKey        = errors.New("invalid application key")
)
