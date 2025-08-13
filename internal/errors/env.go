package errors

import "errors"

var (
	ErrTooManyDefaultValues = errors.New("too many default values passed")
)
