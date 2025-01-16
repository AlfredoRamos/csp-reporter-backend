package errors

import "errors"

var (
	ErrExpiredAccessToken     = errors.New("The access token has expired.")
	ErrExpiredRefreshToken    = errors.New("The refresh token has expired.")
	ErrAuthShortPassword      = errors.New("The password length is lower than the minimum allowed.")
	ErrAuthWeakPassword       = errors.New("The password is not strong enough.")
	ErrAuthLowEntropyPassword = errors.New("The password entropy is low.")
	ErrAuthInvalidPassword    = errors.New("The password is invalid.")
)
