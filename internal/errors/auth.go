package errors

import "errors"

var (
	ErrExpiredAccessToken     = errors.New("the access token has expired")
	ErrExpiredRefreshToken    = errors.New("the refresh token has expired")
	ErrAuthShortPassword      = errors.New("the password length is lower than the minimum allowed")
	ErrAuthWeakPassword       = errors.New("the password is not strong enough")
	ErrAuthLowEntropyPassword = errors.New("the password entropy is low")
	ErrAuthInvalidPassword    = errors.New("the password is invalid")
)
