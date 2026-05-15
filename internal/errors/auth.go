package errors

import "errors"

var (
	ErrEmptyAccessToken    = errors.New("the access token is empty")
	ErrInvalidAccessToken  = errors.New("the access token provided is invalid")
	ErrExpiredAccessToken  = errors.New("the access token has expired")
	ErrEmptyRefreshToken   = errors.New("the refresh token is empty")
	ErrExpiredRefreshToken = errors.New("the refresh token has expired")

	ErrAuthShortPassword      = errors.New("the password length is lower than the minimum allowed")
	ErrAuthWeakPassword       = errors.New("the password is not strong enough")
	ErrAuthLowEntropyPassword = errors.New("the password entropy is low")
	ErrAuthInvalidPassword    = errors.New("the password is invalid")
	ErrAuthInvalidUserID      = errors.New("the user ID is invalid")

	ErrJwtInvalidIssuer    = errors.New("the issuer is invalid")
	ErrJwtInvalidSubject   = errors.New("the subject is invalid")
	ErrJwtInvalidUserID    = errors.New("the user ID is invalid")
	ErrJwtInvalidUserEmail = errors.New("the user email is invalid")
	ErrJwtInvalidUserRoles = errors.New("the user roles are invalid")
	ErrJwtEmptyJwe         = errors.New("the JWE token is empty")

	ErrArgonInvalidHashFormat = errors.New("the format of the encoded hash is invalid")
	ErrArgonInvalidAlgorithm  = errors.New("the version of the Argon2 algorithm is not compatible")

	ErrDecryptShortCipherText = errors.New("the ciphertext is too short")
)
