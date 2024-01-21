package csusrf

import "errors"

var (
	ErrBadToken        = errors.New("csusrf: bad token was provided")
	ErrTokenMismatch   = errors.New("csusrf: csrf mismatch")
	ErrBadOrigin       = errors.New("csusrf: bad origin header was provided")
	ErrUntrustedOrigin = errors.New("csusrf: untrusted origin header was provided")
)
