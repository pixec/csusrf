package csusrf

import "errors"

var (
	ErrInvalidToken  = errors.New("csusrf: invalid token given")
	ErrInvalidOrigin = errors.New("csusrf: invalid origin/referer header given")
)
