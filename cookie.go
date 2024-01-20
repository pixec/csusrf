package csusrf

import (
	"net/http"
	"time"
)

type CookieOptions struct {
	Name     string
	Path     string
	Domain   string
	MaxAge   int
	Secure   bool
	HttpOnly bool
	SameSite http.SameSite
}

// DefaultCookieOptions returns the default CookieOptions for CSRF cookie.
//
// This function provides default values for initializing a CookieOptions instance
// when setting up CSRF protection.
func DefaultCookieOptions() CookieOptions {
	return CookieOptions{
		Name:     "csusrf_tok",
		Path:     "/",
		Domain:   "",
		MaxAge:   3600 * 12,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// Cookie returns an HTTP cookie initialized with the settings specified in CookieOptions.
//
// If the MaxAge is greater than 0, the function sets the Expires field based on the
// current time and the specified MaxAge. This allows the CSRF cookie to expire
// after the specified duration.
func (c CookieOptions) Cookie() *http.Cookie {
	cookie := &http.Cookie{
		Name:     c.Name,
		Path:     c.Path,
		Domain:   c.Domain,
		MaxAge:   c.MaxAge,
		Secure:   c.Secure,
		HttpOnly: c.HttpOnly,
		SameSite: c.SameSite,
	}

	if c.MaxAge > 0 {
		cookie.Expires = time.Now().Add(time.Duration(c.MaxAge) * time.Second)
	}

	return cookie
}
