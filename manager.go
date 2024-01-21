package csusrf

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

type Manager struct {
	secret         []byte
	trustedOrigins []string
	cookieOpts     CookieOptions
	errorHandler   http.Handler
}

// NewManager returns a new Manager with the specified secret, trusted origins, cookie options, and error handler.
func NewManager(secret []byte, trustedOrigins []string, cookieOpts CookieOptions, errorHandler http.Handler) *Manager {
	return &Manager{
		secret:         secret,
		trustedOrigins: trustedOrigins,
		cookieOpts:     cookieOpts,
		errorHandler:   errorHandler,
	}
}

// GenerateRandomBytes generates cryptographically secure random bytes.
func (m *Manager) GenerateRandomBytes() ([]byte, error) {
	b := make([]byte, sha256.Size)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	return b, nil
}

// Hash computes the HMAC SHA-256 hash of the given message using the Manager secret.
func (m *Manager) Hash(message string) []byte {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(message))

	return mac.Sum(nil)
}

// GenerateToken creates a new CSRF token.
func (m *Manager) GenerateToken() (string, error) {
	rb, err := m.GenerateRandomBytes()
	if err != nil {
		return "", err
	}

	message := hex.EncodeToString(rb)
	hash := m.Hash(message)
	tok := hex.EncodeToString(hash) + ":" + message

	return tok, nil
}

// VerifyToken checks the validity of the given CSRF token.
func (m *Manager) VerifyToken(tok string) error {
	spTok := strings.Split(tok, ":")
	if len(spTok) != 2 {
		return ErrBadToken
	}

	// subtle.ConstantTimeCompare will return 0 immediately if the lengths do not match.
	if len(spTok[0]) != 64 || len(spTok[1]) != 64 {
		return ErrBadToken
	}

	message := spTok[1]
	hash := m.Hash(message)
	tok2 := hex.EncodeToString(hash) + ":" + message

	if subtle.ConstantTimeCompare([]byte(tok), []byte(tok2)) == 0 {
		return ErrTokenMismatch
	}

	return nil
}

// Middleware is an HTTP middleware that provides CSRF protection.
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Retrieve the CSRF cookie from the request.
		cookie, err := r.Cookie(m.cookieOpts.Name)
		if errors.Is(err, http.ErrNoCookie) {
			// The request do not have CSRF cookie yet, so let's generate one.
			tok, err := m.GenerateToken()
			if err != nil {
				r = r.WithContext(context.WithValue(r.Context(), ErrCtxKey, err))
				m.errorHandler.ServeHTTP(w, r)
				return
			}

			cookie = m.cookieOpts.Cookie()
			cookie.Value = tok

			http.SetCookie(w, cookie)
		}

		// Add the CSRF token to the request context for downstream handlers.
		r = r.WithContext(context.WithValue(r.Context(), TokCtxKey, cookie.Value))

		if !slices.Contains(safeMethods, r.Method) {
			// Enforce referer header for now.
			if r.URL.Scheme == "https" {
				refererURL, err := url.Parse(r.Referer())
				if err != nil || refererURL.String() == "" {
					r = r.WithContext(context.WithValue(r.Context(), ErrCtxKey, ErrBadOrigin))
					m.errorHandler.ServeHTTP(w, r)
					return
				}

				valid := r.URL.Scheme == refererURL.Scheme && r.URL.Host == refererURL.Host
				if !valid && !slices.Contains(m.trustedOrigins, refererURL.Host) {
					r = r.WithContext(context.WithValue(r.Context(), ErrCtxKey, ErrUntrustedOrigin))
					m.errorHandler.ServeHTTP(w, r)
					return
				}
			}

			if r.Header.Get("X-CSRF-TOKEN") != cookie.Value {
				r = r.WithContext(context.WithValue(r.Context(), ErrCtxKey, ErrTokenMismatch))
				m.errorHandler.ServeHTTP(w, r)
				return
			}

			if err := m.VerifyToken(cookie.Value); err != nil {
				r = r.WithContext(context.WithValue(r.Context(), ErrCtxKey, err))
				m.errorHandler.ServeHTTP(w, r)
				return
			}
		}

		// Avoid clients from caching the response.
		w.Header().Add("Vary", "Cookie")

		next.ServeHTTP(w, r)
	})
}
