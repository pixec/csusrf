package csusrf

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

type Manager struct {
	secret         []byte
	headerName     string
	trustedOrigins []string
	cookieOpts     CookieOptions
	errorHandler   http.Handler
}

type ManagerOption func(m *Manager)

func WithHeaderName(headerName string) ManagerOption {
	return func(m *Manager) {
		m.headerName = headerName
	}
}

func WithTrustedOrigins(trustedOrigins []string) ManagerOption {
	return func(m *Manager) {
		m.trustedOrigins = trustedOrigins
	}
}

func WithCookieOpts(cookieOpts CookieOptions) ManagerOption {
	return func(m *Manager) {
		m.cookieOpts = cookieOpts
	}
}

func WithErrorHandler(errorHandler http.Handler) ManagerOption {
	return func(m *Manager) {
		m.errorHandler = errorHandler
	}
}

// NewManager returns a new Manager with the specified options.
func NewManager(secret []byte, opts ...ManagerOption) *Manager {
	m := &Manager{
		secret: secret,
	}

	for _, opt := range opts {
		opt(m)
	}

	if m.headerName == "" {
		m.headerName = "X-CSRF-TOKEN"
	}

	if m.errorHandler == nil {
		m.errorHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			csusrfErr, _ := FromContext[error](r.Context(), ErrCtxKey)

			http.Error(w, csusrfErr.Error(), http.StatusForbidden)
		})
	}

	return m
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

// GenerateToken creates a new CSRF token for the given session.
//
// It generates a random byte slice, encodes it using base64,
// and combines it with the provided sessionID. The resulting
// message is then hashed using HMAC SHA-256.
// The final CSRF token is a combination of the base64-encoded
// hash and the original message, separated by a colon (:).
//
// sessionID should be empty if user is not unauthenticated.
func (m *Manager) GenerateToken(sessionID string) (string, error) {
	rb, err := m.GenerateRandomBytes()
	if err != nil {
		return "", err
	}

	message := sessionID + "-" + base64.StdEncoding.EncodeToString(rb)
	hash := m.Hash(message)
	tok := base64.StdEncoding.EncodeToString(hash) + ":" + message

	return tok, nil
}

// VerifyToken checks the validity of the given CSRF token.
func (m *Manager) VerifyToken(tok string) error {
	spTok := strings.Split(tok, ":")
	if len(spTok) != 2 {
		return ErrBadToken
	}

	hash := spTok[0]
	message := spTok[1]
	hash2 := base64.StdEncoding.EncodeToString(m.Hash(message))

	// Use constant time comparison to avoid timings attack.
	if subtle.ConstantTimeCompare([]byte(hash), []byte(hash2)) == 0 {
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
			tok, err := m.GenerateToken("")
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

			if r.Header.Get(m.headerName) != cookie.Value {
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
