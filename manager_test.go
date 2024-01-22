package csusrf_test

import (
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pixec/csusrf"
)

var (
	secretKey       = []byte("Sneaky crewmates play, Amogus impostors sway, Betrayal in space's bay.")
	testTok         = "8zKZgE99EYdwGdDbjgMLxO6I3n4enZ/O22bmJ7jLlYI=:-1KeZm/sVzBoKnCQ+1j8MjYf9w+CiFZxWzmr0CP7ywxA="
	reversedTestTok = "-1KeZm/sVzBoKnCQ+1j8MjYf9w+CiFZxWzmr0CP7ywxA=:8zKZgE99EYdwGdDbjgMLxO6I3n4enZ/O22bmJ7jLlYI="
	manager         = csusrf.NewManager(
		secretKey,
		csusrf.WithTrustedOrigins([]string{"a.example.com"}),
		csusrf.WithCookieOpts(csusrf.DefaultCookieOptions()),
	)
)

func TestManagerGenerateRandomBytes(t *testing.T) {
	b, err := manager.GenerateRandomBytes()
	if err != nil {
		t.Error(err)
	}

	if len(b) != sha256.Size {
		t.Errorf("expected %d bytes, got %d", sha256.Size, len(b))
	}
}

func TestManagerGenerateToken(t *testing.T) {
	if _, err := manager.GenerateToken(""); err != nil {
		t.Error(err)
	}
}

func TestManagerVerifyToken(t *testing.T) {
	if err := manager.VerifyToken(testTok); err != nil {
		t.Error(err)
	}
}

func TestManagerVerifyTokenBadToken(t *testing.T) {
	if err := manager.VerifyToken("1"); err != nil {
		if !errors.Is(err, csusrf.ErrBadToken) {
			t.Errorf("expected %v, got %v", csusrf.ErrBadToken, err)
		}
	}
}

func TestManagerVerifyTokenMismatch(t *testing.T) {
	if err := manager.VerifyToken(reversedTestTok); err != nil {
		if !errors.Is(err, csusrf.ErrTokenMismatch) {
			t.Errorf("expected %v, got %v", csusrf.ErrTokenMismatch, err)
		}
	}
}

func TestManagerMiddleware(t *testing.T) {
	cookie := csusrf.DefaultCookieOptions().Cookie()
	cookie.Value = testTok

	r := httptest.NewRequest("POST", "https://example.com", nil)
	r.Header.Set("Referer", "https://a.example.com")
	r.Header.Set("X-CSRF-TOKEN", testTok)
	r.AddCookie(cookie)

	w := httptest.NewRecorder()

	manager.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestManagerMiddlewareBadOrigin(t *testing.T) {
	manager := csusrf.NewManager(
		secretKey,
		csusrf.WithCookieOpts(csusrf.DefaultCookieOptions()),
	)

	r := httptest.NewRequest("POST", "https://example.com", nil)
	r.Header.Set("Referer", "")

	w := httptest.NewRecorder()

	manager.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestManagerMiddlewareUntrustedOrigin(t *testing.T) {
	manager := csusrf.NewManager(
		secretKey,
		csusrf.WithCookieOpts(csusrf.DefaultCookieOptions()),
	)

	r := httptest.NewRequest("POST", "https://example.com", nil)
	r.Header.Set("Referer", "https://a.example.com")

	w := httptest.NewRecorder()

	manager.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestManagerMiddlewareBadToken(t *testing.T) {
	cookie := csusrf.DefaultCookieOptions().Cookie()
	cookie.Value = "bad_token"

	r := httptest.NewRequest("POST", "https://example.com", nil)
	r.Header.Set("Referer", "https://a.example.com")
	r.Header.Set("X-CSRF-TOKEN", "bad_token")
	r.AddCookie(cookie)

	w := httptest.NewRecorder()

	manager.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestManagerMiddlewareTokenMismatch(t *testing.T) {
	cookie := csusrf.DefaultCookieOptions().Cookie()
	cookie.Value = testTok

	r := httptest.NewRequest("POST", "https://example.com", nil)
	r.Header.Set("Referer", "https://a.example.com")
	r.Header.Set("X-CSRF-TOKEN", reversedTestTok)
	r.AddCookie(cookie)

	w := httptest.NewRecorder()

	manager.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func BenchmarkManagerGenerateToken(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := manager.GenerateToken(testTok); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkManagerVerifyToken(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if err := manager.VerifyToken(testTok); err != nil {
			b.Error(err)
		}
	}
}
