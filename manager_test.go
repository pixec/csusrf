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
	testTok         = "1fa7f61b72e5d22ee9e78eb87d343b04fe34c1ec72ca6538a5968ff4a9559c89:520f2f1e2785d05108b35434cf5db674f043974d701aa54c4709ed6c462829ca"
	reversedTestTok = "520f2f1e2785d05108b35434cf5db674f043974d701aa54c4709ed6c462829ca:1fa7f61b72e5d22ee9e78eb87d343b04fe34c1ec72ca6538a5968ff4a9559c89"
	manager         = csusrf.NewManager(
		secretKey,
		[]string{"a.example.com"},
		csusrf.DefaultCookieOptions(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "", http.StatusForbidden)
		}),
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
	if _, err := manager.GenerateToken(); err != nil {
		t.Error(err)
	}
}

func TestManagerVerifyToken(t *testing.T) {
	tok, err := manager.GenerateToken()
	if err != nil {
		t.Error(err)
	}

	if err := manager.VerifyToken(tok); err != nil {
		t.Error(err)
	}
}

func TestManagerVerifyTokenBadToken(t *testing.T) {
	if err := manager.VerifyToken("1"); err != nil {
		if !errors.Is(err, csusrf.ErrBadToken) {
			t.Errorf("expected %v, got %v", csusrf.ErrBadToken, err)
		}
	}

	if err := manager.VerifyToken("1:1"); err != nil {
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
		nil,
		csusrf.DefaultCookieOptions(),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "", http.StatusForbidden)
		}),
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
		nil,
		csusrf.DefaultCookieOptions(),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "", http.StatusForbidden)
		}),
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
