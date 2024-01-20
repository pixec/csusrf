package csusrf_test

import (
	"errors"
	"testing"

	"github.com/pixec/csusrf"
)

var secretKey = []byte("Sneaky crewmates play, Amogus impostors sway, Betrayal in space's bay.")

func TestManagerGenerateToken(t *testing.T) {
	m := csusrf.NewManager(secretKey, nil, csusrf.DefaultCookieOptions())
	if _, err := m.GenerateToken("Crewmate"); err != nil {
		t.Error(err)
	}
}

func TestManagerVerifyToken(t *testing.T) {
	m := csusrf.NewManager(secretKey, nil, csusrf.DefaultCookieOptions())

	tok, err := m.GenerateToken("Crewmate")
	if err != nil {
		t.Error(err)
	}

	if err := m.VerifyToken(tok); err != nil {
		t.Error(err)
	}
}

func TestManagerVerifyTokenInvalid(t *testing.T) {
	m := csusrf.NewManager(secretKey, nil, csusrf.DefaultCookieOptions())

	if err := m.VerifyToken("Impostor"); err != nil {
		if !errors.Is(err, csusrf.ErrInvalidToken) {
			t.Errorf("expected %v, got %v", csusrf.ErrInvalidToken, err)
		}
	}
}
