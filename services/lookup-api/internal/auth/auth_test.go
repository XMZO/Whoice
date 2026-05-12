package auth

import (
	"net/http"
	"testing"
)

func TestPasswordAuth(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/api/lookup", nil)
	req.Header.Set("X-Whoice-Password", "secret")
	if err := NewStatic("password", "secret", nil).Authenticate(req); err != nil {
		t.Fatal(err)
	}
}

func TestTokenAuth(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/api/lookup", nil)
	req.Header.Set("Authorization", "Bearer abc")
	if err := NewStatic("token", "", []string{"abc"}).Authenticate(req); err != nil {
		t.Fatal(err)
	}
}

func TestAuthRejectsUnknownMode(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/api/lookup", nil)
	if err := NewStatic("mystery", "", nil).Authenticate(req); err == nil {
		t.Fatal("expected unknown auth mode to reject")
	}
}
