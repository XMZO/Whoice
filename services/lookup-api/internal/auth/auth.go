package auth

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
)

var ErrUnauthorized = errors.New("unauthorized")

type Authenticator interface {
	Authenticate(r *http.Request) error
}

type StaticAuthenticator struct {
	mode     string
	password string
	tokens   []string
}

func NewStatic(mode, password string, tokens []string) StaticAuthenticator {
	return StaticAuthenticator{
		mode:     strings.ToLower(strings.TrimSpace(mode)),
		password: password,
		tokens:   compact(tokens),
	}
}

func (a StaticAuthenticator) Authenticate(r *http.Request) error {
	switch a.mode {
	case "", "none":
		return nil
	case "password":
		if a.password == "" {
			return ErrUnauthorized
		}
		candidates := []string{
			r.Header.Get("X-Whoice-Password"),
			bearerToken(r.Header.Get("Authorization")),
		}
		if cookie, err := r.Cookie("whoice_password"); err == nil {
			candidates = append(candidates, cookie.Value)
		}
		for _, candidate := range candidates {
			if constantEqual(candidate, a.password) {
				return nil
			}
		}
		return ErrUnauthorized
	case "token", "bearer":
		if len(a.tokens) == 0 {
			return ErrUnauthorized
		}
		candidates := []string{
			bearerToken(r.Header.Get("Authorization")),
			r.Header.Get("X-API-Key"),
			r.URL.Query().Get("token"),
		}
		for _, candidate := range candidates {
			for _, token := range a.tokens {
				if constantEqual(candidate, token) {
					return nil
				}
			}
		}
		return ErrUnauthorized
	default:
		return ErrUnauthorized
	}
}

func bearerToken(header string) string {
	fields := strings.Fields(header)
	if len(fields) == 2 && strings.EqualFold(fields[0], "Bearer") {
		return fields[1]
	}
	return ""
}

func constantEqual(left, right string) bool {
	if left == "" || right == "" || len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func compact(values []string) []string {
	var result []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}
