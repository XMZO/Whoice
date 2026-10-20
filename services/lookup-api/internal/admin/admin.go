// Package admin holds the single-password credential for the Web admin panel and
// issues signed session cookies. The credential lives in <data_dir>/admin.json,
// separate from whoice.toml, so rewriting the config never touches it.
package admin

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	PasswordEnv       = "WHOICE_ADMIN_PASSWORD"
	SessionCookie     = "whoice_admin"
	SessionTTL        = 7 * 24 * time.Hour
	MinPasswordLength = 8
	hashIterations    = 210_000
	fileName          = "admin.json"
)

var (
	ErrWrongPassword   = errors.New("current password is incorrect")
	ErrPasswordFromEnv = errors.New("the admin password is set by " + PasswordEnv + " and cannot be changed here")
	ErrWeakPassword    = fmt.Errorf("the new password must be at least %d characters", MinPasswordLength)
)

type stored struct {
	PasswordHash  string `json:"password_hash,omitempty"`
	SessionSecret string `json:"session_secret"`
	UpdatedAt     string `json:"updated_at"`
}

type Manager struct {
	mu          sync.RWMutex
	path        string
	envPassword string
	hash        string
	secret      []byte
	modTime     time.Time
	limiter     *Limiter
}

// Open loads or creates the credential file. When no password exists yet and none is
// supplied through the environment, it generates one and returns it so the caller can
// log it once.
func Open(dataDir string) (*Manager, string, error) {
	m := &Manager{
		path:        filepath.Join(dataDir, fileName),
		envPassword: os.Getenv(PasswordEnv),
		limiter:     NewLimiter(),
	}
	state, err := m.read()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}
	generated := ""
	dirty := errors.Is(err, os.ErrNotExist)
	if state.SessionSecret == "" {
		state.SessionSecret = randomToken(32)
		dirty = true
	}
	if state.PasswordHash == "" && m.envPassword == "" {
		generated = RandomPassword()
		state.PasswordHash = hashPassword(generated)
		dirty = true
	}
	if dirty {
		if err := m.write(state); err != nil {
			return nil, "", err
		}
	}
	m.apply(state)
	m.markLoaded()
	return m, generated, nil
}

// ResetPassword replaces the stored password with a new random one and signs out every session.
func ResetPassword(dataDir string) (string, error) {
	m := &Manager{path: filepath.Join(dataDir, fileName)}
	state, err := m.read()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	password := RandomPassword()
	state.PasswordHash = hashPassword(password)
	state.SessionSecret = randomToken(32)
	if err := m.write(state); err != nil {
		return "", err
	}
	matchOwner(m.path, filepath.Dir(m.path))
	return password, nil
}

func (m *Manager) PasswordFromEnv() bool {
	return m.envPassword != ""
}

func (m *Manager) Limiter() *Limiter {
	return m.limiter
}

func (m *Manager) VerifyPassword(password string) bool {
	if password == "" {
		return false
	}
	if m.envPassword != "" {
		return subtle.ConstantTimeCompare([]byte(password), []byte(m.envPassword)) == 1
	}
	m.refresh()
	m.mu.RLock()
	hash := m.hash
	m.mu.RUnlock()
	return verifyHash(hash, password)
}

// ChangePassword stores a new password and rotates the session secret, signing out other sessions.
func (m *Manager) ChangePassword(current, next string) error {
	if m.envPassword != "" {
		return ErrPasswordFromEnv
	}
	if !m.VerifyPassword(current) {
		return ErrWrongPassword
	}
	if len([]rune(next)) < MinPasswordLength {
		return ErrWeakPassword
	}
	state := stored{PasswordHash: hashPassword(next), SessionSecret: randomToken(32)}
	if err := m.write(state); err != nil {
		return err
	}
	m.apply(state)
	m.markLoaded()
	return nil
}

// IssueSession returns a signed token: base64(expiry|nonce).base64(hmac).
func (m *Manager) IssueSession(now time.Time) (string, time.Time) {
	expires := now.Add(SessionTTL).UTC()
	payload := make([]byte, 24)
	binary.BigEndian.PutUint64(payload[:8], uint64(expires.Unix()))
	if _, err := rand.Read(payload[8:]); err != nil {
		panic(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	return encoded + "." + m.sign(encoded), expires
}

func (m *Manager) ValidSession(token string, now time.Time) bool {
	m.refresh()
	encoded, signature, ok := strings.Cut(token, ".")
	if !ok || encoded == "" || signature == "" {
		return false
	}
	if !hmac.Equal([]byte(signature), []byte(m.sign(encoded))) {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(payload) != 24 {
		return false
	}
	expires := time.Unix(int64(binary.BigEndian.Uint64(payload[:8])), 0)
	return now.Before(expires)
}

func (m *Manager) sign(value string) string {
	m.mu.RLock()
	secret := m.secret
	m.mu.RUnlock()
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// refresh reloads the credential file when another process (the reset command) changed it.
func (m *Manager) refresh() {
	info, err := os.Stat(m.path)
	if err != nil {
		return
	}
	m.mu.RLock()
	unchanged := info.ModTime().Equal(m.modTime)
	m.mu.RUnlock()
	if unchanged {
		return
	}
	if state, err := m.read(); err == nil && state.SessionSecret != "" {
		m.apply(state)
		m.mu.Lock()
		m.modTime = info.ModTime()
		m.mu.Unlock()
	}
}

func (m *Manager) markLoaded() {
	if info, err := os.Stat(m.path); err == nil {
		m.mu.Lock()
		m.modTime = info.ModTime()
		m.mu.Unlock()
	}
}

func (m *Manager) apply(state stored) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hash = state.PasswordHash
	m.secret = []byte(state.SessionSecret)
}

func (m *Manager) read() (stored, error) {
	var state stored
	body, err := os.ReadFile(m.path)
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(body, &state); err != nil {
		return state, fmt.Errorf("parse %s: %w", m.path, err)
	}
	return state, nil
}

func (m *Manager) write(state stored) error {
	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0o755); err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, append(body, '\n'), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", m.path, err)
	}
	if err := os.Rename(tmp, m.path); err != nil {
		return fmt.Errorf("replace %s: %w", m.path, err)
	}
	return nil
}

func hashPassword(password string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, hashIterations, 32)
	if err != nil {
		panic(err)
	}
	return "pbkdf2-sha256$" + strconv.Itoa(hashIterations) + "$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key)
}

func verifyHash(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 1 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iterations, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

const passwordAlphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// RandomPassword returns an 18-character password without look-alike characters.
func RandomPassword() string {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	for i, b := range buf {
		buf[i] = passwordAlphabet[int(b)%len(passwordAlphabet)]
	}
	return string(buf)
}

func randomToken(size int) string {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}
