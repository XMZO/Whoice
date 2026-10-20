package admin

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenGeneratesPasswordOnce(t *testing.T) {
	dir := t.TempDir()
	m, generated, err := Open(dir)
	if err != nil || generated == "" {
		t.Fatalf("expected a generated password, got %q %v", generated, err)
	}
	if !m.VerifyPassword(generated) || m.VerifyPassword(generated+"x") {
		t.Fatal("generated password does not verify correctly")
	}
	info, err := os.Stat(filepath.Join(dir, fileName))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("credential file missing or too permissive: %v %v", info, err)
	}
	again, second, err := Open(dir)
	if err != nil || second != "" || !again.VerifyPassword(generated) {
		t.Fatalf("reopening should keep the password: %q %v", second, err)
	}
}

func TestChangePasswordRotatesSessions(t *testing.T) {
	m, generated, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	token, _ := m.IssueSession(now)
	if !m.ValidSession(token, now) {
		t.Fatal("fresh session should be valid")
	}
	if err := m.ChangePassword("wrong", "new-password"); err != ErrWrongPassword {
		t.Fatalf("expected ErrWrongPassword, got %v", err)
	}
	if err := m.ChangePassword(generated, "short"); err != ErrWeakPassword {
		t.Fatalf("expected ErrWeakPassword, got %v", err)
	}
	if err := m.ChangePassword(generated, "new-password"); err != nil {
		t.Fatal(err)
	}
	if m.ValidSession(token, now) {
		t.Fatal("changing the password should invalidate existing sessions")
	}
	if !m.VerifyPassword("new-password") || m.VerifyPassword(generated) {
		t.Fatal("password change did not take effect")
	}
}

func TestSessionExpiryAndTampering(t *testing.T) {
	m, _, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	token, _ := m.IssueSession(now)
	if m.ValidSession(token, now.Add(SessionTTL+time.Second)) {
		t.Fatal("expired session accepted")
	}
	if m.ValidSession(token+"x", now) || m.ValidSession("", now) || m.ValidSession("a.b", now) {
		t.Fatal("tampered session accepted")
	}
}

func TestEnvPasswordTakesPriority(t *testing.T) {
	t.Setenv(PasswordEnv, "from-environment")
	m, generated, err := Open(t.TempDir())
	if err != nil || generated != "" {
		t.Fatalf("no password should be generated when the env var is set: %q %v", generated, err)
	}
	if !m.PasswordFromEnv() || !m.VerifyPassword("from-environment") {
		t.Fatal("env password not used")
	}
	if err := m.ChangePassword("from-environment", "something-else"); err != ErrPasswordFromEnv {
		t.Fatalf("expected ErrPasswordFromEnv, got %v", err)
	}
}

func TestResetPassword(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := Open(dir); err != nil {
		t.Fatal(err)
	}
	password, err := ResetPassword(dir)
	if err != nil {
		t.Fatal(err)
	}
	m, generated, err := Open(dir)
	if err != nil || generated != "" || !m.VerifyPassword(password) {
		t.Fatalf("reset password not usable: %q %v", generated, err)
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter()
	now := time.Now()
	for i := 0; i < maxFailuresPerClient; i++ {
		if ok, _ := l.Allowed("a", now); !ok {
			t.Fatalf("attempt %d should be allowed", i)
		}
		l.Fail("a", now)
	}
	if ok, wait := l.Allowed("a", now); ok || wait <= 0 {
		t.Fatal("client should be locked out")
	}
	if ok, _ := l.Allowed("b", now); !ok {
		t.Fatal("other clients must not be affected")
	}
	if ok, _ := l.Allowed("a", now.Add(failureWindow)); !ok {
		t.Fatal("lockout should expire")
	}
}

func TestRunningManagerSeesExternalReset(t *testing.T) {
	dir := t.TempDir()
	m, generated, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := m.IssueSession(time.Now())
	time.Sleep(10 * time.Millisecond)
	password, err := ResetPassword(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m.VerifyPassword(generated) || !m.VerifyPassword(password) {
		t.Fatal("running manager did not pick up the reset password")
	}
	if m.ValidSession(token, time.Now()) {
		t.Fatal("reset should sign out existing sessions")
	}
}
