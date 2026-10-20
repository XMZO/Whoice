package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/admin"
	"github.com/xmzo/whoice/services/lookup-api/internal/config"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

// Admin panel API: single-password login, signed session cookie, and settings
// that are read from and written back to whoice.toml.

const (
	adminCSRFHeader     = "X-Whoice-Admin"
	adminPasswordHeader = "X-Whoice-Admin-Password"
	maxAdminBodyBytes   = 1 << 20
)

// SetAdmin enables the admin panel API with the given credential manager.
func (s *Server) SetAdmin(manager *admin.Manager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.admin = manager
}

// SetConfigReloader lets settings saved from the panel take effect immediately
// instead of waiting for the file watcher.
func (s *Server) SetConfigReloader(reload func(time.Time) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reload = reload
}

func (s *Server) adminManager() *admin.Manager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.admin
}

func (s *Server) adminRoutes() {
	s.mux.HandleFunc("GET /api/admin/session", s.withAdminEndpoint(false, s.handleAdminSession))
	s.mux.HandleFunc("POST /api/admin/login", s.withAdminEndpoint(true, s.handleAdminLogin))
	s.mux.HandleFunc("POST /api/admin/logout", s.withAdminEndpoint(true, s.handleAdminLogout))
	s.mux.HandleFunc("POST /api/admin/password", s.withAdminGuard(endpointAdmin, s.handleAdminPassword))
	s.mux.HandleFunc("GET /api/admin/status", s.withAdminGuard(endpointAdminStatus, s.handleAdminStatus))
	s.mux.HandleFunc("GET /api/admin/config", s.withAdminGuard(endpointAdminConfig, s.handleAdminConfig))
	s.mux.HandleFunc("PATCH /api/admin/config", s.withAdminGuard(endpointAdminConfig, s.handleAdminConfigUpdate))
}

// withAdminEndpoint checks the endpoint switches, IP allowlist, and CSRF header,
// but not the session. It wraps login, logout, and session probing.
func (s *Server) withAdminEndpoint(mutating bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap := s.snapshot()
		if err := apiEndpointAllowed(endpointAdmin, r, snap); err != nil {
			writeAPIAccessError(w, err)
			return
		}
		if s.adminManager() == nil {
			writeAdminError(w, http.StatusServiceUnavailable, "admin_unavailable", "The admin panel is not enabled in this process.")
			return
		}
		if mutating && r.Header.Get(adminCSRFHeader) != "1" {
			writeAdminError(w, http.StatusForbidden, "csrf_required", "Missing "+adminCSRFHeader+" header.")
			return
		}
		next(w, r.WithContext(withSnapshot(r, snap)))
	}
}

// withAdminGuard additionally requires a valid admin session cookie, or the admin
// password in the X-Whoice-Admin-Password header for scripted access.
func (s *Server) withAdminGuard(endpoint apiEndpoint, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap := s.snapshot()
		if err := apiEndpointAllowed(endpoint, r, snap); err != nil {
			writeAPIAccessError(w, err)
			return
		}
		manager := s.adminManager()
		if manager == nil {
			writeAdminError(w, http.StatusServiceUnavailable, "admin_unavailable", "The admin panel is not enabled in this process.")
			return
		}
		if !s.adminAuthenticated(w, r, snap, manager) {
			return
		}
		if r.Method != http.MethodGet && r.Header.Get(adminPasswordHeader) == "" && r.Header.Get(adminCSRFHeader) != "1" {
			writeAdminError(w, http.StatusForbidden, "csrf_required", "Missing "+adminCSRFHeader+" header.")
			return
		}
		next(w, r.WithContext(withSnapshot(r, snap)))
	}
}

func (s *Server) adminAuthenticated(w http.ResponseWriter, r *http.Request, snap serverSnapshot, manager *admin.Manager) bool {
	now := time.Now()
	if cookie, err := r.Cookie(admin.SessionCookie); err == nil && manager.ValidSession(cookie.Value, now) {
		return true
	}
	if password := r.Header.Get(adminPasswordHeader); password != "" {
		client := clientIP(r, snap)
		if ok, wait := manager.Limiter().Allowed(client, now); !ok {
			writeRetryAfter(w, wait)
			return false
		}
		if manager.VerifyPassword(password) {
			manager.Limiter().Succeed(client)
			return true
		}
		manager.Limiter().Fail(client, now)
	}
	writeAdminError(w, http.StatusUnauthorized, "unauthorized", "Admin sign-in is required.")
	return false
}

func (s *Server) handleAdminSession(w http.ResponseWriter, r *http.Request) {
	manager := s.adminManager()
	authenticated := false
	if cookie, err := r.Cookie(admin.SessionCookie); err == nil {
		authenticated = manager.ValidSession(cookie.Value, time.Now())
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"authenticated":   authenticated,
		"passwordFromEnv": manager.PasswordFromEnv(),
	})
}

func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	manager := s.adminManager()
	snap := s.snapshotFromRequest(r)
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeAdminJSON(r, &body); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	now := time.Now()
	client := clientIP(r, snap)
	if ok, wait := manager.Limiter().Allowed(client, now); !ok {
		writeRetryAfter(w, wait)
		return
	}
	if !manager.VerifyPassword(body.Password) {
		manager.Limiter().Fail(client, now)
		writeAdminError(w, http.StatusUnauthorized, "invalid_password", "The password is incorrect.")
		return
	}
	manager.Limiter().Succeed(client)
	token, expires := manager.IssueSession(now)
	setAdminCookie(w, r, token, expires)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "authenticated": true, "expiresAt": expires.Format(time.RFC3339)})
}

func (s *Server) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	setAdminCookie(w, r, "", time.Unix(0, 0))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "authenticated": false})
}

func (s *Server) handleAdminPassword(w http.ResponseWriter, r *http.Request) {
	manager := s.adminManager()
	var body struct {
		Current string `json:"current"`
		Next    string `json:"next"`
	}
	if err := decodeAdminJSON(r, &body); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := manager.ChangePassword(body.Current, body.Next); err != nil {
		switch {
		case errors.Is(err, admin.ErrWrongPassword):
			writeAdminError(w, http.StatusUnauthorized, "invalid_password", err.Error())
		case errors.Is(err, admin.ErrWeakPassword):
			writeAdminError(w, http.StatusBadRequest, "weak_password", err.Error())
		case errors.Is(err, admin.ErrPasswordFromEnv):
			writeAdminError(w, http.StatusConflict, "password_from_env", err.Error())
		default:
			writeAdminError(w, http.StatusInternalServerError, "password_write_failed", err.Error())
		}
		return
	}
	// The secret rotated, so issue a fresh session for the caller.
	token, expires := manager.IssueSession(time.Now())
	setAdminCookie(w, r, token, expires)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	snap := s.snapshotFromRequest(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"version":      Version,
		"capabilities": snap.cfg.Capabilities(),
		"plugins":      snap.plugins,
		"config":       snap.config,
		"stats":        s.stats.Snapshot(),
	})
}

func (s *Server) handleAdminConfig(w http.ResponseWriter, r *http.Request) {
	snap := s.snapshotFromRequest(r)
	payload, err := adminSettingsPayload(snap)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "config_unreadable", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleAdminConfigUpdate(w http.ResponseWriter, r *http.Request) {
	snap := s.snapshotFromRequest(r)
	path := strings.TrimSpace(snap.cfg.ConfigPath)
	if path == "" {
		writeAdminError(w, http.StatusConflict, "config_path_missing", "No config file is active, so settings cannot be saved.")
		return
	}
	var body struct {
		Settings config.FileConfig `json:"settings"`
	}
	if err := decodeAdminJSON(r, &body); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	patch := body.Settings
	touched := settingsPaths(patch)
	if len(touched) == 0 {
		writeAdminError(w, http.StatusBadRequest, "empty_patch", "No settings were provided.")
		return
	}
	if blocked := startupOnly(touched); len(blocked) > 0 {
		writeAdminError(w, http.StatusBadRequest, "startup_only", "These settings can only be changed in the file before startup: "+strings.Join(blocked, ", "))
		return
	}
	locked := config.EnvLockedFields()
	var lockedTouched []string
	for _, field := range touched {
		if env, ok := locked[field]; ok {
			lockedTouched = append(lockedTouched, field+" ("+env+")")
		}
	}
	if len(lockedTouched) > 0 {
		writeAdminError(w, http.StatusConflict, "env_locked", "These settings are set by environment variables: "+strings.Join(lockedTouched, ", "))
		return
	}

	base, err := config.LoadFileOnly(path)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "config_unreadable", err.Error())
		return
	}
	if err := patch.Apply(&base); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid_config", err.Error())
		return
	}
	effective := config.WithEnv(base)
	effective.ConfigPath = path
	if err := effective.Validate(); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid_config", err.Error())
		return
	}
	if _, err := buildRuntime(effective, snap.service, snap.plugins, true); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid_config", err.Error())
		return
	}
	if reason := adminLockout(effective, r, snap); reason != "" {
		writeAdminError(w, http.StatusBadRequest, "admin_lockout", reason)
		return
	}
	if err := config.WriteFile(path, base); err != nil {
		writeAdminError(w, http.StatusInternalServerError, "config_write_failed", err.Error())
		return
	}

	s.mu.RLock()
	reload := s.reload
	s.mu.RUnlock()
	if reload != nil {
		if err := reload(time.Now().UTC()); err != nil {
			s.RecordConfigReloadError(path, time.Now().UTC(), err)
			writeAdminError(w, http.StatusInternalServerError, "reload_failed", "Settings were saved but could not be applied: "+err.Error())
			return
		}
	}
	payload, err := adminSettingsPayload(s.snapshot())
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "config_unreadable", err.Error())
		return
	}
	payload["saved"] = touched
	writeJSON(w, http.StatusOK, payload)
}

func adminSettingsPayload(snap serverSnapshot) (map[string]any, error) {
	path := strings.TrimSpace(snap.cfg.ConfigPath)
	fileCfg := snap.cfg
	if path != "" {
		loaded, err := config.LoadFileOnly(path)
		if err != nil {
			return nil, err
		}
		fileCfg = loaded
	}
	locked := config.EnvLockedFields()
	if locked == nil {
		locked = map[string]string{}
	}
	return map[string]any{
		"ok":        true,
		"config":    snap.config,
		"editor":    configEditorStatus(path),
		"settings":  config.SettingsView(fileCfg),
		"secrets":   config.SecretsOf(fileCfg),
		"envLocked": locked,
	}, nil
}

func configEditorStatus(path string) model.ConfigEditorStatus {
	status := model.ConfigEditorStatus{
		Status:              "enabled",
		Path:                path,
		Format:              "toml",
		Writable:            path != "" && dirWritable(filepath.Dir(path)),
		SourceReadable:      false,
		Surfaces:            []string{"settings"},
		SupportedOperations: []string{"read-settings", "update-settings", "change-password"},
	}
	if path == "" {
		status.Status = "disabled"
		status.Reason = "No config file path is active."
	} else if !status.Writable {
		status.Reason = "The config directory is not writable by the API process."
	}
	return status
}

func dirWritable(dir string) bool {
	file, err := os.CreateTemp(dir, ".whoice-write-check-*")
	if err != nil {
		return false
	}
	name := file.Name()
	file.Close()
	os.Remove(name)
	return true
}

// settingsPaths flattens a partial settings object into dotted paths such as "ai.model".
func settingsPaths(patch config.FileConfig) []string {
	raw, err := json.Marshal(patch)
	if err != nil {
		return nil
	}
	var tree map[string]any
	if err := json.Unmarshal(raw, &tree); err != nil {
		return nil
	}
	var out []string
	var walk func(prefix string, node map[string]any)
	walk = func(prefix string, node map[string]any) {
		for key, value := range node {
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			// Sections and api.endpoints are objects; every other value is a leaf setting.
			if child, ok := value.(map[string]any); ok && (prefix == "" || key == "endpoints") {
				walk(path, child)
				continue
			}
			out = append(out, path)
		}
	}
	walk("", tree)
	sort.Strings(out)
	return out
}

func startupOnly(paths []string) []string {
	var out []string
	for _, path := range paths {
		if path == "server.addr" || path == "server.data_dir" {
			out = append(out, path)
		}
	}
	return out
}

// adminLockout rejects settings that would cut off the panel for the current client.
func adminLockout(cfg config.Config, r *http.Request, snap serverSnapshot) string {
	if !cfg.APIEnabled || !cfg.APIAdminEnabled || !cfg.APIAdminConfigEnabled {
		return "Disabling the API, admin, or admin_config endpoints from the panel would lock the panel out. Edit whoice.toml directly instead."
	}
	next := snap
	next.cfg = cfg
	if !clientIPAllowed(r, next) {
		return "The new API IP allowlist does not include your current address (" + clientIP(r, next) + ")."
	}
	return ""
}

func decodeAdminJSON(r *http.Request, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxAdminBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

func setAdminCookie(w http.ResponseWriter, r *http.Request, value string, expires time.Time) {
	cookie := &http.Cookie{
		Name:     admin.SessionCookie,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   requestIsHTTPS(r),
	}
	if value == "" {
		cookie.MaxAge = -1
	}
	http.SetCookie(w, cookie)
}

func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	proto, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Proto"), ",")
	return strings.EqualFold(strings.TrimSpace(proto), "https")
}

func writeRetryAfter(w http.ResponseWriter, wait time.Duration) {
	seconds := int(wait.Seconds()) + 1
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	writeAdminError(w, http.StatusTooManyRequests, "too_many_attempts", fmt.Sprintf("Too many failed sign-in attempts. Try again in %d seconds.", seconds))
}

func writeAdminError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, model.APIResponse{OK: false, Error: &model.APIError{Code: code, Message: message}})
}

func withSnapshot(r *http.Request, snap serverSnapshot) context.Context {
	return context.WithValue(r.Context(), snapshotContextKey{}, snap)
}
