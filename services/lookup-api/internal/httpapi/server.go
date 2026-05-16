package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/auth"
	"github.com/xmzo/whoice/services/lookup-api/internal/config"
	"github.com/xmzo/whoice/services/lookup-api/internal/icp"
	"github.com/xmzo/whoice/services/lookup-api/internal/lookup"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
	"github.com/xmzo/whoice/services/lookup-api/internal/normalize"
	"github.com/xmzo/whoice/services/lookup-api/internal/observability"
	"github.com/xmzo/whoice/services/lookup-api/internal/ratelimit"
	"github.com/xmzo/whoice/services/lookup-api/internal/security"
)

const Version = "v0.02beta"
const maxAIRequestBytes = 8 << 20

type apiEndpoint string

const (
	endpointHealth       apiEndpoint = "health"
	endpointVersion      apiEndpoint = "version"
	endpointCapabilities apiEndpoint = "capabilities"
	endpointMetrics      apiEndpoint = "metrics"
	endpointLookup       apiEndpoint = "lookup"
	endpointLookupAI     apiEndpoint = "lookup_ai"
	endpointLookupEnrich apiEndpoint = "lookup_enrich"
	endpointICP          apiEndpoint = "icp"
	endpointAdminStatus  apiEndpoint = "admin_status"
	endpointAdminConfig  apiEndpoint = "admin_config"
)

type Server struct {
	mu       sync.RWMutex
	cfg      config.Config
	service  *lookup.Service
	icp      *icp.Client
	plugins  []model.PluginInfo
	policy   security.ServerPolicy
	auth     auth.Authenticator
	limiter  *ratelimit.Limiter
	stats    *observability.Stats
	reporter observability.Reporter
	mux      *http.ServeMux
	config   model.ConfigStatus
}

func New(cfg config.Config, service *lookup.Service, plugins []model.PluginInfo, stats *observability.Stats) *Server {
	server, err := newServer(cfg, service, plugins, stats, false)
	if err == nil {
		return server
	}
	log.Printf("runtime config warning: %v", err)
	server, _ = newServer(config.Default(), service, plugins, stats, false)
	return server
}

func NewStrict(cfg config.Config, service *lookup.Service, plugins []model.PluginInfo, stats *observability.Stats) (*Server, error) {
	return newServer(cfg, service, plugins, stats, true)
}

func newServer(cfg config.Config, service *lookup.Service, plugins []model.PluginInfo, stats *observability.Stats, strict bool) (*Server, error) {
	runtime, err := buildRuntime(cfg, service, plugins, strict)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	s := &Server{
		cfg:      runtime.cfg,
		service:  runtime.service,
		icp:      runtime.icp,
		plugins:  runtime.plugins,
		policy:   runtime.policy,
		auth:     runtime.auth,
		limiter:  runtime.limiter,
		reporter: runtime.reporter,
		stats:    stats,
		mux:      http.NewServeMux(),
		config:   okConfigStatus(runtime.cfg, now),
	}
	s.routes()
	return s, nil
}

type runtimeState struct {
	cfg      config.Config
	service  *lookup.Service
	icp      *icp.Client
	plugins  []model.PluginInfo
	policy   security.ServerPolicy
	auth     auth.Authenticator
	limiter  *ratelimit.Limiter
	reporter observability.Reporter
}

type serverSnapshot struct {
	cfg      config.Config
	service  *lookup.Service
	icp      *icp.Client
	plugins  []model.PluginInfo
	policy   security.ServerPolicy
	auth     auth.Authenticator
	limiter  *ratelimit.Limiter
	reporter observability.Reporter
	config   model.ConfigStatus
}

type snapshotContextKey struct{}

func buildRuntime(cfg config.Config, service *lookup.Service, plugins []model.PluginInfo, strict bool) (runtimeState, error) {
	if strict {
		if err := cfg.Validate(); err != nil {
			return runtimeState{}, err
		}
	}
	limiter, err := ratelimit.New(cfg.RateLimitEnabled, cfg.RateLimitAnon)
	if err != nil {
		if strict {
			return runtimeState{}, fmt.Errorf("invalid rate_limit.anon: %w", err)
		}
		limiter, _ = ratelimit.New(cfg.RateLimitEnabled, "60/min")
	}
	reporter, err := observability.NewReporter(cfg.Reporter, cfg.ReporterWebhookURL, cfg.ReporterTimeout)
	if err != nil {
		if strict {
			return runtimeState{}, fmt.Errorf("invalid observability reporter config: %w", err)
		}
		log.Printf("observability reporter disabled: %v", err)
	}
	return runtimeState{
		cfg:      cfg,
		service:  service,
		icp:      icp.NewClient(cfg),
		plugins:  append([]model.PluginInfo(nil), plugins...),
		policy:   security.NewServerPolicy(cfg.AllowPrivateServers),
		auth:     auth.NewStatic(cfg.AuthMode, cfg.SitePassword, cfg.APITokens),
		limiter:  &limiter,
		reporter: reporter,
	}, nil
}

func (s *Server) ApplyRuntime(cfg config.Config, service *lookup.Service, plugins []model.PluginInfo, loadedAt time.Time) error {
	runtime, err := buildRuntime(cfg, service, plugins, true)
	if err != nil {
		return err
	}
	if loadedAt.IsZero() {
		loadedAt = time.Now().UTC()
	}
	s.mu.Lock()
	previousService := s.service
	defer s.mu.Unlock()
	s.cfg = runtime.cfg
	s.service = runtime.service
	s.icp = runtime.icp
	s.plugins = runtime.plugins
	s.policy = runtime.policy
	s.auth = runtime.auth
	s.limiter = runtime.limiter
	s.reporter = runtime.reporter
	s.config = okConfigStatus(runtime.cfg, loadedAt.UTC())
	runtime.service.StartBackground(context.Background())
	if previousService != nil && previousService != runtime.service {
		previousService.StopBackground()
	}
	return nil
}

func (s *Server) RecordConfigReloadError(path string, attemptedAt time.Time, err error) {
	if attemptedAt.IsZero() {
		attemptedAt = time.Now().UTC()
	}
	message := ""
	if err != nil {
		message = err.Error()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	status := s.config
	if status.Path == "" {
		status.Path = path
	}
	status.Status = "error"
	status.LastCheckedAt = attemptedAt.UTC().Format(time.RFC3339)
	status.LastAttemptAt = attemptedAt.UTC().Format(time.RFC3339)
	status.LastErrorAt = attemptedAt.UTC().Format(time.RFC3339)
	status.LastError = message
	status.RolledBack = true
	status.UsingLoadedAt = status.LoadedAt
	s.config = status
}

func (s *Server) ConfigStatus() model.ConfigStatus {
	return s.snapshot().config
}

func (s *Server) snapshot() serverSnapshot {
	if s == nil {
		return serverSnapshot{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return serverSnapshot{
		cfg:      s.cfg,
		service:  s.service,
		icp:      s.icp,
		plugins:  append([]model.PluginInfo(nil), s.plugins...),
		policy:   s.policy,
		auth:     s.auth,
		limiter:  s.limiter,
		reporter: s.reporter,
		config:   s.config,
	}
}

func (s *Server) snapshotFromRequest(r *http.Request) serverSnapshot {
	if r != nil {
		if snap, ok := r.Context().Value(snapshotContextKey{}).(serverSnapshot); ok {
			return snap
		}
	}
	return s.snapshot()
}

func okConfigStatus(cfg config.Config, loadedAt time.Time) model.ConfigStatus {
	if loadedAt.IsZero() {
		loadedAt = time.Now().UTC()
	}
	text := loadedAt.UTC().Format(time.RFC3339)
	return model.ConfigStatus{
		Status:        "ok",
		Path:          cfg.ConfigPath,
		LoadedAt:      text,
		LastCheckedAt: text,
		LastAttemptAt: text,
	}
}

func configStatusPtr(status model.ConfigStatus) *model.ConfigStatus {
	if status.Status != "error" {
		return nil
	}
	copy := status
	return &copy
}

func configReloadWarning(status model.ConfigStatus) string {
	if status.Status != "error" || status.LastError == "" {
		return ""
	}
	loadedAt := firstNonEmpty(status.UsingLoadedAt, status.LoadedAt, "the previous valid runtime")
	return fmt.Sprintf("Configuration reload failed at %s; using the last valid config loaded at %s: %s", firstNonEmpty(status.LastErrorAt, status.LastAttemptAt, "unknown time"), loadedAt, status.LastError)
}

func (s *Server) Handler() http.Handler {
	return s.withLogging(s.withCORS(s.mux))
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/health", s.withAPIGuard(endpointHealth, s.handleHealth))
	s.mux.HandleFunc("GET /api/version", s.withAPIGuard(endpointVersion, s.handleVersion))
	s.mux.HandleFunc("GET /api/capabilities", s.withAPIGuard(endpointCapabilities, s.handleCapabilities))
	s.mux.HandleFunc("GET /api/metrics", s.withAPIGuard(endpointMetrics, s.handleMetrics))
	s.mux.HandleFunc("GET /api/lookup", s.withLookupGuards(endpointLookup, s.handleLookup))
	s.mux.HandleFunc("POST /api/lookup/ai", s.withLookupGuards(endpointLookupAI, s.handleLookupAI))
	s.mux.HandleFunc("POST /api/lookup/enrich", s.withLookupGuards(endpointLookupEnrich, s.handleLookupEnrich))
	s.mux.HandleFunc("GET /api/icp", s.withLookupGuards(endpointICP, s.handleICP))
	s.mux.HandleFunc("GET /api/admin/status", s.withAdminGuard(endpointAdminStatus, s.handleAdminStatus))
	s.mux.HandleFunc("GET /api/admin/config", s.withAdminGuard(endpointAdminConfig, s.handleAdminConfig))
	s.mux.HandleFunc("PATCH /api/admin/config", s.withAdminGuard(endpointAdminConfig, s.handleAdminConfigUpdate))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	snap := s.snapshotFromRequest(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"version": Version,
		"time":    time.Now().UTC().Format(time.RFC3339),
		"config":  snap.config,
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	snap := s.snapshotFromRequest(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"version": Version,
		"data": map[string]string{
			"schema": "0.1",
		},
		"capabilities": snap.cfg.Capabilities(),
		"plugins":      snap.plugins,
		"config":       snap.config,
	})
}

func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	snap := s.snapshotFromRequest(r)
	capabilities := snap.cfg.Capabilities()
	writeJSON(w, http.StatusOK, model.APIResponse{
		OK:           true,
		Capabilities: &capabilities,
		Config:       &snap.config,
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	snap := s.snapshotFromRequest(r)
	if !snap.cfg.MetricsEnabled {
		writeJSON(w, http.StatusNotFound, model.APIResponse{
			OK: false,
			Error: &model.APIError{
				Code:    "metrics_disabled",
				Message: "Metrics endpoint is disabled.",
			},
			Config: configStatusPtr(snap.config),
		})
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if s.stats == nil {
		_, _ = w.Write([]byte(""))
		return
	}
	_, _ = w.Write([]byte(s.stats.Prometheus()))
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
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"config": snap.config,
		"editor": configEditorStatus(snap),
	})
}

func (s *Server) handleAdminConfigUpdate(w http.ResponseWriter, r *http.Request) {
	snap := s.snapshotFromRequest(r)
	// Intentionally reserved, not implemented yet. Future Web config editing
	// should plug in here after adding a dedicated admin permission model,
	// CSRF protection for browser sessions, source validation/diff preview,
	// backup + atomic write, and reuse of the hot-reload validator before
	// syncing changes back to snap.cfg.ConfigPath.
	writeJSON(w, http.StatusNotImplemented, model.APIResponse{
		OK: false,
		Error: &model.APIError{
			Code:    "config_editor_reserved",
			Message: "Config editing is reserved for a future Web admin UI and is not enabled in this build.",
		},
		Config: configStatusPtr(snap.config),
	})
}

func configEditorStatus(snap serverSnapshot) model.ConfigEditorStatus {
	path := strings.TrimSpace(snap.cfg.ConfigPath)
	status := model.ConfigEditorStatus{
		Status:              "reserved",
		Path:                path,
		Format:              "toml-or-base64-toml",
		Writable:            false,
		SourceReadable:      false,
		Surfaces:            []string{"restricted-controls", "source-file"},
		SupportedOperations: []string{"inspect-capabilities"},
		Reason:              "Reserved for a future Web admin UI. The API does not read or write the config source through HTTP yet.",
	}
	if path == "" {
		status.Reason = "No config file path is active, so Web config editing cannot be enabled."
	}
	return status
}

func (s *Server) handleLookup(w http.ResponseWriter, r *http.Request) {
	snap := s.snapshotFromRequest(r)
	traceID := requestTraceID(r)
	w.Header().Set("X-Trace-ID", traceID)
	query := normalize.CleanUserInput(firstNonEmpty(r.URL.Query().Get("query"), r.URL.Query().Get("q")))
	if query == "" {
		if s.stats != nil {
			s.stats.RecordLookup(false, 0)
		}
		s.reportLookup(observability.LookupEvent{
			TraceID:   traceID,
			OK:        false,
			ErrorCode: "query_required",
			Error:     "Query is required.",
		})
		writeJSON(w, http.StatusBadRequest, model.APIResponse{
			OK: false,
			Error: &model.APIError{
				Code:    "query_required",
				Message: "Query is required.",
			},
			Meta:   &model.ResultMeta{TraceID: traceID},
			Config: configStatusPtr(snap.config),
		})
		return
	}

	if snap.service == nil {
		if s.stats != nil {
			s.stats.RecordLookup(false, 0)
		}
		s.reportLookup(observability.LookupEvent{
			TraceID:   traceID,
			Query:     query,
			OK:        false,
			ErrorCode: "service_unavailable",
			Error:     "Lookup service is not initialized.",
		})
		writeJSON(w, http.StatusServiceUnavailable, model.APIResponse{
			OK: false,
			Error: &model.APIError{
				Code:    "service_unavailable",
				Message: "Lookup service is not initialized.",
			},
			Meta:   &model.ResultMeta{TraceID: traceID},
			Config: configStatusPtr(snap.config),
		})
		return
	}

	opts, err := s.optionsFromRequestWithSnapshot(r, snap)
	if err != nil {
		if s.stats != nil {
			s.stats.RecordLookup(false, 0)
		}
		s.reportLookup(observability.LookupEvent{
			TraceID:   traceID,
			Query:     query,
			OK:        false,
			ErrorCode: "option_not_allowed",
			Error:     err.Error(),
		})
		writeJSON(w, http.StatusForbidden, model.APIResponse{
			OK: false,
			Error: &model.APIError{
				Code:    "option_not_allowed",
				Message: err.Error(),
			},
			Meta:   &model.ResultMeta{TraceID: traceID},
			Config: configStatusPtr(snap.config),
		})
		return
	}

	result, err := snap.service.Lookup(r.Context(), query, opts)
	if err != nil {
		if s.stats != nil {
			s.stats.RecordLookup(false, 0)
		}
		if _, ok := err.(normalize.InputError); ok {
			s.reportLookup(observability.LookupEvent{
				TraceID:   traceID,
				Query:     query,
				OK:        false,
				ErrorCode: "invalid_query",
				Error:     err.Error(),
			})
			writeJSON(w, http.StatusBadRequest, model.APIResponse{
				OK: false,
				Error: &model.APIError{
					Code:    "invalid_query",
					Message: err.Error(),
				},
				Meta:   &model.ResultMeta{TraceID: traceID},
				Config: configStatusPtr(snap.config),
			})
			return
		}
		s.reportLookup(observability.LookupEvent{
			TraceID:   traceID,
			Query:     query,
			OK:        false,
			ErrorCode: "lookup_failed",
			Error:     err.Error(),
		})
		writeJSON(w, http.StatusBadGateway, model.APIResponse{
			OK: false,
			Error: &model.APIError{
				Code:    "lookup_failed",
				Message: err.Error(),
			},
			Meta:   &model.ResultMeta{TraceID: traceID},
			Config: configStatusPtr(snap.config),
		})
		return
	}

	result.Meta.TraceID = traceID
	if warning := configReloadWarning(snap.config); warning != "" {
		result.Meta.Warnings = append(result.Meta.Warnings, warning)
	}
	meta := result.Meta
	if s.stats != nil {
		s.stats.RecordLookup(true, meta.ElapsedMs)
		s.stats.RecordProviders(providerTraceViews(meta.Providers))
	}
	s.reportLookup(observability.LookupEvent{
		TraceID:         traceID,
		Query:           result.Query,
		NormalizedQuery: result.NormalizedQuery,
		Type:            string(result.Type),
		Status:          string(result.Status),
		OK:              true,
		ElapsedMs:       meta.ElapsedMs,
		Providers:       providerTraceViews(meta.Providers),
	})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, model.APIResponse{
		OK:     true,
		Result: result,
		Meta:   &meta,
		Config: configStatusPtr(snap.config),
	})
}

func (s *Server) handleLookupAI(w http.ResponseWriter, r *http.Request) {
	snap := s.snapshotFromRequest(r)
	traceID := requestTraceID(r)
	w.Header().Set("X-Trace-ID", traceID)
	w.Header().Set("Cache-Control", "no-store")
	if !snap.cfg.AIEnabled || snap.service == nil {
		writeJSON(w, http.StatusServiceUnavailable, model.APIResponse{
			OK: false,
			Error: &model.APIError{
				Code:    "ai_disabled",
				Message: "AI registration analysis is disabled.",
			},
			Meta:   &model.ResultMeta{TraceID: traceID},
			Config: configStatusPtr(snap.config),
		})
		return
	}

	var payload struct {
		Result *model.LookupResult `json:"result"`
		Force  *bool               `json:"force,omitempty"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAIRequestBytes))
	if err := decoder.Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, model.APIResponse{
			OK: false,
			Error: &model.APIError{
				Code:    "invalid_ai_request",
				Message: "AI request must contain a lookup result.",
			},
			Meta:   &model.ResultMeta{TraceID: traceID},
			Config: configStatusPtr(snap.config),
		})
		return
	}
	if payload.Result == nil || payload.Result.Type != model.QueryDomain {
		writeJSON(w, http.StatusBadRequest, model.APIResponse{
			OK: false,
			Error: &model.APIError{
				Code:    "invalid_ai_request",
				Message: "AI registration analysis only supports domain lookup results.",
			},
			Meta:   &model.ResultMeta{TraceID: traceID},
			Config: configStatusPtr(snap.config),
		})
		return
	}

	force := true
	if payload.Force != nil {
		force = *payload.Force
	}
	result, err := snap.service.ApplyAI(r.Context(), payload.Result, force)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, model.APIResponse{
			OK: false,
			Error: &model.APIError{
				Code:    "ai_lookup_failed",
				Message: err.Error(),
			},
			Meta:   &model.ResultMeta{TraceID: traceID},
			Config: configStatusPtr(snap.config),
		})
		return
	}
	result.Meta.TraceID = traceID
	if warning := configReloadWarning(snap.config); warning != "" {
		result.Meta.Warnings = append(result.Meta.Warnings, warning)
	}
	meta := result.Meta
	writeJSON(w, http.StatusOK, model.APIResponse{
		OK:     true,
		Result: result,
		Meta:   &meta,
		Config: configStatusPtr(snap.config),
	})
}

func (s *Server) handleLookupEnrich(w http.ResponseWriter, r *http.Request) {
	snap := s.snapshotFromRequest(r)
	traceID := requestTraceID(r)
	w.Header().Set("X-Trace-ID", traceID)
	w.Header().Set("Cache-Control", "no-store")
	if snap.service == nil {
		writeJSON(w, http.StatusServiceUnavailable, model.APIResponse{
			OK: false,
			Error: &model.APIError{
				Code:    "service_unavailable",
				Message: "Lookup service is not initialized.",
			},
			Meta:   &model.ResultMeta{TraceID: traceID},
			Config: configStatusPtr(snap.config),
		})
		return
	}

	var payload struct {
		Result *model.LookupResult `json:"result"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAIRequestBytes))
	if err := decoder.Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, model.APIResponse{
			OK: false,
			Error: &model.APIError{
				Code:    "invalid_enrichment_request",
				Message: "Enrichment request must contain a lookup result.",
			},
			Meta:   &model.ResultMeta{TraceID: traceID},
			Config: configStatusPtr(snap.config),
		})
		return
	}
	if payload.Result == nil {
		writeJSON(w, http.StatusBadRequest, model.APIResponse{
			OK: false,
			Error: &model.APIError{
				Code:    "invalid_enrichment_request",
				Message: "Enrichment request must contain a lookup result.",
			},
			Meta:   &model.ResultMeta{TraceID: traceID},
			Config: configStatusPtr(snap.config),
		})
		return
	}

	result, err := snap.service.ApplyDeferred(r.Context(), payload.Result)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, model.APIResponse{
			OK: false,
			Error: &model.APIError{
				Code:    "enrichment_failed",
				Message: err.Error(),
			},
			Meta:   &model.ResultMeta{TraceID: traceID},
			Config: configStatusPtr(snap.config),
		})
		return
	}
	result.Meta.TraceID = traceID
	if warning := configReloadWarning(snap.config); warning != "" {
		result.Meta.Warnings = append(result.Meta.Warnings, warning)
	}
	meta := result.Meta
	writeJSON(w, http.StatusOK, model.APIResponse{
		OK:     true,
		Result: result,
		Meta:   &meta,
		Config: configStatusPtr(snap.config),
	})
}

func (s *Server) handleICP(w http.ResponseWriter, r *http.Request) {
	snap := s.snapshotFromRequest(r)
	traceID := requestTraceID(r)
	w.Header().Set("X-Trace-ID", traceID)
	w.Header().Set("Cache-Control", "no-store")
	if snap.icp == nil || !snap.icp.Enabled() {
		writeJSON(w, http.StatusServiceUnavailable, model.APIResponse{
			OK: false,
			Error: &model.APIError{
				Code:    "icp_disabled",
				Message: "ICP lookup is disabled.",
			},
			Meta:   &model.ResultMeta{TraceID: traceID},
			Config: configStatusPtr(snap.config),
		})
		return
	}
	query := normalize.CleanUserInput(firstNonEmpty(r.URL.Query().Get("domain"), r.URL.Query().Get("query"), r.URL.Query().Get("q")))
	if query == "" {
		writeJSON(w, http.StatusBadRequest, model.APIResponse{
			OK: false,
			Error: &model.APIError{
				Code:    "query_required",
				Message: "Domain is required.",
			},
			Meta:   &model.ResultMeta{TraceID: traceID},
			Config: configStatusPtr(snap.config),
		})
		return
	}
	normalized, err := normalize.New(snap.cfg.DataDir).Normalize(query)
	if err != nil || normalized.Type != model.QueryDomain {
		writeJSON(w, http.StatusBadRequest, model.APIResponse{
			OK: false,
			Error: &model.APIError{
				Code:    "invalid_domain",
				Message: "ICP lookup only supports domain queries.",
			},
			Meta:   &model.ResultMeta{TraceID: traceID},
			Config: configStatusPtr(snap.config),
		})
		return
	}

	result, err := snap.icp.Query(r.Context(), normalized.RegisteredDomain)
	status := http.StatusOK
	response := map[string]any{
		"ok":     true,
		"result": result,
		"meta": map[string]any{
			"traceId": traceID,
		},
	}
	if config := configStatusPtr(snap.config); config != nil {
		response["config"] = config
	}
	if err != nil && result.Status == icp.StatusError {
		status = http.StatusBadGateway
		response["ok"] = false
		response["error"] = model.APIError{
			Code:    "icp_lookup_failed",
			Message: result.Message,
		}
	}
	writeJSON(w, status, response)
}

func (s *Server) reportLookup(event observability.LookupEvent) {
	snap := s.snapshot()
	if snap.reporter == nil {
		return
	}
	go snap.reporter.ReportLookup(context.Background(), event)
}

func providerTraceViews(traces []model.ProviderTrace) []observability.ProviderTraceView {
	views := make([]observability.ProviderTraceView, 0, len(traces))
	for _, trace := range traces {
		views = append(views, observability.ProviderTraceView{
			Source:    string(trace.Source),
			Status:    trace.Status,
			ElapsedMs: trace.ElapsedMs,
		})
	}
	return views
}

func (s *Server) optionsFromRequest(r *http.Request) (model.LookupOptions, error) {
	return s.optionsFromRequestWithSnapshot(r, s.snapshot())
}

func (s *Server) optionsFromRequestWithSnapshot(r *http.Request, snap serverSnapshot) (model.LookupOptions, error) {
	values := r.URL.Query()
	rdapSet := values.Has("rdap")
	whoisSet := values.Has("whois")

	opts := model.LookupOptions{
		ProviderLimit: snap.cfg.ProviderTimeout,
		LookupLimit:   snap.cfg.LookupTimeout,
		WHOISFollow:   -1,
	}

	if !rdapSet && !whoisSet {
		opts.UseRDAP = true
		opts.UseWHOIS = true
	} else {
		opts.UseRDAP = rdapSet && parseBool(values.Get("rdap"))
		opts.UseWHOIS = whoisSet && parseBool(values.Get("whois"))
	}

	opts.RDAPServer = normalize.CleanUserInput(values.Get("rdap_server"))
	opts.WHOISServer = normalize.CleanUserInput(values.Get("whois_server"))
	opts.ExactDomain = parseBool(firstNonEmpty(values.Get("exact_domain"), values.Get("exact")))
	opts.ForceAI = parseBool(firstNonEmpty(values.Get("ai"), values.Get("force_ai")))
	if values.Has("fast") || values.Has("fast_response") {
		opts.FastResponseSet = true
		opts.FastResponse = parseBool(firstNonEmpty(values.Get("fast"), values.Get("fast_response")))
	}
	if values.Has("whois_follow") {
		follow, err := strconv.Atoi(values.Get("whois_follow"))
		if err != nil || follow < 0 || follow > 5 {
			return opts, errors.New("whois_follow must be between 0 and 5")
		}
		opts.WHOISFollow = follow
	}

	if !snap.cfg.AllowCustomServers && (opts.RDAPServer != "" || opts.WHOISServer != "") {
		return opts, errors.New("custom WHOIS/RDAP servers are disabled")
	}
	if snap.cfg.AllowCustomServers {
		if opts.RDAPServer != "" {
			if err := snap.policy.AllowRDAP(r.Context(), opts.RDAPServer); err != nil {
				return opts, err
			}
		}
		if opts.WHOISServer != "" {
			if err := snap.policy.AllowWHOIS(r.Context(), opts.WHOISServer); err != nil {
				return opts, err
			}
		}
	}

	return opts, nil
}

func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withAPIGuard(endpoint apiEndpoint, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap := s.snapshot()
		if err := apiEndpointAllowed(endpoint, r, snap); err != nil {
			writeAPIAccessError(w, err)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), snapshotContextKey{}, snap)))
	}
}

func (s *Server) withLookupGuards(endpoint apiEndpoint, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap := s.snapshot()
		if err := apiEndpointAllowed(endpoint, r, snap); err != nil {
			writeAPIAccessError(w, err)
			return
		}
		if snap.auth != nil {
			if err := snap.auth.Authenticate(r); err != nil {
				w.Header().Set("WWW-Authenticate", "Bearer")
				writeJSON(w, http.StatusUnauthorized, model.APIResponse{
					OK: false,
					Error: &model.APIError{
						Code:    "unauthorized",
						Message: "Authentication is required.",
					},
				})
				return
			}
		}
		if snap.limiter != nil {
			decision := snap.limiter.Allow(s.rateLimitKeyWithSnapshot(r, snap), time.Now())
			if decision.ResetAt.After(time.Now()) {
				w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(decision.ResetAt.Unix(), 10))
			}
			if decision.Remaining >= 0 {
				w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(decision.Remaining))
			}
			if !decision.Allowed {
				writeJSON(w, http.StatusTooManyRequests, model.APIResponse{
					OK: false,
					Error: &model.APIError{
						Code:    "rate_limited",
						Message: "Too many lookup requests.",
					},
				})
				return
			}
		}
		next(w, r.WithContext(context.WithValue(r.Context(), snapshotContextKey{}, snap)))
	}
}

func (s *Server) withAdminGuard(endpoint apiEndpoint, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap := s.snapshot()
		if err := apiEndpointAllowed(endpoint, r, snap); err != nil {
			writeAPIAccessError(w, err)
			return
		}
		if snap.auth != nil {
			if err := snap.auth.Authenticate(r); err != nil {
				writeJSON(w, http.StatusUnauthorized, model.APIResponse{
					OK: false,
					Error: &model.APIError{
						Code:    "unauthorized",
						Message: "Authentication is required.",
					},
				})
				return
			}
		}
		next(w, r.WithContext(context.WithValue(r.Context(), snapshotContextKey{}, snap)))
	}
}

type apiAccessError struct {
	status  int
	code    string
	message string
}

func (e apiAccessError) Error() string {
	return e.message
}

func apiEndpointAllowed(endpoint apiEndpoint, r *http.Request, snap serverSnapshot) error {
	if !snap.cfg.APIEnabled {
		return apiAccessError{status: http.StatusNotFound, code: "api_disabled", message: "API is disabled."}
	}
	if !endpointEnabled(endpoint, snap.cfg) {
		return apiAccessError{status: http.StatusNotFound, code: "api_endpoint_disabled", message: "This API endpoint is disabled."}
	}
	if !clientIPAllowed(r, snap) {
		return apiAccessError{status: http.StatusForbidden, code: "ip_not_allowed", message: "Client IP is not allowed."}
	}
	return nil
}

func writeAPIAccessError(w http.ResponseWriter, err error) {
	accessErr, ok := err.(apiAccessError)
	if !ok {
		accessErr = apiAccessError{status: http.StatusForbidden, code: "api_forbidden", message: "API access is forbidden."}
	}
	writeJSON(w, accessErr.status, model.APIResponse{
		OK: false,
		Error: &model.APIError{
			Code:    accessErr.code,
			Message: accessErr.message,
		},
	})
}

func endpointEnabled(endpoint apiEndpoint, cfg config.Config) bool {
	switch endpoint {
	case endpointHealth:
		return cfg.APIHealthEnabled
	case endpointVersion:
		return cfg.APIVersionEnabled
	case endpointCapabilities:
		return cfg.APICapabilitiesEnabled
	case endpointMetrics:
		return cfg.APIMetricsEnabled
	case endpointLookup:
		return cfg.APILookupEnabled
	case endpointLookupAI:
		return cfg.APILookupAIEnabled
	case endpointLookupEnrich:
		return cfg.APILookupEnrichEnabled
	case endpointICP:
		return cfg.APIICPEnabled
	case endpointAdminStatus:
		return cfg.APIAdminEnabled && cfg.APIAdminStatusEnabled
	case endpointAdminConfig:
		return cfg.APIAdminEnabled && cfg.APIAdminConfigEnabled
	default:
		return false
	}
}

func clientIPAllowed(r *http.Request, snap serverSnapshot) bool {
	allowlist := cleanAllowlist(snap.cfg.APIIPAllowlist)
	if len(allowlist) == 0 {
		return true
	}
	ip := net.ParseIP(clientIP(r, snap))
	if ip == nil {
		return false
	}
	for _, entry := range allowlist {
		if allowed := net.ParseIP(entry); allowed != nil {
			if allowed.Equal(ip) {
				return true
			}
			continue
		}
		_, network, err := net.ParseCIDR(entry)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func cleanAllowlist(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		traceID := requestTraceID(r)
		r.Header.Set("X-Request-ID", traceID)
		w.Header().Set("X-Trace-ID", traceID)
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		body, _ := json.Marshal(map[string]any{
			"level":     "info",
			"event":     "http_request",
			"method":    r.Method,
			"path":      r.URL.Path,
			"status":    recorder.status,
			"elapsedMs": time.Since(start).Milliseconds(),
			"traceId":   traceID,
			"remote":    r.RemoteAddr,
		})
		log.Print(string(body))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func parseBool(value string) bool {
	if value == "" {
		return false
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return value == "1"
	}
	return parsed
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func requestTraceID(r *http.Request) string {
	if value := strings.TrimSpace(r.Header.Get("X-Request-ID")); validTraceID(value) {
		return value
	}
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(bytes[:])
}

func validTraceID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func (s *Server) rateLimitKey(r *http.Request) string {
	return s.rateLimitKeyWithSnapshot(r, s.snapshot())
}

func (s *Server) rateLimitKeyWithSnapshot(r *http.Request, snap serverSnapshot) string {
	if token := strings.TrimSpace(r.Header.Get("Authorization")); token != "" {
		return token
	}
	return clientIP(r, snap)
}

func clientIP(r *http.Request, snap serverSnapshot) string {
	if snap.cfg.TrustProxy {
		if forwarded := clientIPFromForwardedFor(r.Header.Get("X-Forwarded-For")); forwarded != "" {
			return forwarded
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func clientIPFromForwardedFor(value string) string {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if host, _, err := net.SplitHostPort(part); err == nil {
			part = host
		}
		if ip := net.ParseIP(part); ip != nil {
			return ip.String()
		}
	}
	return ""
}
