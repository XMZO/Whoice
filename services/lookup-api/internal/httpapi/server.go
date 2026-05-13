package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
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

const Version = "v0.01beta"
const maxAIRequestBytes = 8 << 20

type Server struct {
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
}

func New(cfg config.Config, service *lookup.Service, plugins []model.PluginInfo, stats *observability.Stats) *Server {
	limiter, err := ratelimit.New(cfg.RateLimitEnabled, cfg.RateLimitAnon)
	if err != nil {
		limiter, _ = ratelimit.New(cfg.RateLimitEnabled, "60/min")
	}
	s := &Server{
		cfg:     cfg,
		service: service,
		icp:     icp.NewClient(cfg),
		plugins: plugins,
		policy:  security.NewServerPolicy(cfg.AllowPrivateServers),
		auth:    auth.NewStatic(cfg.AuthMode, cfg.SitePassword, cfg.APITokens),
		limiter: &limiter,
		stats:   stats,
		mux:     http.NewServeMux(),
	}
	if reporter, err := observability.NewReporter(cfg.Reporter, cfg.ReporterWebhookURL, cfg.ReporterTimeout); err == nil {
		s.reporter = reporter
	} else {
		log.Printf("observability reporter disabled: %v", err)
	}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler {
	return s.withLogging(s.withCORS(s.mux))
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/version", s.handleVersion)
	s.mux.HandleFunc("GET /api/capabilities", s.handleCapabilities)
	s.mux.HandleFunc("GET /api/metrics", s.handleMetrics)
	s.mux.HandleFunc("GET /api/lookup", s.withLookupGuards(s.handleLookup))
	s.mux.HandleFunc("POST /api/lookup/ai", s.withLookupGuards(s.handleLookupAI))
	s.mux.HandleFunc("GET /api/icp", s.withLookupGuards(s.handleICP))
	s.mux.HandleFunc("GET /api/admin/status", s.withAdminGuard(s.handleAdminStatus))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"version": Version,
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version": Version,
		"data": map[string]string{
			"schema": "0.1",
		},
		"capabilities": s.cfg.Capabilities(),
		"plugins":      s.plugins,
	})
}

func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	capabilities := s.cfg.Capabilities()
	writeJSON(w, http.StatusOK, model.APIResponse{
		OK:           true,
		Capabilities: &capabilities,
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.MetricsEnabled {
		writeJSON(w, http.StatusNotFound, model.APIResponse{
			OK: false,
			Error: &model.APIError{
				Code:    "metrics_disabled",
				Message: "Metrics endpoint is disabled.",
			},
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
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"version":      Version,
		"capabilities": s.cfg.Capabilities(),
		"plugins":      s.plugins,
		"stats":        s.stats.Snapshot(),
	})
}

func (s *Server) handleLookup(w http.ResponseWriter, r *http.Request) {
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
			Meta: &model.ResultMeta{TraceID: traceID},
		})
		return
	}

	opts, err := s.optionsFromRequest(r)
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
			Meta: &model.ResultMeta{TraceID: traceID},
		})
		return
	}

	result, err := s.service.Lookup(r.Context(), query, opts)
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
				Meta: &model.ResultMeta{TraceID: traceID},
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
			Meta: &model.ResultMeta{TraceID: traceID},
		})
		return
	}

	result.Meta.TraceID = traceID
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
	})
}

func (s *Server) handleLookupAI(w http.ResponseWriter, r *http.Request) {
	traceID := requestTraceID(r)
	w.Header().Set("X-Trace-ID", traceID)
	w.Header().Set("Cache-Control", "no-store")
	if !s.cfg.AIEnabled || s.service == nil {
		writeJSON(w, http.StatusServiceUnavailable, model.APIResponse{
			OK: false,
			Error: &model.APIError{
				Code:    "ai_disabled",
				Message: "AI registration analysis is disabled.",
			},
			Meta: &model.ResultMeta{TraceID: traceID},
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
			Meta: &model.ResultMeta{TraceID: traceID},
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
			Meta: &model.ResultMeta{TraceID: traceID},
		})
		return
	}

	force := true
	if payload.Force != nil {
		force = *payload.Force
	}
	result, err := s.service.ApplyAI(r.Context(), payload.Result, force)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, model.APIResponse{
			OK: false,
			Error: &model.APIError{
				Code:    "ai_lookup_failed",
				Message: err.Error(),
			},
			Meta: &model.ResultMeta{TraceID: traceID},
		})
		return
	}
	result.Meta.TraceID = traceID
	meta := result.Meta
	writeJSON(w, http.StatusOK, model.APIResponse{
		OK:     true,
		Result: result,
		Meta:   &meta,
	})
}

func (s *Server) handleICP(w http.ResponseWriter, r *http.Request) {
	traceID := requestTraceID(r)
	w.Header().Set("X-Trace-ID", traceID)
	w.Header().Set("Cache-Control", "no-store")
	if s.icp == nil || !s.icp.Enabled() {
		writeJSON(w, http.StatusServiceUnavailable, model.APIResponse{
			OK: false,
			Error: &model.APIError{
				Code:    "icp_disabled",
				Message: "ICP lookup is disabled.",
			},
			Meta: &model.ResultMeta{TraceID: traceID},
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
			Meta: &model.ResultMeta{TraceID: traceID},
		})
		return
	}
	normalized, err := normalize.New(s.cfg.DataDir).Normalize(query)
	if err != nil || normalized.Type != model.QueryDomain {
		writeJSON(w, http.StatusBadRequest, model.APIResponse{
			OK: false,
			Error: &model.APIError{
				Code:    "invalid_domain",
				Message: "ICP lookup only supports domain queries.",
			},
			Meta: &model.ResultMeta{TraceID: traceID},
		})
		return
	}

	result, err := s.icp.Query(r.Context(), normalized.RegisteredDomain)
	status := http.StatusOK
	response := map[string]any{
		"ok":     true,
		"result": result,
		"meta": map[string]any{
			"traceId": traceID,
		},
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
	if s == nil || s.reporter == nil {
		return
	}
	go s.reporter.ReportLookup(context.Background(), event)
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
	values := r.URL.Query()
	rdapSet := values.Has("rdap")
	whoisSet := values.Has("whois")

	opts := model.LookupOptions{
		ProviderLimit: s.cfg.ProviderTimeout,
		LookupLimit:   s.cfg.LookupTimeout,
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
	if values.Has("whois_follow") {
		follow, err := strconv.Atoi(values.Get("whois_follow"))
		if err != nil || follow < 0 || follow > 5 {
			return opts, errors.New("whois_follow must be between 0 and 5")
		}
		opts.WHOISFollow = follow
	}

	if !s.cfg.AllowCustomServers && (opts.RDAPServer != "" || opts.WHOISServer != "") {
		return opts, errors.New("custom WHOIS/RDAP servers are disabled")
	}
	if s.cfg.AllowCustomServers {
		if opts.RDAPServer != "" {
			if err := s.policy.AllowRDAP(r.Context(), opts.RDAPServer); err != nil {
				return opts, err
			}
		}
		if opts.WHOISServer != "" {
			if err := s.policy.AllowWHOIS(r.Context(), opts.WHOISServer); err != nil {
				return opts, err
			}
		}
	}

	return opts, nil
}

func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withLookupGuards(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.auth != nil {
			if err := s.auth.Authenticate(r); err != nil {
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
		if s.limiter != nil {
			decision := s.limiter.Allow(s.rateLimitKey(r), time.Now())
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
		next(w, r)
	}
}

func (s *Server) withAdminGuard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.auth != nil {
			if err := s.auth.Authenticate(r); err != nil {
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
		next(w, r)
	}
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
	if token := strings.TrimSpace(r.Header.Get("Authorization")); token != "" {
		return token
	}
	if s.cfg.TrustProxy {
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
