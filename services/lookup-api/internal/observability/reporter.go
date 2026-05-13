package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type LookupEvent struct {
	TraceID         string              `json:"traceId,omitempty"`
	Query           string              `json:"query,omitempty"`
	NormalizedQuery string              `json:"normalizedQuery,omitempty"`
	Type            string              `json:"type,omitempty"`
	Status          string              `json:"status,omitempty"`
	OK              bool                `json:"ok"`
	ErrorCode       string              `json:"errorCode,omitempty"`
	Error           string              `json:"error,omitempty"`
	ElapsedMs       int64               `json:"elapsedMs"`
	Providers       []ProviderTraceView `json:"providers,omitempty"`
}

type Reporter interface {
	ReportLookup(ctx context.Context, event LookupEvent)
}

type MultiReporter []Reporter

func (m MultiReporter) ReportLookup(ctx context.Context, event LookupEvent) {
	for _, reporter := range m {
		if reporter != nil {
			reporter.ReportLookup(ctx, event)
		}
	}
}

type LogReporter struct{}

func (LogReporter) ReportLookup(_ context.Context, event LookupEvent) {
	body, err := json.Marshal(map[string]any{
		"level": "info",
		"event": "lookup",
		"data":  event,
	})
	if err != nil {
		return
	}
	log.Print(string(body))
}

type WebhookReporter struct {
	URL     string
	Timeout time.Duration
	Client  *http.Client
}

func (r WebhookReporter) ReportLookup(ctx context.Context, event LookupEvent) {
	url := strings.TrimSpace(r.URL)
	if url == "" {
		return
	}
	body, err := json.Marshal(event)
	if err != nil {
		return
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	reportCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(reportCtx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Printf("observability webhook request build failed: %v", err)
		return
	}
	request.Header.Set("Content-Type", "application/json")
	client := r.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		log.Printf("observability webhook request failed: %v", err)
		return
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		log.Printf("observability webhook returned HTTP %d", response.StatusCode)
	}
}

func NewReporter(mode, webhookURL string, timeout time.Duration) (Reporter, error) {
	var reporters []Reporter
	for _, part := range strings.Split(mode, ",") {
		switch strings.ToLower(strings.TrimSpace(part)) {
		case "", "none", "off", "false":
			continue
		case "log", "stdout":
			reporters = append(reporters, LogReporter{})
		case "webhook":
			if strings.TrimSpace(webhookURL) == "" {
				return nil, errors.New("webhook reporter requires WHOICE_OBSERVABILITY_WEBHOOK_URL")
			}
			reporters = append(reporters, WebhookReporter{URL: webhookURL, Timeout: timeout})
		default:
			return nil, errors.New("unknown observability reporter: " + part)
		}
	}
	if len(reporters) == 0 {
		return nil, nil
	}
	if len(reporters) == 1 {
		return reporters[0], nil
	}
	return MultiReporter(reporters), nil
}
