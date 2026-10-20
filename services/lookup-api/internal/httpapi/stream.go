package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

// lookupStream serves GET /api/lookup?stream=1 as NDJSON. Each preview is a
// line {"partial": LookupResult}; the last line is {"status": N, "final":
// APIResponse}, where N is the HTTP status the plain endpoint would have
// returned. The handler writes its final response through the stream as if
// it were the ResponseWriter, so every error path is covered.
type lookupStream struct {
	w       http.ResponseWriter
	mu      sync.Mutex
	started bool
	status  int
	final   bytes.Buffer
}

func newLookupStream(w http.ResponseWriter) *lookupStream {
	return &lookupStream{w: w, status: http.StatusOK}
}

func (s *lookupStream) Header() http.Header { return s.w.Header() }

func (s *lookupStream) WriteHeader(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = status
}

func (s *lookupStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.final.Write(p)
}

func (s *lookupStream) startLocked() {
	if s.started {
		return
	}
	s.started = true
	header := s.w.Header()
	header.Set("Content-Type", "application/x-ndjson; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("X-Accel-Buffering", "no")
	header.Del("Content-Length")
	s.w.WriteHeader(http.StatusOK)
}

func (s *lookupStream) writeLineLocked(value any) {
	s.startLocked()
	_ = json.NewEncoder(s.w).Encode(value)
	if flusher, ok := s.w.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (s *lookupStream) partial(result *model.LookupResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeLineLocked(struct {
		Partial *model.LookupResult `json:"partial"`
	}{result})
}

func (s *lookupStream) finish() {
	s.mu.Lock()
	defer s.mu.Unlock()
	body := bytes.TrimSpace(s.final.Bytes())
	if len(body) == 0 || !json.Valid(body) {
		body = []byte(`{"ok":false,"error":{"code":"empty_response","message":"Lookup produced no response."}}`)
	}
	s.writeLineLocked(struct {
		Status int             `json:"status"`
		Final  json.RawMessage `json:"final"`
	}{s.status, body})
}
