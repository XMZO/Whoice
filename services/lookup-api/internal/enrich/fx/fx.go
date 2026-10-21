// Package fx keeps daily USD-based exchange rates for converting registration
// prices. Rates are fetched from public, keyless sources (first that answers
// wins), cached in data/cache/fx.json, and refreshed when older than the
// configured TTL.
package fx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

// Rates are units of each currency per one USD.
type Rates struct {
	Rates     map[string]float64 `json:"rates"`
	Source    string             `json:"source"`
	UpdatedAt string             `json:"updatedAt,omitempty"`
	FetchedAt time.Time          `json:"fetchedAt"`
}

type source struct {
	name  string
	url   string
	parse func([]byte) (map[string]float64, string, error)
}

var defaultSources = []source{
	{name: "open.er-api.com", url: "https://open.er-api.com/v6/latest/USD", parse: parseOpenER},
	{name: "currency-api (jsDelivr)", url: "https://cdn.jsdelivr.net/npm/@fawazahmed0/currency-api@latest/v1/currencies/usd.json", parse: parseCurrencyAPI},
	{name: "Frankfurter (ECB)", url: "https://api.frankfurter.dev/v1/latest?base=USD", parse: parseFrankfurter},
}

type Service struct {
	path    string
	ttl     time.Duration
	client  *http.Client
	sources []source
	now     func() time.Time

	mu         sync.Mutex
	loaded     bool
	current    *Rates
	refreshing bool
}

// New returns a rate service; ttl < 0 never expires, ttl == 0 fetches on
// every deferred request.
func New(dataDir string, ttl time.Duration) *Service {
	path := ""
	if dataDir != "" {
		path = filepath.Join(dataDir, "cache", "fx.json")
	}
	return &Service{path: path, ttl: ttl, client: &http.Client{Timeout: 8 * time.Second}, sources: defaultSources, now: time.Now}
}

// Snapshot returns the rates for the given currencies. With allowFetch it
// refreshes expired rates synchronously (deferred enrichment); without, it
// returns what is cached and refreshes in the background (fast path).
func (s *Service) Snapshot(ctx context.Context, currencies []string, allowFetch bool) *model.FXRates {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	s.loadLocked()
	rates := s.current
	expired := rates == nil || s.ttl == 0 || (s.ttl > 0 && s.now().Sub(rates.FetchedAt) > s.ttl)
	s.mu.Unlock()

	if expired {
		if allowFetch {
			if fresh, err := s.refresh(ctx); err == nil {
				rates = fresh
			}
		} else {
			s.refreshAsync()
		}
	}
	if rates == nil {
		return nil
	}
	return subset(rates, currencies)
}

func subset(rates *Rates, currencies []string) *model.FXRates {
	out := &model.FXRates{
		Base:      "USD",
		Rates:     map[string]float64{},
		Source:    rates.Source,
		UpdatedAt: rates.UpdatedAt,
		CachedAt:  rates.FetchedAt.UTC().Format(time.RFC3339),
	}
	for _, code := range append([]string{"USD", "CNY"}, currencies...) {
		code = strings.ToUpper(strings.TrimSpace(code))
		if rate, ok := rates.Rates[code]; ok && rate > 0 {
			out.Rates[code] = rate
		}
	}
	return out
}

func (s *Service) refreshAsync() {
	s.mu.Lock()
	if s.refreshing {
		s.mu.Unlock()
		return
	}
	s.refreshing = true
	s.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, _ = s.refresh(ctx)
	}()
}

func (s *Service) refresh(ctx context.Context) (*Rates, error) {
	defer func() {
		s.mu.Lock()
		s.refreshing = false
		s.mu.Unlock()
	}()
	var problems []string
	for _, src := range s.sources {
		rates, updated, err := s.fetch(ctx, src)
		if err != nil {
			problems = append(problems, src.name+": "+err.Error())
			continue
		}
		fresh := &Rates{Rates: rates, Source: src.name, UpdatedAt: updated, FetchedAt: s.now().UTC()}
		s.mu.Lock()
		s.current = fresh
		s.saveLocked()
		s.mu.Unlock()
		return fresh, nil
	}
	return nil, errors.New(strings.Join(problems, "; "))
}

func (s *Service) fetch(ctx context.Context, src source) (map[string]float64, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "Whoice/0.1 (+https://github.com/XMZO/Whoice)")
	res, err := s.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("HTTP %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, "", err
	}
	rates, updated, err := src.parse(body)
	if err != nil {
		return nil, "", err
	}
	if rates["CNY"] <= 0 {
		return nil, "", errors.New("response has no CNY rate")
	}
	rates["USD"] = 1
	return rates, updated, nil
}

func (s *Service) loadLocked() {
	if s.loaded {
		return
	}
	s.loaded = true
	if s.path == "" {
		return
	}
	body, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var rates Rates
	if json.Unmarshal(body, &rates) == nil && len(rates.Rates) > 0 {
		s.current = &rates
	}
}

func (s *Service) saveLocked() {
	if s.path == "" || s.current == nil {
		return
	}
	body, err := json.Marshal(s.current)
	if err != nil {
		return
	}
	if os.MkdirAll(filepath.Dir(s.path), 0o755) != nil {
		return
	}
	tmp := s.path + ".tmp"
	if os.WriteFile(tmp, body, 0o644) == nil {
		_ = os.Rename(tmp, s.path)
	}
}

func parseOpenER(body []byte) (map[string]float64, string, error) {
	var payload struct {
		Result  string             `json:"result"`
		Updated string             `json:"time_last_update_utc"`
		Rates   map[string]float64 `json:"rates"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, "", err
	}
	if payload.Result != "success" {
		return nil, "", fmt.Errorf("result %q", payload.Result)
	}
	updated := payload.Updated
	if parsed, err := time.Parse(time.RFC1123Z, updated); err == nil {
		updated = parsed.UTC().Format(time.RFC3339)
	}
	return upper(payload.Rates), updated, nil
}

func parseCurrencyAPI(body []byte) (map[string]float64, string, error) {
	var payload struct {
		Date string             `json:"date"`
		USD  map[string]float64 `json:"usd"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, "", err
	}
	return upper(payload.USD), payload.Date, nil
}

func parseFrankfurter(body []byte) (map[string]float64, string, error) {
	var payload struct {
		Date  string             `json:"date"`
		Rates map[string]float64 `json:"rates"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, "", err
	}
	return upper(payload.Rates), payload.Date, nil
}

func upper(rates map[string]float64) map[string]float64 {
	out := make(map[string]float64, len(rates))
	for code, rate := range rates {
		if rate > 0 {
			out[strings.ToUpper(code)] = rate
		}
	}
	return out
}
