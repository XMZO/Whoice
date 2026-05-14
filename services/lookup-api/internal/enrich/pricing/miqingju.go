package pricing

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

const (
	miqingjuSnapshotURL = "https://api.miqingju.com/api/v1/snapshot"
	miqingjuSourceName  = "miqingju"
	miqingjuWebsite     = "https://miqingju.com"
)

type MiqingjuSnapshotSource struct {
	client   *http.Client
	endpoint string
	ttl      time.Duration

	mu         sync.RWMutex
	refreshMu  sync.Mutex
	pricing    map[string]model.PricingInfo
	loadedAt   time.Time
	refreshing bool
	lastErr    error
	lastErrAt  time.Time
	startOnce  sync.Once
}

func NewMiqingjuSnapshotSource() *MiqingjuSnapshotSource {
	return newMiqingjuSnapshotSource(miqingjuSnapshotURL, http.DefaultClient, time.Hour)
}

func newMiqingjuSnapshotSource(endpoint string, client *http.Client, ttl time.Duration) *MiqingjuSnapshotSource {
	if client == nil {
		client = http.DefaultClient
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	source := &MiqingjuSnapshotSource{
		client:   client,
		endpoint: endpoint,
		ttl:      ttl,
		pricing:  map[string]model.PricingInfo{},
	}
	return source
}

func (s *MiqingjuSnapshotSource) Name() string {
	return miqingjuSourceName
}

func (s *MiqingjuSnapshotSource) Lookup(ctx context.Context, suffix string) (model.PricingInfo, bool, error) {
	if s == nil {
		return model.PricingInfo{}, false, nil
	}
	suffix = normalizeSuffix(suffix)
	if suffix == "" {
		return model.PricingInfo{}, false, nil
	}
	if !s.hasSnapshot() {
		if s.isRefreshing() {
			return model.PricingInfo{}, false, nil
		}
		refreshCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, err := s.refreshSync(refreshCtx)
		cancel()
		if err != nil {
			return model.PricingInfo{}, false, err
		}
	} else if s.isExpired() {
		s.refreshAsync()
	}
	s.mu.RLock()
	value, ok := s.pricing[suffix]
	lastErr := s.lastErr
	loaded := !s.loadedAt.IsZero()
	s.mu.RUnlock()
	if ok {
		return value, true, nil
	}
	if !loaded && lastErr != nil {
		return model.PricingInfo{}, false, lastErr
	}
	return model.PricingInfo{}, false, nil
}

func (s *MiqingjuSnapshotSource) Start(ctx context.Context) {
	if s == nil {
		return
	}
	s.startOnce.Do(func() {
		go s.run(ctx)
	})
}

func (s *MiqingjuSnapshotSource) run(ctx context.Context) {
	s.refreshAsync()
	ticker := time.NewTicker(s.ttl)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refreshAsync()
		}
	}
}

func (s *MiqingjuSnapshotSource) hasSnapshot() bool {
	s.mu.RLock()
	ok := !s.loadedAt.IsZero()
	s.mu.RUnlock()
	return ok
}

func (s *MiqingjuSnapshotSource) isExpired() bool {
	s.mu.RLock()
	expired := !s.loadedAt.IsZero() && time.Since(s.loadedAt) > s.ttl
	s.mu.RUnlock()
	return expired
}

func (s *MiqingjuSnapshotSource) isRefreshing() bool {
	s.mu.RLock()
	refreshing := s.refreshing
	s.mu.RUnlock()
	return refreshing
}

func (s *MiqingjuSnapshotSource) refreshSync(ctx context.Context) (int, error) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	if s.hasSnapshot() && !s.isExpired() {
		s.mu.RLock()
		count := len(s.pricing)
		s.mu.RUnlock()
		return count, nil
	}
	return s.refresh(ctx)
}

func (s *MiqingjuSnapshotSource) refreshAsync() {
	s.mu.Lock()
	if s.refreshing {
		s.mu.Unlock()
		return
	}
	s.refreshing = true
	s.mu.Unlock()
	go func() {
		defer func() {
			s.mu.Lock()
			s.refreshing = false
			s.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = s.refreshSync(ctx)
	}()
}

func (s *MiqingjuSnapshotSource) refresh(ctx context.Context) (int, error) {
	if s == nil {
		return 0, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Whoice/0.0.1 pricing")
	resp, err := s.client.Do(req)
	if err != nil {
		s.recordError(err)
		return 0, err
	}
	defer resp.Body.Close()
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(strings.ToLower(contentType), "text/html") {
		err := fmt.Errorf("miqingju snapshot returned HTML content")
		s.recordError(err)
		return 0, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := fmt.Errorf("miqingju snapshot returned HTTP %d", resp.StatusCode)
		s.recordError(err)
		return 0, err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		s.recordError(err)
		return 0, err
	}
	pricing, updatedAt, err := parseMiqingjuSnapshot(body)
	if err != nil {
		s.recordError(err)
		return 0, err
	}
	s.mu.Lock()
	s.pricing = pricing
	s.loadedAt = time.Now()
	s.lastErr = nil
	s.lastErrAt = time.Time{}
	if updatedAt != "" {
		for suffix, value := range s.pricing {
			if value.UpdatedAt == "" {
				value.UpdatedAt = updatedAt
				s.pricing[suffix] = value
			}
		}
	}
	count := len(s.pricing)
	s.mu.Unlock()
	return count, nil
}

func (s *MiqingjuSnapshotSource) recordError(err error) {
	s.mu.Lock()
	s.lastErr = err
	s.lastErrAt = time.Now()
	s.mu.Unlock()
}

type miqingjuSnapshotResponse struct {
	Success   bool                                 `json:"success"`
	Timestamp string                               `json:"timestamp"`
	Data      map[string]miqingjuSnapshotTLDPrices `json:"data"`
}

type miqingjuSnapshotTLDPrices struct {
	Registration *miqingjuPriceEntry `json:"registration"`
	Renewal      *miqingjuPriceEntry `json:"renewal"`
	Transfer     *miqingjuPriceEntry `json:"transfer"`
}

type miqingjuPriceEntry struct {
	Registrar string   `json:"registrar"`
	Website   string   `json:"website"`
	Logo      string   `json:"logo"`
	Price     *float64 `json:"price"`
	Currency  string   `json:"currency"`
	PriceCNY  *float64 `json:"price_cny"`
}

func parseMiqingjuSnapshot(body []byte) (map[string]model.PricingInfo, string, error) {
	var response miqingjuSnapshotResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, "", err
	}
	if !response.Success {
		return nil, "", fmt.Errorf("miqingju snapshot success=false")
	}
	pricing := make(map[string]model.PricingInfo, len(response.Data))
	for suffix, entry := range response.Data {
		key := normalizeSuffix(suffix)
		if key == "" {
			continue
		}
		info := model.PricingInfo{
			Provider:  miqingjuSourceName,
			Source:    miqingjuWebsite,
			UpdatedAt: strings.TrimSpace(response.Timestamp),
		}
		if entry.Registration != nil {
			info.RegisterOffer = entry.Registration.toModel()
			info.Register = pricePtr(info.RegisterOffer)
			info.Currency = firstNonEmpty(info.Currency, info.RegisterOffer.Currency)
		}
		if entry.Renewal != nil {
			info.RenewOffer = entry.Renewal.toModel()
			info.Renew = pricePtr(info.RenewOffer)
			info.Currency = firstNonEmpty(info.Currency, info.RenewOffer.Currency)
		}
		if entry.Transfer != nil {
			info.TransferOffer = entry.Transfer.toModel()
			info.Transfer = pricePtr(info.TransferOffer)
			info.Currency = firstNonEmpty(info.Currency, info.TransferOffer.Currency)
		}
		if info.Register != nil || info.Renew != nil || info.Transfer != nil {
			pricing[key] = info
		}
	}
	return pricing, strings.TrimSpace(response.Timestamp), nil
}

func (e miqingjuPriceEntry) toModel() *model.PricingOffer {
	return &model.PricingOffer{
		Registrar: strings.TrimSpace(e.Registrar),
		Website:   strings.TrimSpace(e.Website),
		Logo:      strings.TrimSpace(e.Logo),
		Price:     cloneFloat(e.Price),
		Currency:  strings.TrimSpace(e.Currency),
		PriceCNY:  cloneFloat(e.PriceCNY),
	}
}

func pricePtr(offer *model.PricingOffer) *float64 {
	if offer == nil || offer.Price == nil {
		return nil
	}
	value := *offer.Price
	return &value
}

func cloneFloat(value *float64) *float64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
