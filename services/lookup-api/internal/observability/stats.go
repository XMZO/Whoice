package observability

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type Stats struct {
	startedAt time.Time
	mu        sync.RWMutex
	lookups   LookupStats
	providers map[string]ProviderStats
}

var latencyBucketsMs = []int64{50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000}

type LookupStats struct {
	Total       uint64            `json:"total"`
	Succeeded   uint64            `json:"succeeded"`
	Failed      uint64            `json:"failed"`
	LastElapsed int64             `json:"lastElapsedMs"`
	Latency     HistogramSnapshot `json:"latencyMs"`
}

type ProviderStats struct {
	Total       uint64            `json:"total"`
	Succeeded   uint64            `json:"succeeded"`
	Failed      uint64            `json:"failed"`
	Skipped     uint64            `json:"skipped"`
	LastElapsed int64             `json:"lastElapsedMs"`
	Latency     HistogramSnapshot `json:"latencyMs"`
}

type HistogramSnapshot struct {
	Buckets map[string]uint64 `json:"buckets"`
	Sum     uint64            `json:"sum"`
	Count   uint64            `json:"count"`
}

type latencyHistogram struct {
	Buckets []uint64
	Sum     uint64
	Count   uint64
}

type Snapshot struct {
	StartedAt string                   `json:"startedAt"`
	UptimeSec int64                    `json:"uptimeSec"`
	Lookups   LookupStats              `json:"lookups"`
	Providers map[string]ProviderStats `json:"providers,omitempty"`
}

func NewStats() *Stats {
	return &Stats{startedAt: time.Now().UTC(), providers: map[string]ProviderStats{}}
}

func (s *Stats) RecordLookup(succeeded bool, elapsedMs int64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lookups.Total++
	if succeeded {
		s.lookups.Succeeded++
	} else {
		s.lookups.Failed++
	}
	s.lookups.LastElapsed = elapsedMs
	s.lookups.Latency = recordLatency(s.lookups.Latency, elapsedMs)
}

func (s *Stats) RecordProviders(traces []ProviderTraceView) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.providers == nil {
		s.providers = map[string]ProviderStats{}
	}
	for _, trace := range traces {
		if trace.Source == "" {
			continue
		}
		current := s.providers[trace.Source]
		current.Total++
		switch trace.Status {
		case "ok":
			current.Succeeded++
		case "skipped":
			current.Skipped++
		default:
			current.Failed++
		}
		current.LastElapsed = trace.ElapsedMs
		current.Latency = recordLatency(current.Latency, trace.ElapsedMs)
		s.providers[trace.Source] = current
	}
}

func (s *Stats) Snapshot() Snapshot {
	if s == nil {
		return Snapshot{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	providers := make(map[string]ProviderStats, len(s.providers))
	for key, value := range s.providers {
		providers[key] = value
	}
	return Snapshot{
		StartedAt: s.startedAt.Format(time.RFC3339),
		UptimeSec: int64(time.Since(s.startedAt).Seconds()),
		Lookups:   s.lookups,
		Providers: providers,
	}
}

func (s *Stats) Prometheus() string {
	snapshot := s.Snapshot()
	var builder strings.Builder
	writeMetric(&builder, "whoice_uptime_seconds", "Time since the lookup API process started.", nil, snapshot.UptimeSec)
	writeMetric(&builder, "whoice_lookup_requests_total", "Total lookup requests by outcome.", map[string]string{"outcome": "success"}, snapshot.Lookups.Succeeded)
	writeMetric(&builder, "whoice_lookup_requests_total", "Total lookup requests by outcome.", map[string]string{"outcome": "failure"}, snapshot.Lookups.Failed)
	writeMetric(&builder, "whoice_lookup_last_elapsed_milliseconds", "Elapsed milliseconds for the most recent lookup.", nil, snapshot.Lookups.LastElapsed)
	writeHistogram(&builder, "whoice_lookup_latency_milliseconds", "Lookup latency histogram in milliseconds.", nil, snapshot.Lookups.Latency)

	providerNames := make([]string, 0, len(snapshot.Providers))
	for name := range snapshot.Providers {
		providerNames = append(providerNames, name)
	}
	sort.Strings(providerNames)
	for _, name := range providerNames {
		stats := snapshot.Providers[name]
		writeMetric(&builder, "whoice_provider_requests_total", "Total provider requests by provider and outcome.", map[string]string{"provider": name, "outcome": "success"}, stats.Succeeded)
		writeMetric(&builder, "whoice_provider_requests_total", "Total provider requests by provider and outcome.", map[string]string{"provider": name, "outcome": "failure"}, stats.Failed)
		writeMetric(&builder, "whoice_provider_requests_total", "Total provider requests by provider and outcome.", map[string]string{"provider": name, "outcome": "skipped"}, stats.Skipped)
		writeMetric(&builder, "whoice_provider_last_elapsed_milliseconds", "Elapsed milliseconds for the most recent provider request.", map[string]string{"provider": name}, stats.LastElapsed)
		writeHistogram(&builder, "whoice_provider_latency_milliseconds", "Provider latency histogram in milliseconds.", map[string]string{"provider": name}, stats.Latency)
	}
	return builder.String()
}

type ProviderTraceView struct {
	Source    string
	Status    string
	ElapsedMs int64
}

func writeMetric(builder *strings.Builder, name string, help string, labels map[string]string, value any) {
	builder.WriteString("# HELP ")
	builder.WriteString(name)
	builder.WriteByte(' ')
	builder.WriteString(help)
	builder.WriteByte('\n')
	builder.WriteString("# TYPE ")
	builder.WriteString(name)
	builder.WriteString(" gauge\n")
	builder.WriteString(name)
	builder.WriteString(formatLabels(labels))
	builder.WriteByte(' ')
	builder.WriteString(fmt.Sprint(value))
	builder.WriteByte('\n')
}

func writeHistogram(builder *strings.Builder, name string, help string, labels map[string]string, histogram HistogramSnapshot) {
	builder.WriteString("# HELP ")
	builder.WriteString(name)
	builder.WriteByte(' ')
	builder.WriteString(help)
	builder.WriteByte('\n')
	builder.WriteString("# TYPE ")
	builder.WriteString(name)
	builder.WriteString(" histogram\n")
	cumulative := uint64(0)
	for _, bucket := range latencyBucketsMs {
		cumulative += histogram.Buckets[formatBucket(bucket)]
		writeMetricLine(builder, name+"_bucket", withLabel(labels, "le", fmt.Sprint(bucket)), cumulative)
	}
	cumulative += histogram.Buckets["+Inf"]
	writeMetricLine(builder, name+"_bucket", withLabel(labels, "le", "+Inf"), cumulative)
	writeMetricLine(builder, name+"_sum", labels, histogram.Sum)
	writeMetricLine(builder, name+"_count", labels, histogram.Count)
}

func writeMetricLine(builder *strings.Builder, name string, labels map[string]string, value any) {
	builder.WriteString(name)
	builder.WriteString(formatLabels(labels))
	builder.WriteByte(' ')
	builder.WriteString(fmt.Sprint(value))
	builder.WriteByte('\n')
}

func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var builder strings.Builder
	builder.WriteByte('{')
	for index, key := range keys {
		if index > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(key)
		builder.WriteString(`="`)
		builder.WriteString(escapeLabelValue(labels[key]))
		builder.WriteByte('"')
	}
	builder.WriteByte('}')
	return builder.String()
}

func escapeLabelValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return value
}

func recordLatency(snapshot HistogramSnapshot, elapsedMs int64) HistogramSnapshot {
	if elapsedMs < 0 {
		elapsedMs = 0
	}
	if snapshot.Buckets == nil {
		snapshot.Buckets = map[string]uint64{}
	}
	bucket := "+Inf"
	for _, limit := range latencyBucketsMs {
		if elapsedMs <= limit {
			bucket = formatBucket(limit)
			break
		}
	}
	snapshot.Buckets[bucket]++
	snapshot.Sum += uint64(elapsedMs)
	snapshot.Count++
	return snapshot
}

func formatBucket(limit int64) string {
	return fmt.Sprint(limit)
}

func withLabel(labels map[string]string, key, value string) map[string]string {
	next := map[string]string{}
	for existingKey, existingValue := range labels {
		next[existingKey] = existingValue
	}
	next[key] = value
	return next
}
