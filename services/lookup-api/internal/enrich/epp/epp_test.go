package epp

import (
	"testing"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

func TestApplyExpandsKnownStatuses(t *testing.T) {
	result := &model.LookupResult{
		Statuses: []model.DomainStatus{
			{Code: "clientTransferProhibited https://icann.org/epp#clientTransferProhibited"},
			{Code: "serverHold"},
			{Code: "pendingRestore"},
			{Code: "renew period"},
		},
	}

	Apply(result)

	tests := []struct {
		index    int
		label    string
		category string
	}{
		{0, "clientTransferProhibited", "client"},
		{1, "serverHold", "server"},
		{2, "pendingRestore", "pending"},
		{3, "renewPeriod", "grace"},
	}
	for _, tt := range tests {
		status := result.Statuses[tt.index]
		if status.Label != tt.label || status.Category != tt.category || status.Description == "" || status.URL == "" {
			t.Fatalf("status[%d] = %#v, want label %q category %q with description/url", tt.index, status, tt.label, tt.category)
		}
	}
}

func TestApplyKeepsUnknownStatusReadable(t *testing.T) {
	result := &model.LookupResult{
		Statuses: []model.DomainStatus{{Code: "customRegistryState"}},
	}

	Apply(result)

	status := result.Statuses[0]
	if status.Label != "customRegistryState" {
		t.Fatalf("label: got %q", status.Label)
	}
	if status.URL != "https://icann.org/epp" {
		t.Fatalf("url: got %q", status.URL)
	}
}
