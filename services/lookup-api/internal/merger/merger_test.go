package merger

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

func TestMergeInitializesCollections(t *testing.T) {
	q := model.NormalizedQuery{
		Input:            "example.com",
		Query:            "example.com",
		UnicodeQuery:     "example.com",
		Type:             model.QueryDomain,
		Suffix:           "com",
		RegisteredDomain: "example.com",
	}
	part := &model.PartialResult{
		Source: model.SourceWHOIS,
		Status: model.StatusRegistered,
		Raw:    model.RawData{WHOIS: "domain: EXAMPLE.COM"},
	}

	result := New().Merge(q, []*model.PartialResult{part})
	if result.Statuses == nil {
		t.Fatal("statuses should be an empty slice, not nil")
	}
	if result.Nameservers == nil {
		t.Fatal("nameservers should be an empty slice, not nil")
	}

	body, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), `"statuses":null`) {
		t.Fatal("statuses should not encode as null")
	}
	if strings.Contains(string(body), `"nameservers":null`) {
		t.Fatal("nameservers should not encode as null")
	}
}

func TestMergeKeepsWHOISWebNoticeUnknown(t *testing.T) {
	q := model.NormalizedQuery{
		Input:            "example.ao",
		Query:            "example.ao",
		UnicodeQuery:     "example.ao",
		Type:             model.QueryDomain,
		Suffix:           "ao",
		RegisteredDomain: "example.ao",
	}
	part := &model.PartialResult{
		Source: model.SourceWHOISWeb,
		Status: model.StatusUnknown,
		Raw:    model.RawData{WHOISWeb: "WHOIS Web fallback notice: Please visit https://www.dns.ao/ao/whois/."},
	}

	result := New().Merge(q, []*model.PartialResult{part})
	if result.Status != model.StatusUnknown {
		t.Fatalf("status: got %q want %q", result.Status, model.StatusUnknown)
	}
	if result.Raw.WHOISWeb == "" {
		t.Fatal("expected WHOIS Web raw evidence to be preserved")
	}
}
