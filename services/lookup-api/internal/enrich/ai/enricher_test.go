package ai

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

type fakeClient struct {
	calls    int
	analysis Analysis
	err      error
}

func (f *fakeClient) analyze(context.Context, string, string) (Analysis, error) {
	f.calls++
	return f.analysis, f.err
}

func (f *fakeClient) provider() string { return "fake" }
func (f *fakeClient) model() string    { return "fake-model" }

type sequenceClient struct {
	calls     int
	responses []Analysis
	errs      []error
}

func (s *sequenceClient) analyze(context.Context, string, string) (Analysis, error) {
	index := s.calls
	s.calls++
	if index < len(s.errs) && s.errs[index] != nil {
		return Analysis{}, s.errs[index]
	}
	if index < len(s.responses) {
		return s.responses[index], nil
	}
	return Analysis{}, nil
}

func (s *sequenceClient) provider() string { return "fake" }
func (s *sequenceClient) model() string    { return "fake-model" }

func TestApplyFillsOnlyMissingFields(t *testing.T) {
	confidence := 0.92
	fake := &fakeClient{
		analysis: Analysis{
			Registrar: model.RegistrarInfo{
				Name:       "AI Registrar",
				URL:        "https://registrar.example",
				IANAID:     "9999",
				Confidence: &confidence,
				Evidence:   "Registrar: AI Registrar",
			},
			Registrant: model.RegistrantInfo{
				Organization: "Example Org",
				Country:      "KZ",
				Confidence:   &confidence,
				Evidence:     "Organization: Example Org",
				Extra: []model.RegistrationField{
					{Label: "IP Address", Value: "203.0.113.10", Confidence: &confidence, Evidence: "IP Address: 203.0.113.10"},
				},
			},
		},
	}
	enricher := &Enricher{
		opts: Options{
			Enabled:       true,
			Model:         "fake-model",
			MinConfidence: 0.68,
			MaxInputChars: 4000,
			CacheTTL:      0,
		},
		client: fake,
	}
	result := &model.LookupResult{
		Type: model.QueryDomain,
		Registrar: model.RegistrarInfo{
			Name: "Deterministic Registrar",
		},
		Raw: model.RawData{WHOIS: "Registrar: AI Registrar\nOrganization: Example Org\nIP Address: 203.0.113.10"},
	}

	trace := enricher.Apply(context.Background(), result, false)

	if trace.Status != "ok" {
		t.Fatalf("trace status: %s error=%s", trace.Status, trace.Error)
	}
	if result.Registrar.Name != "Deterministic Registrar" {
		t.Fatalf("deterministic registrar name was overwritten: %q", result.Registrar.Name)
	}
	if result.Registrar.URL != "https://registrar.example" {
		t.Fatalf("registrar url: %q", result.Registrar.URL)
	}
	if result.Registrar.Source != "ai:fake-model" {
		t.Fatalf("registrar source: %q", result.Registrar.Source)
	}
	if result.Registrant.Organization != "Example Org" || result.Registrant.Country != "KZ" {
		t.Fatalf("registrant: %#v", result.Registrant)
	}
	if len(result.Registrant.Extra) != 1 || result.Registrant.Extra[0].Source != "ai:fake-model" {
		t.Fatalf("extra fields: %#v", result.Registrant.Extra)
	}
}

func TestApplySkipsLowConfidence(t *testing.T) {
	confidence := 0.2
	enricher := &Enricher{
		opts: Options{
			Enabled:       true,
			Model:         "fake-model",
			MinConfidence: 0.68,
			MaxInputChars: 4000,
		},
		client: &fakeClient{
			analysis: Analysis{
				Registrant: model.RegistrantInfo{
					Organization: "Maybe Org",
					Confidence:   &confidence,
				},
			},
		},
	}
	result := &model.LookupResult{
		Type: model.QueryDomain,
		Raw:  model.RawData{WHOIS: "Organization: Maybe Org"},
	}

	trace := enricher.Apply(context.Background(), result, false)
	if trace.Status != "ok" {
		t.Fatalf("trace status: %s", trace.Status)
	}
	if result.Registrant.Organization != "" {
		t.Fatalf("low confidence field applied: %#v", result.Registrant)
	}
}

func TestApplyDecodesEscapedUnicodeInAIValues(t *testing.T) {
	confidence := 0.92
	enricher := &Enricher{
		opts: Options{
			Enabled:       true,
			Model:         "fake-model",
			MinConfidence: 0.68,
			MaxInputChars: 4000,
		},
		client: &fakeClient{
			analysis: Analysis{
				Registrant: model.RegistrantInfo{
					Province:   `\u0130zmir`,
					Confidence: &confidence,
					Extra: []model.RegistrationField{
						{Label: "Locality", Value: `\u0130zmir`, Confidence: &confidence},
					},
				},
			},
		},
	}
	result := &model.LookupResult{
		Type: model.QueryDomain,
		Raw:  model.RawData{WHOIS: `Registrant State/Province: \u0130zmir`},
	}

	trace := enricher.Apply(context.Background(), result, true)

	if trace.Status != "ok" {
		t.Fatalf("trace status: %s error=%s", trace.Status, trace.Error)
	}
	if result.Registrant.Province != "İzmir" {
		t.Fatalf("province: got %q", result.Registrant.Province)
	}
	if result.Registrant.City != "" {
		t.Fatalf("duplicate locality should not create city: got %q", result.Registrant.City)
	}
	if len(result.Registrant.Extra) != 0 {
		t.Fatalf("standard locality should be merged, got %#v", result.Registrant.Extra)
	}
}

func TestApplyDecodesEscapedUnicodeAlreadyPresentInResult(t *testing.T) {
	enricher := &Enricher{
		opts: Options{
			Enabled:       true,
			Model:         "fake-model",
			MinConfidence: 0.68,
			MaxInputChars: 4000,
		},
		client: &fakeClient{analysis: Analysis{}},
	}
	result := &model.LookupResult{
		Type:       model.QueryDomain,
		Registrant: model.RegistrantInfo{Province: `\u0130zmir`},
		Raw:        model.RawData{WHOIS: `Registrant State/Province: \u0130zmir`},
	}
	result.Registrant.FieldSources = map[string][]model.RegistrationField{
		"province": {{Label: "province", Value: `\u0130zmir`, Source: "whois"}},
	}

	trace := enricher.Apply(context.Background(), result, true)

	if trace.Status != "ok" {
		t.Fatalf("trace status: %s error=%s", trace.Status, trace.Error)
	}
	if result.Registrant.Province != "İzmir" {
		t.Fatalf("province: got %q", result.Registrant.Province)
	}
	if len(result.Registrant.FieldSources["province"]) != 2 {
		t.Fatalf("province sources: %#v", result.Registrant.FieldSources["province"])
	}
	if result.Registrant.FieldSources["province"][1].Source != "ai:fake-model" {
		t.Fatalf("expected AI decode source, got %#v", result.Registrant.FieldSources["province"])
	}
}

func TestApplyAddsAISourceWhenConfirmingExistingRegistrantField(t *testing.T) {
	confidence := 0.92
	enricher := &Enricher{
		opts: Options{
			Enabled:       true,
			Model:         "fake-model",
			MinConfidence: 0.68,
			MaxInputChars: 4000,
		},
		client: &fakeClient{
			analysis: Analysis{
				Registrant: model.RegistrantInfo{
					Province:   "İzmir",
					Confidence: &confidence,
					Evidence:   `Registrant State/Province: \u0130zmir`,
				},
			},
		},
	}
	result := &model.LookupResult{
		Type:       model.QueryDomain,
		Registrant: model.RegistrantInfo{Province: "İzmir"},
		Raw:        model.RawData{WHOIS: `Registrant State/Province: \u0130zmir`},
	}
	result.Registrant.FieldSources = map[string][]model.RegistrationField{
		"province": {{Label: "province", Value: `\u0130zmir`, Source: "whois"}},
	}

	trace := enricher.Apply(context.Background(), result, true)

	if trace.Status != "ok" {
		t.Fatalf("trace status: %s error=%s", trace.Status, trace.Error)
	}
	if result.Registrant.Province != "İzmir" {
		t.Fatalf("province: got %q", result.Registrant.Province)
	}
	sources := result.Registrant.FieldSources["province"]
	if len(sources) != 2 {
		t.Fatalf("province sources: %#v", sources)
	}
	if sources[0].Source != "whois" || sources[1].Source != "ai:fake-model" {
		t.Fatalf("expected original and AI sources, got %#v", sources)
	}
	if len(result.Registrant.Extra) != 0 {
		t.Fatalf("existing fixed field should not become extra: %#v", result.Registrant.Extra)
	}
}

func TestApplyMergesStandardExtraFieldsIntoRegistrantFields(t *testing.T) {
	confidence := 0.92
	enricher := &Enricher{
		opts: Options{
			Enabled:       true,
			Model:         "fake-model",
			MinConfidence: 0.68,
			MaxInputChars: 4000,
		},
		client: &fakeClient{
			analysis: Analysis{
				Registrant: model.RegistrantInfo{
					Confidence: &confidence,
					Extra: []model.RegistrationField{
						{Label: "State/Province", Value: `\u0130zmir`, Confidence: &confidence},
					},
				},
			},
		},
	}
	result := &model.LookupResult{
		Type: model.QueryDomain,
		Raw:  model.RawData{WHOIS: `Registrant State/Province: \u0130zmir`},
	}

	trace := enricher.Apply(context.Background(), result, true)

	if trace.Status != "ok" {
		t.Fatalf("trace status: %s error=%s", trace.Status, trace.Error)
	}
	if result.Registrant.Province != "İzmir" {
		t.Fatalf("province: got %q", result.Registrant.Province)
	}
	if len(result.Registrant.Extra) != 0 {
		t.Fatalf("standard extra should be merged, got %#v", result.Registrant.Extra)
	}
}

func TestApplyDropsExtraWhenValueDuplicatesFixedField(t *testing.T) {
	confidence := 0.92
	enricher := &Enricher{
		opts: Options{
			Enabled:       true,
			Model:         "fake-model",
			MinConfidence: 0.68,
			MaxInputChars: 4000,
		},
		client: &fakeClient{
			analysis: Analysis{
				Registrant: model.RegistrantInfo{
					Confidence: &confidence,
					Extra: []model.RegistrationField{
						{Label: "City", Value: `\u0130zmir`, Confidence: &confidence},
					},
				},
			},
		},
	}
	result := &model.LookupResult{
		Type:       model.QueryDomain,
		Registrant: model.RegistrantInfo{Province: `\u0130zmir`},
		Raw:        model.RawData{WHOIS: `Registrant State/Province: \u0130zmir`},
	}

	trace := enricher.Apply(context.Background(), result, true)

	if trace.Status != "ok" {
		t.Fatalf("trace status: %s error=%s", trace.Status, trace.Error)
	}
	if result.Registrant.Province != "İzmir" {
		t.Fatalf("province: got %q", result.Registrant.Province)
	}
	if result.Registrant.City != "" {
		t.Fatalf("duplicate city should not be applied: %q", result.Registrant.City)
	}
	if len(result.Registrant.Extra) != 0 {
		t.Fatalf("duplicate extra should be dropped, got %#v", result.Registrant.Extra)
	}
}

func TestApplyUsesCache(t *testing.T) {
	confidence := 0.9
	fake := &fakeClient{
		analysis: Analysis{
			Registrar: model.RegistrarInfo{
				URL:        "https://cached.example",
				Confidence: &confidence,
			},
		},
	}
	enricher := &Enricher{
		opts: Options{
			Enabled:       true,
			Model:         "fake-model",
			MinConfidence: 0.68,
			MaxInputChars: 4000,
			CacheTTL:      time.Hour,
			DataDir:       t.TempDir(),
		},
		client: fake,
	}
	enricher.cache = newCache(enricher.opts.DataDir)
	raw := model.RawData{WHOIS: "Registrar URL: https://cached.example"}

	first := &model.LookupResult{Type: model.QueryDomain, Raw: raw}
	second := &model.LookupResult{Type: model.QueryDomain, Raw: raw}
	trace1 := enricher.Apply(context.Background(), first, false)
	trace2 := enricher.Apply(context.Background(), second, false)

	if trace1.Cached {
		t.Fatal("first call should not be cached")
	}
	if !trace2.Cached {
		t.Fatal("second call should be cached")
	}
	if fake.calls != 1 {
		t.Fatalf("AI client calls: %d", fake.calls)
	}
}

func TestApplyRetriesAIAnalysisFailures(t *testing.T) {
	confidence := 0.9
	client := &sequenceClient{
		errs: []error{
			errors.New("AI response did not contain JSON"),
			errors.New("parse AI analysis JSON: invalid character"),
			nil,
		},
		responses: []Analysis{
			{},
			{},
			{
				Registrant: model.RegistrantInfo{
					Name:       "Retry Owner",
					Confidence: &confidence,
				},
			},
		},
	}
	enricher := &Enricher{
		opts: Options{
			Enabled:       true,
			Model:         "fake-model",
			MinConfidence: 0.68,
			MaxInputChars: 4000,
			MaxAttempts:   3,
		},
		client: client,
	}
	result := &model.LookupResult{
		Type: model.QueryDomain,
		Raw:  model.RawData{WHOIS: "Registrant: Retry Owner"},
	}

	trace := enricher.Apply(context.Background(), result, true)

	if trace.Status != "ok" {
		t.Fatalf("trace status: %s error=%s", trace.Status, trace.Error)
	}
	if trace.Attempts != 3 || client.calls != 3 {
		t.Fatalf("attempts: trace=%d calls=%d", trace.Attempts, client.calls)
	}
	if result.Registrant.Name != "Retry Owner" {
		t.Fatalf("registrant name: %q", result.Registrant.Name)
	}
}

func TestApplyStopsAfterConfiguredAIAttempts(t *testing.T) {
	client := &sequenceClient{
		errs: []error{
			errors.New("bad json 1"),
			errors.New("bad json 2"),
			errors.New("bad json 3"),
		},
	}
	enricher := &Enricher{
		opts: Options{
			Enabled:       true,
			Model:         "fake-model",
			MinConfidence: 0.68,
			MaxInputChars: 4000,
			MaxAttempts:   2,
		},
		client: client,
	}
	result := &model.LookupResult{
		Type: model.QueryDomain,
		Raw:  model.RawData{WHOIS: "Registrant: Failed Owner"},
	}

	trace := enricher.Apply(context.Background(), result, true)

	if trace.Status != "error" {
		t.Fatalf("trace status: %s", trace.Status)
	}
	if trace.Attempts != 2 || client.calls != 2 {
		t.Fatalf("attempts: trace=%d calls=%d", trace.Attempts, client.calls)
	}
	if trace.Error != "bad json 2" {
		t.Fatalf("trace error: %q", trace.Error)
	}
}

func TestApplyForceRunsWhenNotNeeded(t *testing.T) {
	confidence := 0.9
	fake := &fakeClient{
		analysis: Analysis{
			Registrant: model.RegistrantInfo{
				Extra: []model.RegistrationField{
					{Label: "Registry Note", Value: "AI checked", Confidence: &confidence},
				},
			},
		},
	}
	enricher := &Enricher{
		opts: Options{
			Enabled:       true,
			Model:         "fake-model",
			MinConfidence: 0.68,
			MaxInputChars: 4000,
		},
		client: fake,
	}
	result := &model.LookupResult{
		Type: model.QueryDomain,
		Registrar: model.RegistrarInfo{
			Name:   "Parsed Registrar",
			URL:    "https://registrar.example",
			IANAID: "9999",
		},
		Registrant: model.RegistrantInfo{Name: "Parsed Name"},
		Raw:        model.RawData{WHOIS: "Registrar: Parsed Registrar\nRegistrant Name: Parsed Name"},
	}

	trace := enricher.Apply(context.Background(), result, true)
	if trace.Status != "ok" {
		t.Fatalf("trace status: %s", trace.Status)
	}
	if fake.calls != 1 {
		t.Fatalf("AI client calls: %d", fake.calls)
	}
}

func TestParseAnalysisExtractsJSON(t *testing.T) {
	analysis, err := parseAnalysis("```json\n{\"registrar\":{\"name\":\"Example\",\"confidence\":0.8}}\n```")
	if err != nil {
		t.Fatal(err)
	}
	if analysis.Registrar.Name != "Example" {
		t.Fatalf("registrar: %#v", analysis.Registrar)
	}
}
