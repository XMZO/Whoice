package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/config"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

type Enricher struct {
	opts   Options
	client client
	cache  *cache
}

func New(cfg config.Config) *Enricher {
	opts := Options{
		Enabled:       cfg.AIEnabled,
		Provider:      strings.ToLower(strings.TrimSpace(cfg.AIProvider)),
		BaseURL:       cfg.AIBaseURL,
		APIKey:        cfg.AIAPIKey,
		Model:         cfg.AIModel,
		Timeout:       cfg.AITimeout,
		CacheTTL:      cfg.AICacheTTL,
		MaxInputChars: cfg.AIMaxInputChars,
		MinConfidence: cfg.AIMinConfidence,
		Temperature:   cfg.AITemperature,
		MaxTokens:     cfg.AIMaxOutputTokens,
		MaxAttempts:   cfg.AIMaxAttempts,
		Prompt:        cfg.AIPrompt,
		DataDir:       cfg.DataDir,
	}
	enricher := &Enricher{opts: opts}
	if !opts.Enabled {
		return enricher
	}
	enricher.client = newOpenAICompatibleClient(opts)
	enricher.cache = newCache(opts.DataDir)
	return enricher
}

func (e *Enricher) Enabled() bool {
	return e != nil && e.opts.Enabled
}

func (e *Enricher) Apply(ctx context.Context, result *model.LookupResult, force bool) model.AITrace {
	trace := model.AITrace{
		Provider: e.provider(),
		Model:    e.model(),
		Status:   "skipped",
	}
	if e == nil || !e.opts.Enabled {
		return trace
	}
	if result == nil || result.Type != model.QueryDomain {
		return trace
	}
	if !force && !needsAI(result) {
		trace.Status = "not_needed"
		return trace
	}
	evidence := buildEvidence(result, e.opts.MaxInputChars)
	if strings.TrimSpace(evidence) == "" {
		trace.Status = "skipped"
		trace.Error = "no raw evidence"
		return trace
	}
	if e.client == nil {
		trace.Status = "error"
		trace.Error = "AI client is not configured"
		return trace
	}

	key := cacheKey(e.opts, evidence)
	start := time.Now()
	analysis, cached := e.cache.get(key)
	if !cached {
		timeout := e.opts.Timeout
		if timeout <= 0 {
			timeout = 8 * time.Second
		}
		var err error
		attempts := clampAttempts(e.opts.MaxAttempts)
		trace.Attempts = attempts
		for attempt := 1; attempt <= attempts; attempt++ {
			aiCtx, cancel := context.WithTimeout(ctx, timeout)
			analysis, err = e.client.analyze(aiCtx, prompt(e.opts), evidence)
			cancel()
			if err == nil {
				trace.Attempts = attempt
				break
			}
			if ctx.Err() != nil {
				break
			}
		}
		if err != nil {
			trace.Status = "error"
			trace.Error = err.Error()
			trace.ElapsedMs = time.Since(start).Milliseconds()
			return trace
		}
		e.cache.set(key, analysis, e.opts.CacheTTL)
	}

	applied := applyAnalysis(result, analysis, e.sourceLabel(), e.opts.MinConfidence)
	trace.Status = "ok"
	trace.Cached = cached
	if cached {
		trace.Attempts = 0
	}
	trace.ElapsedMs = time.Since(start).Milliseconds()
	trace.Applied = applied
	return trace
}

func clampAttempts(value int) int {
	if value <= 0 {
		return 3
	}
	if value > 3 {
		return 3
	}
	return value
}

func (e *Enricher) provider() string {
	if e == nil || strings.TrimSpace(e.opts.Provider) == "" {
		return "openai-compatible"
	}
	return e.opts.Provider
}

func (e *Enricher) model() string {
	if e == nil {
		return ""
	}
	return e.opts.Model
}

func (e *Enricher) sourceLabel() string {
	modelName := strings.TrimSpace(e.model())
	if modelName == "" {
		return "ai"
	}
	return "ai:" + modelName
}

func prompt(opts Options) string {
	if strings.TrimSpace(opts.Prompt) != "" {
		return opts.Prompt
	}
	return defaultPrompt
}

func needsAI(result *model.LookupResult) bool {
	if result.Registrar.Name == "" || result.Registrar.URL == "" || result.Registrar.IANAID == "" {
		return true
	}
	return !hasRegistrant(result.Registrant)
}

func hasRegistrant(info model.RegistrantInfo) bool {
	return info.Name != "" ||
		info.Organization != "" ||
		info.Country != "" ||
		info.Province != "" ||
		info.City != "" ||
		info.Address != "" ||
		info.PostalCode != "" ||
		info.Email != "" ||
		info.Phone != "" ||
		len(info.Extra) > 0
}

func buildEvidence(result *model.LookupResult, maxChars int) string {
	if maxChars <= 0 {
		maxChars = 16000
	}
	sections := []struct {
		title string
		body  string
	}{
		{title: "RDAP JSON", body: result.Raw.RDAP},
		{title: "WHOIS", body: result.Raw.WHOIS},
		{title: "WHOIS Web", body: result.Raw.WHOISWeb},
	}
	var builder strings.Builder
	for _, section := range sections {
		body := strings.TrimSpace(section.body)
		if body == "" {
			continue
		}
		remaining := maxChars - builder.Len()
		if remaining <= 0 {
			break
		}
		prefix := "\n\n[" + section.title + "]\n"
		if builder.Len() == 0 {
			prefix = "[" + section.title + "]\n"
		}
		if len(prefix) >= remaining {
			break
		}
		builder.WriteString(prefix)
		remaining = maxChars - builder.Len()
		if len(body) > remaining {
			body = body[:remaining]
		}
		builder.WriteString(body)
	}
	return builder.String()
}

func cacheKey(opts Options, evidence string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		promptVersion,
		strings.TrimSpace(opts.Provider),
		strings.TrimSpace(opts.BaseURL),
		strings.TrimSpace(opts.Model),
		prompt(opts),
		evidence,
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}

func applyAnalysis(result *model.LookupResult, analysis Analysis, source string, minConfidence float64) []string {
	if minConfidence <= 0 || minConfidence > 1 {
		minConfidence = 0.68
	}
	normalizeExistingAIVisibleFields(result, source)
	var applied []string
	if okConfidence(analysis.Registrar.Confidence, minConfidence) {
		if setString(&result.Registrar.Name, analysis.Registrar.Name) {
			applied = append(applied, "registrar.name")
		}
		if setString(&result.Registrar.URL, analysis.Registrar.URL) {
			applied = append(applied, "registrar.url")
		}
		if setString(&result.Registrar.IANAID, analysis.Registrar.IANAID) {
			applied = append(applied, "registrar.ianaId")
		}
		if setString(&result.Registrar.Country, analysis.Registrar.Country) {
			applied = append(applied, "registrar.country")
		}
		if len(applied) > 0 && result.Registrar.Source == "" {
			result.Registrar.Source = source
			result.Registrar.Confidence = clampConfidence(analysis.Registrar.Confidence)
			result.Registrar.Evidence = cleanSnippet(analysis.Registrar.Evidence)
		}
	}
	if okConfidence(analysis.Registrant.Confidence, minConfidence) {
		before := len(applied)
		filledRegistrant := false
		if appliedField, filled := applyRegistrantAIField(&result.Registrant, "name", &result.Registrant.Name, analysis.Registrant.Name, source, analysis.Registrant.Confidence, analysis.Registrant.Evidence); appliedField {
			applied = append(applied, "registrant.name")
			filledRegistrant = filledRegistrant || filled
		}
		if appliedField, filled := applyRegistrantAIField(&result.Registrant, "organization", &result.Registrant.Organization, analysis.Registrant.Organization, source, analysis.Registrant.Confidence, analysis.Registrant.Evidence); appliedField {
			applied = append(applied, "registrant.organization")
			filledRegistrant = filledRegistrant || filled
		}
		if appliedField, filled := applyRegistrantAIField(&result.Registrant, "country", &result.Registrant.Country, analysis.Registrant.Country, source, analysis.Registrant.Confidence, analysis.Registrant.Evidence); appliedField {
			applied = append(applied, "registrant.country")
			filledRegistrant = filledRegistrant || filled
		}
		if appliedField, filled := applyRegistrantAIField(&result.Registrant, "province", &result.Registrant.Province, analysis.Registrant.Province, source, analysis.Registrant.Confidence, analysis.Registrant.Evidence); appliedField {
			applied = append(applied, "registrant.province")
			filledRegistrant = filledRegistrant || filled
		}
		if appliedField, filled := applyRegistrantAIField(&result.Registrant, "city", &result.Registrant.City, analysis.Registrant.City, source, analysis.Registrant.Confidence, analysis.Registrant.Evidence); appliedField {
			applied = append(applied, "registrant.city")
			filledRegistrant = filledRegistrant || filled
		}
		if appliedField, filled := applyRegistrantAIField(&result.Registrant, "address", &result.Registrant.Address, analysis.Registrant.Address, source, analysis.Registrant.Confidence, analysis.Registrant.Evidence); appliedField {
			applied = append(applied, "registrant.address")
			filledRegistrant = filledRegistrant || filled
		}
		if appliedField, filled := applyRegistrantAIField(&result.Registrant, "postalCode", &result.Registrant.PostalCode, analysis.Registrant.PostalCode, source, analysis.Registrant.Confidence, analysis.Registrant.Evidence); appliedField {
			applied = append(applied, "registrant.postalCode")
			filledRegistrant = filledRegistrant || filled
		}
		if appliedField, filled := applyRegistrantAIField(&result.Registrant, "email", &result.Registrant.Email, analysis.Registrant.Email, source, analysis.Registrant.Confidence, analysis.Registrant.Evidence); appliedField {
			applied = append(applied, "registrant.email")
			filledRegistrant = filledRegistrant || filled
		}
		if appliedField, filled := applyRegistrantAIField(&result.Registrant, "phone", &result.Registrant.Phone, analysis.Registrant.Phone, source, analysis.Registrant.Confidence, analysis.Registrant.Evidence); appliedField {
			applied = append(applied, "registrant.phone")
			filledRegistrant = filledRegistrant || filled
		}
		if len(applied) > before && filledRegistrant && result.Registrant.Source == "" {
			result.Registrant.Source = source
			result.Registrant.Confidence = clampConfidence(analysis.Registrant.Confidence)
			result.Registrant.Evidence = cleanSnippet(analysis.Registrant.Evidence)
		}
	}
	for _, field := range analysis.Registrant.Extra {
		if !okConfidence(field.Confidence, minConfidence) {
			continue
		}
		field.Label = strings.TrimSpace(field.Label)
		field.Value = normalizeAIValue(field.Value)
		if field.Label == "" || field.Value == "" {
			continue
		}
		if duplicatesFixedRegistrantValue(result.Registrant, field.Value) || hasExtra(result.Registrant.Extra, field) {
			continue
		}
		if mergeRegistrantExtraIntoFixedFields(result, field, source, minConfidence) {
			applied = append(applied, fmt.Sprintf("registrant.%s", canonicalExtraField(field.Label)))
			continue
		}
		field.Source = source
		field.Confidence = clampConfidence(field.Confidence)
		field.Evidence = cleanSnippet(field.Evidence)
		result.Registrant.Extra = append(result.Registrant.Extra, field)
		applied = append(applied, fmt.Sprintf("registrant.extra.%s", field.Label))
	}
	return applied
}

func setString(target *string, value string) bool {
	value = normalizeAIValue(value)
	if *target != "" || value == "" {
		return false
	}
	*target = value
	return true
}

func applyRegistrantAIField(registrant *model.RegistrantInfo, key string, target *string, value, source string, confidence *float64, evidence string) (bool, bool) {
	if registrant == nil || target == nil {
		return false, false
	}
	value = normalizeAIValue(value)
	if value == "" {
		return false, false
	}
	current := strings.TrimSpace(*target)
	if current == "" {
		*target = value
		addRegistrantFieldSource(registrant, key, value, source, confidence, evidence)
		return true, true
	}
	normalizedCurrent := normalizeAIValue(current)
	if normalizedCurrent == value {
		if normalizedCurrent != current {
			*target = normalizedCurrent
		}
		addRegistrantFieldSource(registrant, key, value, source, confidence, evidence)
		return true, false
	}
	return false, false
}

func okConfidence(value *float64, min float64) bool {
	if value == nil {
		return true
	}
	return *value >= min
}

func clampConfidence(value *float64) *float64 {
	if value == nil {
		return nil
	}
	clamped := *value
	if clamped < 0 {
		clamped = 0
	}
	if clamped > 1 {
		clamped = 1
	}
	return &clamped
}

func hasExtra(values []model.RegistrationField, candidate model.RegistrationField) bool {
	key := extraKey(candidate)
	for _, value := range values {
		if extraKey(value) == key {
			return true
		}
	}
	return false
}

func extraKey(value model.RegistrationField) string {
	return strings.ToLower(strings.TrimSpace(value.Label)) + "\x00" + strings.ToLower(strings.TrimSpace(value.Value))
}

func cleanSnippet(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 240 {
		return value[:240]
	}
	return value
}

func normalizeAIValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || !strings.Contains(value, `\u`) {
		return value
	}
	decoded, err := strconv.Unquote(`"` + strings.ReplaceAll(value, `"`, `\"`) + `"`)
	if err != nil {
		return value
	}
	return strings.TrimSpace(decoded)
}

func normalizeExistingAIVisibleFields(result *model.LookupResult, source string) {
	if result == nil {
		return
	}
	normalizeExistingString(&result.Registrar.Name)
	normalizeExistingString(&result.Registrar.URL)
	normalizeExistingString(&result.Registrar.IANAID)
	normalizeExistingString(&result.Registrar.Country)
	normalizeExistingRegistrantString(&result.Registrant, "name", &result.Registrant.Name, source)
	normalizeExistingRegistrantString(&result.Registrant, "organization", &result.Registrant.Organization, source)
	normalizeExistingRegistrantString(&result.Registrant, "country", &result.Registrant.Country, source)
	normalizeExistingRegistrantString(&result.Registrant, "province", &result.Registrant.Province, source)
	normalizeExistingRegistrantString(&result.Registrant, "city", &result.Registrant.City, source)
	normalizeExistingRegistrantString(&result.Registrant, "address", &result.Registrant.Address, source)
	normalizeExistingRegistrantString(&result.Registrant, "postalCode", &result.Registrant.PostalCode, source)
	normalizeExistingRegistrantString(&result.Registrant, "email", &result.Registrant.Email, source)
	normalizeExistingRegistrantString(&result.Registrant, "phone", &result.Registrant.Phone, source)
	for index := range result.Registrant.Extra {
		normalizeExistingString(&result.Registrant.Extra[index].Value)
	}
}

func normalizeExistingRegistrantString(registrant *model.RegistrantInfo, key string, value *string, source string) {
	if value == nil || *value == "" {
		return
	}
	previous := *value
	normalized := normalizeAIValue(previous)
	if normalized == "" || normalized == previous {
		return
	}
	*value = normalized
	addRegistrantFieldSource(registrant, key, normalized, source, nil, previous)
}

func normalizeExistingString(value *string) {
	if value == nil || *value == "" {
		return
	}
	*value = normalizeAIValue(*value)
}

func addRegistrantFieldSource(registrant *model.RegistrantInfo, key, value, source string, confidence *float64, evidence string) {
	if registrant == nil {
		return
	}
	key = strings.TrimSpace(key)
	value = normalizeAIValue(value)
	if key == "" || value == "" {
		return
	}
	if registrant.FieldSources == nil {
		registrant.FieldSources = map[string][]model.RegistrationField{}
	}
	field := model.RegistrationField{
		Label:      key,
		Value:      value,
		Source:     source,
		Confidence: clampConfidence(confidence),
		Evidence:   cleanSnippet(evidence),
	}
	fieldKey := registrantFieldSourceKey(field)
	for _, existing := range registrant.FieldSources[key] {
		if registrantFieldSourceKey(existing) == fieldKey {
			return
		}
	}
	registrant.FieldSources[key] = append(registrant.FieldSources[key], field)
}

func registrantFieldSourceKey(value model.RegistrationField) string {
	return strings.ToLower(strings.TrimSpace(value.Label)) + "\x00" +
		strings.ToLower(strings.TrimSpace(value.Value)) + "\x00" +
		strings.ToLower(strings.TrimSpace(value.Source))
}

func mergeRegistrantExtraIntoFixedFields(result *model.LookupResult, field model.RegistrationField, source string, minConfidence float64) bool {
	if result == nil {
		return false
	}
	target := registrantFieldTarget(&result.Registrant, field.Label)
	if target == nil {
		return false
	}
	previous := strings.TrimSpace(*target)
	if previous == "" {
		if setString(target, field.Value) {
			markRegistrantAI(&result.Registrant, source, field.Confidence, field.Evidence)
			addRegistrantFieldSource(&result.Registrant, canonicalExtraField(field.Label), field.Value, source, field.Confidence, field.Evidence)
			return true
		}
		return false
	}
	normalized := normalizeAIValue(previous)
	if normalized == previous {
		return false
	}
	*target = normalized
	markRegistrantAI(&result.Registrant, source, field.Confidence, field.Evidence)
	addRegistrantFieldSource(&result.Registrant, canonicalExtraField(field.Label), normalized, source, field.Confidence, field.Evidence)
	return true
}

func registrantFieldTarget(registrant *model.RegistrantInfo, label string) *string {
	if registrant == nil {
		return nil
	}
	switch canonicalExtraField(label) {
	case "name":
		return &registrant.Name
	case "organization":
		return &registrant.Organization
	case "country":
		return &registrant.Country
	case "province":
		return &registrant.Province
	case "city":
		return &registrant.City
	case "address":
		return &registrant.Address
	case "postalCode":
		return &registrant.PostalCode
	case "email":
		return &registrant.Email
	case "phone":
		return &registrant.Phone
	default:
		return nil
	}
}

func canonicalExtraField(label string) string {
	normalized := strings.ToLower(strings.TrimSpace(label))
	normalized = strings.NewReplacer("_", " ", "-", " ", "/", " ").Replace(normalized)
	normalized = strings.Join(strings.Fields(normalized), " ")
	switch normalized {
	case "name", "registrant", "registrant name", "owner", "owner name":
		return "name"
	case "organization", "organisation", "org", "registrant organization", "registrant organisation", "owner organization", "owner organisation":
		return "organization"
	case "country", "registrant country", "owner country":
		return "country"
	case "province", "state", "region", "state province", "province state", "registrant state", "registrant province", "registrant state province", "owner state", "owner province":
		return "province"
	case "city", "locality", "registrant city", "owner city":
		return "city"
	case "address", "street", "registrant address", "registrant street", "owner address", "owner street":
		return "address"
	case "postal code", "postalcode", "zip", "zip code", "registrant postal code", "registrant zip", "owner postal code":
		return "postalCode"
	case "email", "e mail", "registrant email", "registrant contact email", "owner email":
		return "email"
	case "phone", "telephone", "tel", "registrant phone", "owner phone":
		return "phone"
	default:
		return ""
	}
}

func duplicatesFixedRegistrantValue(registrant model.RegistrantInfo, value string) bool {
	value = normalizeAIValue(value)
	if value == "" {
		return false
	}
	for _, existing := range []string{
		registrant.Name,
		registrant.Organization,
		registrant.Country,
		registrant.Province,
		registrant.City,
		registrant.Address,
		registrant.PostalCode,
		registrant.Email,
		registrant.Phone,
	} {
		if strings.EqualFold(normalizeAIValue(existing), value) {
			return true
		}
	}
	return false
}

func markRegistrantAI(registrant *model.RegistrantInfo, source string, confidence *float64, evidence string) {
	if registrant == nil || registrant.Source != "" {
		return
	}
	registrant.Source = source
	registrant.Confidence = clampConfidence(confidence)
	registrant.Evidence = cleanSnippet(evidence)
}
