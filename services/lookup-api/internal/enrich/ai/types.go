package ai

import (
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

const (
	defaultPrompt = `You extract domain registration data from RDAP JSON and WHOIS text.
Return strict JSON only. Do not include markdown, commentary, explanation, reasoning, chain-of-thought, or <think> blocks.
Use only facts present in the input. Do not guess.
Be concise. Output only useful non-empty fields.
Decode escaped Unicode sequences in output field values, for example turn \u0130zmir into İzmir. Keep evidence snippets verbatim from the input.
Prefer official registrar fields over reseller, abuse contact, registry, technical contact, billing contact, or privacy-service boilerplate.
If a value is redacted for privacy, omit it unless it is the only useful public registrant signal.
Never put standard registrant fields in extra. State, Province, State/Province, Region, City, Address, Postal Code, Email, Phone, Name, Organization, and Country must use the fixed registrant keys. For example Registrant State/Province belongs in registrant.province, not extra and not registrant.city.
Use ISO-like labels in extra fields only for registry-specific public fields that do not fit the fixed keys, such as IP Address, Server, Hosting Provider, Tax ID, or Organization Type.
Include very short evidence snippets copied from the input only when helpful.
Confidence is 0.0 to 1.0. Use lower confidence for ambiguous labels or conflicting sources.
Output shape:
{
  "registrar": {"name":"","url":"","ianaId":"","country":"","confidence":0.0,"evidence":""},
  "registrant": {"name":"","organization":"","country":"","province":"","city":"","address":"","postalCode":"","email":"","phone":"","confidence":0.0,"evidence":"","extra":[{"label":"","value":"","confidence":0.0,"evidence":""}]}
}`
	promptVersion = "whoice-ai-registration-v2"
)

type Options struct {
	Enabled       bool
	Provider      string
	BaseURL       string
	APIKey        string
	Model         string
	Timeout       time.Duration
	CacheTTL      time.Duration
	MaxInputChars int
	MinConfidence float64
	Temperature   float64
	MaxTokens     int
	MaxAttempts   int
	Prompt        string
	DataDir       string
}

type Analysis struct {
	Registrar  model.RegistrarInfo  `json:"registrar,omitempty"`
	Registrant model.RegistrantInfo `json:"registrant,omitempty"`
}

type ApplyResult struct {
	Trace model.AITrace
}
