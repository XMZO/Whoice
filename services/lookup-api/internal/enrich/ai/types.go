package ai

import (
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/config"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

const (
	defaultPrompt = config.DefaultAIPrompt
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
