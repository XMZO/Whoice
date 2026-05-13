package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type client interface {
	analyze(ctx context.Context, prompt, evidence string) (Analysis, error)
	provider() string
	model() string
}

type openAICompatibleClient struct {
	baseURL      string
	apiKey       string
	modelID      string
	providerName string
	temperature  float64
	maxTokens    int
	http         *http.Client
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Stream      bool          `json:"stream"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type,omitempty"`
	} `json:"error,omitempty"`
}

func newOpenAICompatibleClient(opts Options) *openAICompatibleClient {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	return &openAICompatibleClient{
		baseURL:      normalizeBaseURL(opts.Provider, opts.BaseURL),
		apiKey:       opts.APIKey,
		modelID:      opts.Model,
		providerName: firstNonEmpty(strings.TrimSpace(opts.Provider), "openai-compatible"),
		temperature:  clampTemperature(opts.Temperature),
		maxTokens:    opts.MaxTokens,
		http:         &http.Client{Timeout: timeout},
	}
}

func (c *openAICompatibleClient) provider() string {
	return c.providerName
}

func (c *openAICompatibleClient) model() string {
	return c.modelID
}

func (c *openAICompatibleClient) analyze(ctx context.Context, prompt, evidence string) (Analysis, error) {
	if c.baseURL == "" {
		return Analysis{}, errors.New("AI base URL is empty")
	}
	if c.modelID == "" {
		return Analysis{}, errors.New("AI model is empty")
	}
	requestBody := chatRequest{
		Model:       c.modelID,
		Temperature: c.temperature,
		MaxTokens:   c.maxTokens,
		Stream:      false,
		Messages: []chatMessage{
			{Role: "system", Content: prompt},
			{Role: "user", Content: evidence},
		},
	}
	body, err := json.Marshal(requestBody)
	if err != nil {
		return Analysis{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Analysis{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	res, err := c.http.Do(req)
	if err != nil {
		return Analysis{}, err
	}
	defer res.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		return Analysis{}, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return Analysis{}, fmt.Errorf("AI endpoint returned HTTP %d: %s", res.StatusCode, trimForError(string(responseBody)))
	}
	var chat chatResponse
	if err := json.Unmarshal(responseBody, &chat); err != nil {
		return Analysis{}, fmt.Errorf("parse AI response: %w", err)
	}
	if chat.Error != nil && chat.Error.Message != "" {
		return Analysis{}, errors.New(chat.Error.Message)
	}
	if len(chat.Choices) == 0 {
		return Analysis{}, errors.New("AI response has no choices")
	}
	content := chat.Choices[0].Message.Content
	if strings.TrimSpace(content) == "" {
		return Analysis{}, errors.New("AI response is empty")
	}
	return parseAnalysis(content)
}

func parseAnalysis(content string) (Analysis, error) {
	jsonText := extractJSONObject(content)
	if jsonText == "" {
		return Analysis{}, errors.New("AI response did not contain JSON")
	}
	var analysis Analysis
	if err := json.NewDecoder(strings.NewReader(jsonText)).Decode(&analysis); err != nil {
		return Analysis{}, fmt.Errorf("parse AI analysis JSON: %w", err)
	}
	return analysis, nil
}

func extractJSONObject(content string) string {
	content = strings.TrimSpace(content)
	if strings.HasPrefix(content, "```") {
		content = strings.TrimPrefix(content, "```json")
		content = strings.TrimPrefix(content, "```")
		content = strings.TrimSuffix(content, "```")
		content = strings.TrimSpace(content)
	}
	if strings.HasPrefix(content, "{") && strings.HasSuffix(content, "}") {
		return content
	}
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start >= 0 && end > start {
		return content[start : end+1]
	}
	return ""
}

func trimForError(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 400 {
		return value
	}
	return value[:400] + "..."
}

func normalizeBaseURL(provider, baseURL string) string {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if strings.EqualFold(strings.TrimSpace(provider), "ollama") && baseURL != "" && !strings.HasSuffix(baseURL, "/v1") {
		return baseURL + "/v1"
	}
	return baseURL
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func clampTemperature(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 2 {
		return 2
	}
	return value
}
