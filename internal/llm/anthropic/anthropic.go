// Package anthropic adapts Anthropic's Messages API to the
// llm.Provider interface using only net/http. It never uses the
// Anthropic SDK.
package anthropic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/llm"
)

const (
	defaultBaseURL = "https://api.anthropic.com"
	apiVersion     = "2023-06-01"
	defaultTimeout = 60 * time.Second
	defaultMaxTok  = 1024
)

// Adapter calls the Anthropic Messages API. It is always a cloud
// provider: IsLocal always reports false.
type Adapter struct {
	name    string
	baseURL string
	model   string
	apiKey  string
	client  *http.Client
}

// Options configures an Adapter.
type Options struct {
	Name    string
	BaseURL string // defaults to https://api.anthropic.com
	Model   string
	APIKey  string
	Timeout time.Duration // defaults to 60s
}

// New returns an Adapter.
func New(opts Options) *Adapter {
	base := opts.BaseURL
	if base == "" {
		base = defaultBaseURL
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	return &Adapter{
		name:    opts.Name,
		baseURL: strings.TrimSuffix(base, "/"),
		model:   opts.Model,
		apiKey:  opts.APIKey,
		client: &http.Client{
			Timeout: timeout,
			// No legitimate Messages API response is ever a redirect;
			// refusing to follow one avoids resending the request
			// (with its x-api-key header) to a server-controlled
			// destination.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (a *Adapter) Name() string  { return a.name }
func (a *Adapter) IsLocal() bool { return false }

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type messagesRequest struct {
	Model       string    `json:"model"`
	MaxTokens   int       `json:"max_tokens"`
	Messages    []message `json:"messages"`
	System      string    `json:"system,omitempty"`
	Temperature float64   `json:"temperature,omitempty"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type messagesResponse struct {
	Content []contentBlock `json:"content"`
}

// Complete calls POST {base_url}/v1/messages. A system-role message in
// req.Messages is lifted into the top-level "system" field, since the
// Messages API doesn't accept "system" inside the messages array.
func (a *Adapter) Complete(ctx context.Context, req llm.CompleteRequest) (llm.CompleteResponse, error) {
	body := messagesRequest{Model: a.model, Temperature: req.Temperature, MaxTokens: req.MaxTokens}
	if body.MaxTokens == 0 {
		body.MaxTokens = defaultMaxTok
	}
	for _, m := range req.Messages {
		if m.Role == "system" {
			body.System = m.Content
			continue
		}
		body.Messages = append(body.Messages, message{Role: m.Role, Content: m.Content})
	}
	var out messagesResponse
	if err := a.post(ctx, "/v1/messages", body, &out); err != nil {
		return llm.CompleteResponse{}, err
	}
	var text strings.Builder
	for _, b := range out.Content {
		if b.Type == "text" {
			text.WriteString(b.Text)
		}
	}
	return llm.CompleteResponse{Text: text.String()}, nil
}

// Embed always fails: Anthropic has no embeddings API. Callers reach
// this only through router misconfiguration; the router treats it as
// an ordinary fallthrough error.
func (a *Adapter) Embed(ctx context.Context, texts []string) ([][]float32, error) {
	return nil, fmt.Errorf("anthropic: %s: embeddings are not supported by this provider", a.name)
}

func (a *Adapter) post(ctx context.Context, path string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("anthropic: %s: encode request: %w", a.name, err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+path, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("anthropic: %s: build request: %w", a.name, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", a.apiKey)
	httpReq.Header.Set("anthropic-version", apiVersion)
	resp, err := a.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("anthropic: %s: %w", a.name, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("anthropic: %s: read response: %w", a.name, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("anthropic: %s: status %d: %s", a.name, resp.StatusCode, truncate(respBody, 200))
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("anthropic: %s: decode response: %w", a.name, err)
	}
	return nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
