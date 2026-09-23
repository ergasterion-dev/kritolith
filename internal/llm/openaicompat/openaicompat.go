// Package openaicompat adapts an OpenAI-compatible HTTP API (Ollama,
// llama.cpp, vLLM, LM Studio, OpenAI itself) to the llm.Provider
// interface using only net/http.
package openaicompat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/llm"
)

const defaultTimeout = 60 * time.Second

// Adapter calls an OpenAI-compatible chat completions and embeddings
// API over plain net/http.
type Adapter struct {
	name    string
	baseURL string
	model   string
	apiKey  string
	local   bool
	client  *http.Client
}

// Options configures an Adapter.
type Options struct {
	Name    string
	BaseURL string // e.g. "http://127.0.0.1:11434/v1"; required
	Model   string
	APIKey  string        // may be empty for a local server with no auth
	Timeout time.Duration // defaults to 60s
}

// New returns an Adapter. It computes IsLocal once, from baseURL's
// host, at construction time.
func New(opts Options) (*Adapter, error) {
	u, err := url.Parse(opts.BaseURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("openaicompat: %s: invalid base_url %q", opts.Name, opts.BaseURL)
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	return &Adapter{
		name:    opts.Name,
		baseURL: strings.TrimSuffix(opts.BaseURL, "/"),
		model:   opts.Model,
		apiKey:  opts.APIKey,
		local:   llm.IsLocalHost(u.Host),
		client:  &http.Client{Timeout: timeout},
	}, nil
}

func (a *Adapter) Name() string  { return a.name }
func (a *Adapter) IsLocal() bool { return a.local }

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature,omitempty"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
}

// Complete calls POST {base_url}/chat/completions.
func (a *Adapter) Complete(ctx context.Context, req llm.CompleteRequest) (llm.CompleteResponse, error) {
	body := chatRequest{Model: a.model, Temperature: req.Temperature, MaxTokens: req.MaxTokens}
	for _, m := range req.Messages {
		body.Messages = append(body.Messages, chatMessage{Role: m.Role, Content: m.Content})
	}
	var out chatResponse
	if err := a.post(ctx, "/chat/completions", body, &out); err != nil {
		return llm.CompleteResponse{}, err
	}
	if len(out.Choices) == 0 {
		return llm.CompleteResponse{}, fmt.Errorf("openaicompat: %s: no choices in response", a.name)
	}
	return llm.CompleteResponse{Text: out.Choices[0].Message.Content}, nil
}

type embedRequest struct {
	Model string   `json:"model"`
	Input []string `json:"input"`
}

type embedResponse struct {
	Data []struct {
		Embedding []float32 `json:"embedding"`
		Index     int       `json:"index"`
	} `json:"data"`
}

// Embed calls POST {base_url}/embeddings.
func (a *Adapter) Embed(ctx context.Context, texts []string) ([][]float32, error) {
	var out embedResponse
	if err := a.post(ctx, "/embeddings", embedRequest{Model: a.model, Input: texts}, &out); err != nil {
		return nil, err
	}
	vecs := make([][]float32, len(texts))
	for _, d := range out.Data {
		if d.Index < 0 || d.Index >= len(vecs) {
			continue
		}
		vecs[d.Index] = d.Embedding
	}
	return vecs, nil
}

func (a *Adapter) post(ctx context.Context, path string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("openaicompat: %s: encode request: %w", a.name, err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+path, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("openaicompat: %s: build request: %w", a.name, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if a.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+a.apiKey)
	}
	resp, err := a.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("openaicompat: %s: %w", a.name, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("openaicompat: %s: read response: %w", a.name, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("openaicompat: %s: status %d: %s", a.name, resp.StatusCode, truncate(respBody, 200))
	}
	// Not DisallowUnknownFields: this is the provider's own API
	// envelope, which legitimately carries fields (id, usage, ...)
	// this adapter doesn't model. Strict decoding belongs to
	// llmextract, which validates the LLM's *content*, not this
	// transport layer.
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("openaicompat: %s: decode response: %w", a.name, err)
	}
	return nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
