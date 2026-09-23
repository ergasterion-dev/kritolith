// Package gemini adapts Google's Gemini generateContent/embedContent
// API to the llm.Provider interface using only net/http.
package gemini

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

const (
	defaultBaseURL = "https://generativelanguage.googleapis.com/v1beta"
	defaultTimeout = 60 * time.Second
)

// Adapter calls the Gemini generateContent and embedContent APIs. It
// is always a cloud provider: IsLocal always reports false.
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
	BaseURL string // defaults to https://generativelanguage.googleapis.com/v1beta
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
		client:  &http.Client{Timeout: timeout},
	}
}

func (a *Adapter) Name() string  { return a.name }
func (a *Adapter) IsLocal() bool { return false }

type part struct {
	Text string `json:"text"`
}

type content struct {
	Role  string `json:"role,omitempty"`
	Parts []part `json:"parts"`
}

type generateRequest struct {
	Contents          []content `json:"contents"`
	SystemInstruction *content  `json:"systemInstruction,omitempty"`
}

type candidate struct {
	Content content `json:"content"`
}

type generateResponse struct {
	Candidates []candidate `json:"candidates"`
}

// Complete calls POST {base_url}/models/{model}:generateContent. A
// system-role message in req.Messages becomes systemInstruction, since
// Gemini has no "system" role inside contents. "assistant" maps to
// Gemini's "model" role.
func (a *Adapter) Complete(ctx context.Context, req llm.CompleteRequest) (llm.CompleteResponse, error) {
	body := generateRequest{}
	var system strings.Builder
	for _, m := range req.Messages {
		switch m.Role {
		case "system":
			if system.Len() > 0 {
				system.WriteString("\n")
			}
			system.WriteString(m.Content)
		case "assistant":
			body.Contents = append(body.Contents, content{Role: "model", Parts: []part{{Text: m.Content}}})
		default:
			body.Contents = append(body.Contents, content{Role: "user", Parts: []part{{Text: m.Content}}})
		}
	}
	if system.Len() > 0 {
		body.SystemInstruction = &content{Parts: []part{{Text: system.String()}}}
	}
	var out generateResponse
	if err := a.post(ctx, fmt.Sprintf("/models/%s:generateContent", a.model), body, &out); err != nil {
		return llm.CompleteResponse{}, err
	}
	if len(out.Candidates) == 0 || len(out.Candidates[0].Content.Parts) == 0 {
		return llm.CompleteResponse{}, fmt.Errorf("gemini: %s: no candidates in response", a.name)
	}
	var text strings.Builder
	for _, p := range out.Candidates[0].Content.Parts {
		text.WriteString(p.Text)
	}
	return llm.CompleteResponse{Text: text.String()}, nil
}

type embedRequest struct {
	Content content `json:"content"`
}

type embedResponse struct {
	Embedding struct {
		Values []float32 `json:"values"`
	} `json:"embedding"`
}

// Embed calls POST {base_url}/models/{model}:embedContent once per
// text: this adapter doesn't use Gemini's separate batch endpoint. It
// stops and returns an error on the first per-text failure, or on ctx
// cancellation between calls.
func (a *Adapter) Embed(ctx context.Context, texts []string) ([][]float32, error) {
	vecs := make([][]float32, len(texts))
	for i, txt := range texts {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("gemini: %s: %w", a.name, err)
		}
		var out embedResponse
		req := embedRequest{Content: content{Parts: []part{{Text: txt}}}}
		if err := a.post(ctx, fmt.Sprintf("/models/%s:embedContent", a.model), req, &out); err != nil {
			return nil, err
		}
		vecs[i] = out.Embedding.Values
	}
	return vecs, nil
}

func (a *Adapter) post(ctx context.Context, path string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("gemini: %s: encode request: %w", a.name, err)
	}
	u := a.baseURL + path + "?key=" + url.QueryEscape(a.apiKey)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("gemini: %s: build request: %w", a.name, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("gemini: %s: %w", a.name, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("gemini: %s: read response: %w", a.name, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gemini: %s: status %d: %s", a.name, resp.StatusCode, truncate(respBody, 200))
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("gemini: %s: decode response: %w", a.name, err)
	}
	return nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
