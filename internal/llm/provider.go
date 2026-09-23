// Package llm defines Kritolith's LLM provider abstraction: a common
// interface, zero-SDK adapters (in sibling packages), and a router
// that gates cloud providers behind per-project opt-in. Kritolith runs
// fully with no provider configured; every caller must degrade
// gracefully, not error, when a chain is empty.
package llm

import "context"

// Message is one turn in a Complete request.
type Message struct {
	Role    string // "system", "user", or "assistant"
	Content string
}

// CompleteRequest is a provider-agnostic completion request.
type CompleteRequest struct {
	Messages    []Message
	MaxTokens   int
	Temperature float64
}

// CompleteResponse is a provider-agnostic completion result.
type CompleteResponse struct {
	Text string
}

// Provider is one LLM backend Kritolith can route a task to.
type Provider interface {
	Complete(ctx context.Context, req CompleteRequest) (CompleteResponse, error)
	Embed(ctx context.Context, texts []string) ([][]float32, error)
	Name() string
	IsLocal() bool
}
