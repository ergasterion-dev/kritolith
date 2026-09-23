// Package llmextract turns an LLM completion into report.Claims,
// validating every field before trusting any of it. Nothing here
// changes a verdict outcome: everything it produces is re-verified by
// grounding later.
package llmextract

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ergasterion-dev/kritolith/internal/llm"
	"github.com/ergasterion-dev/kritolith/internal/report"
)

const maxClaims = 50

const promptTemplate = `You are extracting checkable claims from a security vulnerability report. Read the report body below and list every concrete claim it makes: file paths, function or method names, line numbers, version strings, and the vulnerability class if stated.

Respond with ONLY a JSON object of this exact shape, no other text:
{"claims": [{"kind": "file|function|line|version|vuln_class", "value": "the claimed file, function, line (as file.go:123), version, or class", "evidence": "the sentence or phrase this came from"}]}

If the report makes no checkable claims, respond with {"claims": []}.

Report body:
%s`

type rawClaim struct {
	Kind     string `json:"kind"`
	Value    string `json:"value"`
	Evidence string `json:"evidence"`
}

type rawResponse struct {
	Claims []rawClaim `json:"claims"`
}

var validKinds = map[string]report.ClaimKind{
	"file":       report.ClaimFile,
	"function":   report.ClaimFunction,
	"line":       report.ClaimLine,
	"version":    report.ClaimVersion,
	"vuln_class": report.ClaimVulnClass,
}

// Chain is the subset of *llm.Router that Extract needs. It's an
// interface so tests can supply a fixed provider list without a real
// Router.
type Chain interface {
	Chain(task, reportID, repo string) []llm.Provider
}

// Extract asks each provider in the router's "extract" chain, in
// order, to find claims in r.Body, using the first provider whose
// response is valid JSON matching the schema. A provider that errors,
// times out, or returns invalid JSON is skipped, not fatal: if every
// provider fails, Extract returns no claims and no error, since
// deterministic extraction already ran and the caller must not treat
// this as a pipeline failure.
func Extract(ctx context.Context, chain Chain, r report.Report) []report.Claim {
	for _, p := range chain.Chain("extract", r.ID, r.Repo) {
		claims, err := extractFrom(ctx, p, r.Body)
		if err != nil {
			continue
		}
		return claims
	}
	return nil
}

func extractFrom(ctx context.Context, p llm.Provider, body string) ([]report.Claim, error) {
	resp, err := p.Complete(ctx, llm.CompleteRequest{
		Messages: []llm.Message{
			{Role: "user", Content: fmt.Sprintf(promptTemplate, body)},
		},
		MaxTokens: 2048,
	})
	if err != nil {
		return nil, fmt.Errorf("llmextract: %s: %w", p.Name(), err)
	}
	var raw rawResponse
	dec := json.NewDecoder(strings.NewReader(extractJSONObject(resp.Text)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("llmextract: %s: invalid schema: %w", p.Name(), err)
	}
	source := "llm:" + p.Name()
	claims := make([]report.Claim, 0, len(raw.Claims))
	for _, rc := range raw.Claims {
		if len(claims) >= maxClaims {
			break
		}
		kind, ok := validKinds[rc.Kind]
		if !ok {
			continue
		}
		value := strings.TrimSpace(rc.Value)
		if value == "" || len(value) > 500 {
			continue
		}
		claims = append(claims, report.Claim{
			Kind:     kind,
			Value:    report.Printable(value),
			Source:   source,
			Verified: report.TriUnknown,
			Evidence: report.Printable(truncate(strings.TrimSpace(rc.Evidence), 300)),
		})
	}
	return claims, nil
}

// extractJSONObject trims any leading/trailing prose a chat model adds
// around the JSON object it was asked for, by slicing from the first
// '{' to the last '}'. If no braces are found, the input is returned
// unchanged and decoding will fail cleanly.
func extractJSONObject(s string) string {
	start := strings.IndexByte(s, '{')
	end := strings.LastIndexByte(s, '}')
	if start < 0 || end < start {
		return s
	}
	return s[start : end+1]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
