// Package pipeline runs a report through Kritolith's stages and stores
// the result. Later milestones add dedupe and sandbox between
// grounding and composing the verdict.
package pipeline

import (
	"context"
	"fmt"

	"github.com/ergasterion-dev/kritolith/internal/extract/deterministic"
	"github.com/ergasterion-dev/kritolith/internal/extract/llmextract"
	"github.com/ergasterion-dev/kritolith/internal/ground"
	"github.com/ergasterion-dev/kritolith/internal/report"
	"github.com/ergasterion-dev/kritolith/internal/verdict"
)

// Store is the persistence the pipeline needs.
type Store interface {
	SaveReport(ctx context.Context, r report.Report) error
	SaveVerdict(ctx context.Context, v report.Verdict) error
}

// Pipeline processes reports.
type Pipeline struct {
	store    Store
	llmChain llmextract.Chain // nil when no LLM is configured
	grounder ground.Grounder  // nil when no Grounder is configured
}

// New returns a Pipeline that persists to s, with no LLM or Grounder
// configured.
func New(s Store) *Pipeline { return &Pipeline{store: s} }

// WithLLM returns p configured to also try LLM extraction through
// chain. A nil chain (New's default) skips the LLM extraction stage
// entirely: Kritolith must work with no LLM configured.
func (p *Pipeline) WithLLM(chain llmextract.Chain) *Pipeline {
	p.llmChain = chain
	return p
}

// WithGround returns p configured to also ground claims through g. A
// nil grounder (New's default) skips the grounding stage entirely:
// Run behaves exactly as it did before Week 3, for any caller that
// doesn't wire one in.
func (p *Pipeline) WithGround(g ground.Grounder) *Pipeline {
	p.grounder = g
	return p
}

// Run stores the report, extracts claims, grounds them, composes the
// verdict and stores that too. Deterministic extraction always runs;
// LLM extraction runs only when WithLLM configured a chain, and its
// claims never override a deterministic claim with the same kind and
// value. Grounding runs only when WithGround configured a grounder; it
// never fails Run — a grounding failure of any kind degrades to a
// "ref not resolved" verdict, never a pipeline error.
func (p *Pipeline) Run(ctx context.Context, r report.Report) (report.Verdict, error) {
	if err := p.store.SaveReport(ctx, r); err != nil {
		return report.Verdict{}, fmt.Errorf("pipeline: save report: %w", err)
	}
	claims := deterministic.Extract(r.Body)
	var llmUnavailable bool
	if p.llmChain != nil {
		llmClaims := llmextract.Extract(ctx, p.llmChain, r)
		llmUnavailable = len(llmClaims) == 0
		claims = mergeClaims(claims, llmClaims)
	}
	res := verdict.StageResults{Claims: claims, LLMUnavailable: llmUnavailable}
	if p.grounder != nil {
		grounded, resolved, resolvedRef := p.grounder.Ground(ctx, r, claims)
		res.Claims = grounded
		res.GroundingRan = true
		res.RefResolved = resolved
		res.ResolvedRef = resolvedRef
	}
	v := verdict.Compose(r, res)
	if err := p.store.SaveVerdict(ctx, v); err != nil {
		return report.Verdict{}, fmt.Errorf("pipeline: save verdict: %w", err)
	}
	return v, nil
}

// mergeClaims combines deterministic and LLM-sourced claims. A
// deterministic claim always wins over an LLM claim with the same
// (Kind, Value): the LLM claim is dropped, not appended.
func mergeClaims(det, fromLLM []report.Claim) []report.Claim {
	seen := make(map[string]bool, len(det))
	for _, c := range det {
		seen[string(c.Kind)+"\x00"+c.Value] = true
	}
	out := append([]report.Claim(nil), det...)
	for _, c := range fromLLM {
		if seen[string(c.Kind)+"\x00"+c.Value] {
			continue
		}
		out = append(out, c)
	}
	return out
}
