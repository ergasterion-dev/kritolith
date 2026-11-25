// Package pipeline runs a report through Kritolith's stages and stores
// the result: extract, ground, dedupe, sandbox, then compose and sign
// the verdict.
package pipeline

import (
	"context"
	"fmt"

	"github.com/ergasterion-dev/kritolith/internal/dedupe"
	"github.com/ergasterion-dev/kritolith/internal/extract/deterministic"
	"github.com/ergasterion-dev/kritolith/internal/extract/llmextract"
	"github.com/ergasterion-dev/kritolith/internal/ground"
	"github.com/ergasterion-dev/kritolith/internal/report"
	"github.com/ergasterion-dev/kritolith/internal/sandbox"
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
	deduper  dedupe.Deduper   // nil when no Deduper is configured
	signer   Signer           // nil when no signing key exists
	sandbox  SandboxRunner    // nil when no sandbox is configured
	logSink  SandboxLogSink   // nil when sandbox logs are not kept
}

// SandboxRunner runs a report's PoC. *sandbox.Runner implements it.
type SandboxRunner interface {
	Run(ctx context.Context, req sandbox.Request) sandbox.Result
}

// SandboxLogSink receives the capped phase logs of a sandbox run, keyed
// by phase. The logs are hostile, reporter-controlled text: a sink may
// keep them in the local store, but they never go into the verdict or
// the emailed bundle.
type SandboxLogSink func(reportID string, logs map[string][]byte)

// Signer signs a composed verdict. *verdict.Signer implements it.
type Signer interface {
	Sign(r report.Report, v report.Verdict) (report.Verdict, error)
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

// WithDedupe returns p configured to also check claims for duplicates
// through d. A nil deduper (New's default) skips the dedupe stage
// entirely — Run behaves exactly as it did before Week 4 for any
// caller that doesn't wire one in.
func (p *Pipeline) WithDedupe(d dedupe.Deduper) *Pipeline {
	p.deduper = d
	return p
}

// WithSigner returns p configured to sign each verdict before it is
// stored. A nil signer (New's default) leaves verdicts unsigned:
// signing is optional and starts when the operator runs `keygen`.
func (p *Pipeline) WithSigner(s Signer) *Pipeline {
	p.signer = s
	return p
}

// WithSandbox returns p configured to run a report's PoC through s. A
// nil runner (New's default) skips the sandbox stage entirely.
func (p *Pipeline) WithSandbox(s SandboxRunner) *Pipeline {
	p.sandbox = s
	return p
}

// WithSandboxLogs returns p configured to hand each sandbox run's
// capped logs to sink. A nil sink (New's default) drops them.
func (p *Pipeline) WithSandboxLogs(sink SandboxLogSink) *Pipeline {
	p.logSink = sink
	return p
}

// Run stores the report, extracts claims, grounds them, composes the
// verdict and stores that too. Deterministic extraction always runs;
// LLM extraction runs only when WithLLM configured a chain, and its
// claims never override a deterministic claim with the same kind and
// value. Grounding runs only when WithGround configured a grounder; it
// never fails Run — a grounding failure of any kind degrades to a
// "ref not resolved" verdict, never a pipeline error. The sandbox
// stage runs after dedupe, only when WithSandbox configured a runner,
// grounding resolved a ref, no hard claim failed and the report
// carries a PoC; like grounding it never fails Run.
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
	res := verdict.StageResults{Claims: claims, LLMUnavailable: llmUnavailable, HasPoC: len(r.PoC) > 0}
	if p.grounder != nil {
		gr := p.grounder.Ground(ctx, r, claims)
		res.Claims = gr.Claims
		res.GroundingRan = true
		res.RefResolved = gr.RefResolved
		res.ResolvedRef = gr.ResolvedRef
		res.ResolvedViaFallback = gr.ViaFallback
		res.Module = gr.Module
	}
	if p.deduper != nil {
		matches, exactMatch := p.deduper.Dedupe(ctx, r, res.Claims, res.Module)
		res.DedupeRan = true
		res.Duplicates = matches
		res.DedupeExactMatch = exactMatch
	}
	if p.sandbox != nil && res.GroundingRan && res.RefResolved && !verdict.HardClaimFailed(res.Claims) && len(r.PoC) > 0 {
		out, logs := p.runSandbox(ctx, sandbox.Request{
			Report: r, ResolvedRef: res.ResolvedRef, ViaFallback: res.ResolvedViaFallback,
			Claims: res.Claims, Module: res.Module,
		})
		res.SandboxRan = true
		res.Sandbox = out
		if p.logSink != nil && len(logs) > 0 {
			p.logSink(r.ID, logs)
		}
	}
	v := verdict.Compose(r, res)
	if p.signer != nil {
		// A key is configured, so an unsigned verdict must not go out
		// looking like a signed deployment's: failing here is safer
		// than quietly storing it unsigned.
		signed, err := p.signer.Sign(r, v)
		if err != nil {
			return report.Verdict{}, fmt.Errorf("pipeline: sign verdict: %w", err)
		}
		v = signed
	}
	if err := p.store.SaveVerdict(ctx, v); err != nil {
		return report.Verdict{}, fmt.Errorf("pipeline: save verdict: %w", err)
	}
	return v, nil
}

// runSandbox calls the runner and converts its Result. A panic in the
// runner, or a Result with no evidence and no reason, becomes an
// inconclusive outcome: the sandbox never fails Run.
func (p *Pipeline) runSandbox(ctx context.Context, req sandbox.Request) (out verdict.SandboxOutcome, logs map[string][]byte) {
	defer func() {
		if rec := recover(); rec != nil {
			out = verdict.SandboxOutcome{Inconclusive: "the sandbox runner failed unexpectedly"}
			logs = nil
		}
	}()
	res := p.sandbox.Run(ctx, req)
	out = verdict.SandboxOutcome{
		Repro:        cloneRepro(res.Repro),
		Skipped:      res.Skipped,
		NeedsInfo:    res.NeedsInfo,
		Inconclusive: res.Inconclusive,
		Passed:       res.Passed,
		Weak:         res.Weak,
		ViaFallback:  res.ViaFallback || req.ViaFallback,
	}
	if out.Repro == nil {
		out.Passed = false
		if out.Skipped == "" && out.NeedsInfo == "" && out.Inconclusive == "" {
			out.Inconclusive = "the sandbox returned no result"
		}
	}
	return out, res.Logs
}

// cloneRepro deep-copies a ReproResult so the verdict never shares
// memory with the runner's result.
func cloneRepro(rr *report.ReproResult) *report.ReproResult {
	if rr == nil {
		return nil
	}
	c := *rr
	c.Control = cloneRepro(rr.Control)
	c.Notes = append([]string(nil), rr.Notes...)
	if rr.LogSHA256 != nil {
		c.LogSHA256 = make(map[string]string, len(rr.LogSHA256))
		for k, v := range rr.LogSHA256 {
			c.LogSHA256[k] = v
		}
	}
	return &c
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
