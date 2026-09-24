package pipeline

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/llm"
	"github.com/ergasterion-dev/kritolith/internal/report"
	"github.com/ergasterion-dev/kritolith/internal/store"
)

type fakeStore struct {
	calls      []string
	reportErr  error
	verdictErr error
}

func (f *fakeStore) SaveReport(_ context.Context, r report.Report) error {
	f.calls = append(f.calls, "report:"+r.ID)
	return f.reportErr
}

func (f *fakeStore) SaveVerdict(_ context.Context, v report.Verdict) error {
	f.calls = append(f.calls, "verdict:"+string(v.Outcome))
	return f.verdictErr
}

func TestRunOrderAndOutcome(t *testing.T) {
	fs := &fakeStore{}
	v, err := New(fs).Run(context.Background(), report.Report{ID: "R1", Repo: "a/b", ClaimedRef: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Outcome != report.OutcomeInconclusive {
		t.Errorf("outcome = %s", v.Outcome)
	}
	if len(fs.calls) != 2 || fs.calls[0] != "report:R1" || fs.calls[1] != "verdict:INCONCLUSIVE" {
		t.Errorf("calls = %v", fs.calls)
	}
}

func TestRunStoreError(t *testing.T) {
	fs := &fakeStore{reportErr: errors.New("disk full")}
	_, err := New(fs).Run(context.Background(), report.Report{ID: "R1"})
	if err == nil {
		t.Fatal("want error")
	}
	if !strings.Contains(err.Error(), "save report:") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "save report:")
	}
	if len(fs.calls) != 1 {
		t.Errorf("verdict saved after report failed: %v", fs.calls)
	}
}

func TestRunVerdictSaveError(t *testing.T) {
	fs := &fakeStore{verdictErr: errors.New("disk full")}
	_, err := New(fs).Run(context.Background(), report.Report{ID: "R1"})
	if err == nil {
		t.Fatal("want error")
	}
	if !strings.Contains(err.Error(), "save verdict:") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "save verdict:")
	}
}

func TestRunWithSQLite(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := report.Report{ID: "01ARYZ6S410000000000000000", Source: report.SourceFile, Repo: "a/b"}
	if _, err := New(s).Run(ctx, r); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetVerdict(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != report.OutcomeNeedsInfo {
		t.Errorf("stored outcome = %s, want NEEDS_INFO", got.Outcome)
	}
}

type stubProvider struct{ text string }

func (s stubProvider) Complete(ctx context.Context, req llm.CompleteRequest) (llm.CompleteResponse, error) {
	return llm.CompleteResponse{Text: s.text}, nil
}
func (s stubProvider) Embed(ctx context.Context, texts []string) ([][]float32, error) {
	return nil, nil
}
func (s stubProvider) Name() string  { return "stub" }
func (s stubProvider) IsLocal() bool { return true }

type stubChain struct{ providers []llm.Provider }

func (s stubChain) Chain(task, reportID, repo string) []llm.Provider { return s.providers }

func TestRunExtractsDeterministicClaims(t *testing.T) {
	fs := &fakeStore{}
	r := report.Report{ID: "R1", Repo: "a/b", ClaimedRef: "v1", Body: "See internal/hpack/decode.go:412."}
	v, err := New(fs).Run(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range v.Claims {
		if c.Kind == report.ClaimFile && c.Value == "internal/hpack/decode.go" {
			found = true
		}
	}
	if !found {
		t.Errorf("claims = %+v, missing deterministic file claim", v.Claims)
	}
}

func TestRunMergesLLMClaimsWithoutOverridingDeterministic(t *testing.T) {
	fs := &fakeStore{}
	r := report.Report{ID: "R1", Repo: "a/b", ClaimedRef: "v1", Body: "See a.go for the bug."}
	stub := stubChain{[]llm.Provider{stubProvider{text: `{"claims": [{"kind": "file", "value": "a.go", "evidence": "llm evidence"}, {"kind": "version", "value": "v9.9.9", "evidence": "llm only"}]}`}}}
	v, err := New(fs).WithLLM(stub).Run(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	var fileClaim, versionClaim *report.Claim
	for i := range v.Claims {
		switch v.Claims[i].Kind {
		case report.ClaimFile:
			fileClaim = &v.Claims[i]
		case report.ClaimVersion:
			versionClaim = &v.Claims[i]
		}
	}
	if fileClaim == nil || fileClaim.Source != "deterministic" {
		t.Errorf("file claim = %+v, want deterministic to win", fileClaim)
	}
	if versionClaim == nil || versionClaim.Source != "llm:stub" {
		t.Errorf("version claim = %+v, want the LLM-only claim kept", versionClaim)
	}
}

func TestRunWithNoLLMConfigured(t *testing.T) {
	fs := &fakeStore{}
	r := report.Report{ID: "R1", Repo: "a/b", ClaimedRef: "v1", Body: "See a.go."}
	v, err := New(fs).Run(context.Background(), r) // no WithLLM call
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Claims) == 0 {
		t.Error("want deterministic claims even with no LLM configured")
	}
	for _, n := range v.Notes {
		if strings.Contains(n, "LLM extraction unavailable") {
			t.Errorf("notes = %v, want no LLM-unavailable note when no LLM was configured at all", v.Notes)
		}
	}
}

type failingProvider struct{ name string }

func (f failingProvider) Complete(ctx context.Context, req llm.CompleteRequest) (llm.CompleteResponse, error) {
	return llm.CompleteResponse{}, errors.New("boom")
}
func (f failingProvider) Embed(ctx context.Context, texts []string) ([][]float32, error) {
	return nil, nil
}
func (f failingProvider) Name() string  { return f.name }
func (f failingProvider) IsLocal() bool { return true }

// TestRunSucceedsWithLLMUnavailableNote proves that when WithLLM is
// configured but every provider in the chain fails, Run still
// succeeds (never wrongly rejects a report over an LLM outage) and the
// verdict carries a note that LLM extraction was unavailable, so the
// degraded state is visible instead of silent.
func TestRunSucceedsWithLLMUnavailableNote(t *testing.T) {
	fs := &fakeStore{}
	r := report.Report{ID: "R1", Repo: "a/b", ClaimedRef: "v1", Body: "See a.go."}
	chain := stubChain{[]llm.Provider{failingProvider{name: "bad"}}}
	v, err := New(fs).WithLLM(chain).Run(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Claims) == 0 {
		t.Error("want deterministic claims to still be present")
	}
	found := false
	for _, n := range v.Notes {
		if strings.Contains(n, "LLM extraction unavailable") {
			found = true
		}
	}
	if !found {
		t.Errorf("notes = %v, want a note that LLM extraction was unavailable", v.Notes)
	}
}

type fakeGrounder struct {
	claims      []report.Claim // if non-nil, returned as-is instead of the input claims
	resolved    bool
	resolvedRef string
	viaFallback bool
	module      string
}

func (g fakeGrounder) Ground(ctx context.Context, r report.Report, claims []report.Claim) ([]report.Claim, bool, string, bool, string) {
	out := claims
	if g.claims != nil {
		out = g.claims
	}
	return out, g.resolved, g.resolvedRef, g.viaFallback, g.module
}

func TestRunGroundingFailedOutcome(t *testing.T) {
	fs := &fakeStore{}
	r := report.Report{ID: "R1", Repo: "a/b", ClaimedRef: "v1", Body: "See a.go for the bug."}
	failed := []report.Claim{{Kind: report.ClaimFile, Value: "a.go", Verified: report.TriNo, Evidence: "not found"}}
	v, err := New(fs).WithGround(fakeGrounder{claims: failed, resolved: true, resolvedRef: "abc123"}).Run(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if v.Outcome != report.OutcomeGroundingFailed {
		t.Errorf("Outcome = %s, want GROUNDING_FAILED", v.Outcome)
	}
}

func TestRunGroundingRefNotResolved(t *testing.T) {
	fs := &fakeStore{}
	r := report.Report{ID: "R1", Repo: "a/b", ClaimedRef: "v1", Body: "See a.go."}
	v, err := New(fs).WithGround(fakeGrounder{resolved: false}).Run(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if v.Outcome != report.OutcomeNeedsInfo {
		t.Errorf("Outcome = %s, want NEEDS_INFO", v.Outcome)
	}
}

func TestRunWithNoGrounderConfiguredIsUnchanged(t *testing.T) {
	fs := &fakeStore{}
	r := report.Report{ID: "R1", Repo: "a/b", ClaimedRef: "v1", Body: "See a.go."}
	v, err := New(fs).Run(context.Background(), r) // no WithGround call
	if err != nil {
		t.Fatal(err)
	}
	if v.Outcome != report.OutcomeInconclusive {
		t.Errorf("Outcome = %s, want INCONCLUSIVE (no grounder configured must behave exactly like before Week 3)", v.Outcome)
	}
}

func TestRunGroundingViaFallbackNeverGroundingFails(t *testing.T) {
	fs := &fakeStore{}
	r := report.Report{ID: "R1", Repo: "o/n", ClaimedRef: "e1fcd82abba34df74614020343be8eb1fe85f0d9", Body: "x"}
	failed := []report.Claim{{Kind: report.ClaimFunction, Value: "parseThing", Verified: report.TriNo}}
	v, err := New(fs).WithGround(fakeGrounder{claims: failed, resolved: true, resolvedRef: "abc123", viaFallback: true}).Run(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if v.Outcome != report.OutcomeInconclusive {
		t.Errorf("Outcome = %s, want INCONCLUSIVE when grounding resolved only a fallback version", v.Outcome)
	}
}
