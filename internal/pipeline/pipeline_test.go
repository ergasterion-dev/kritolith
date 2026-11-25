package pipeline

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/ground"
	"github.com/ergasterion-dev/kritolith/internal/llm"
	"github.com/ergasterion-dev/kritolith/internal/report"
	"github.com/ergasterion-dev/kritolith/internal/sandbox"
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
	if v.Outcome != report.OutcomeNeedsInfo {
		t.Errorf("outcome = %s, want NEEDS_INFO (no runnable PoC attached)", v.Outcome)
	}
	if len(fs.calls) != 2 || fs.calls[0] != "report:R1" || fs.calls[1] != "verdict:NEEDS_INFO" {
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
	r := report.Report{ID: "R1", Repo: "a/b", ClaimedRef: "v1", Body: "See a.go for the bug in release 9.9.9."}
	stub := stubChain{[]llm.Provider{stubProvider{text: `{"claims": [{"kind": "file", "value": "a.go", "evidence": "llm evidence"}, {"kind": "version", "value": "9.9.9", "evidence": "llm only"}]}`}}}
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

func (g fakeGrounder) Ground(ctx context.Context, r report.Report, claims []report.Claim) ground.GroundResult {
	out := claims
	if g.claims != nil {
		out = g.claims
	}
	return ground.GroundResult{Claims: out, RefResolved: g.resolved, ResolvedRef: g.resolvedRef, ViaFallback: g.viaFallback, Module: g.module}
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
	r := report.Report{ID: "R1", Repo: "a/b", ClaimedRef: "v1", Body: "See a.go.", PoC: []report.Artifact{{Name: "poc_test.go", Content: []byte("package a")}}}
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

type fakeDeduper struct {
	matches []report.DupMatch
	exact   bool
	called  bool
}

func (f *fakeDeduper) Dedupe(_ context.Context, _ report.Report, _ []report.Claim, _ string) ([]report.DupMatch, bool) {
	f.called = true
	return f.matches, f.exact
}

func TestPipelineRunWithDedupe(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	fd := &fakeDeduper{matches: []report.DupMatch{{ReportID: "prior", Score: 1.0}}, exact: true}
	p := New(st).WithDedupe(fd)

	v, err := p.Run(ctx, report.Report{ID: "r1", Repo: "owner/repo", ClaimedRef: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", Body: "no claims here"})
	if err != nil {
		t.Fatal(err)
	}
	if !fd.called {
		t.Error("a configured Deduper must be called")
	}
	if v.Outcome != report.OutcomeLikelyDuplicate {
		t.Errorf("Outcome = %s, want LIKELY_DUPLICATE", v.Outcome)
	}
}

func TestPipelineRunWithoutDedupeUnchanged(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p := New(st) // no WithDedupe: must behave exactly as before Week 4

	v, err := p.Run(ctx, report.Report{ID: "r1", Repo: "owner/repo", Body: "no claims here"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Outcome != report.OutcomeNeedsInfo {
		t.Errorf("Outcome = %s, want NEEDS_INFO (no ClaimedRef), unaffected by the new dedupe stage", v.Outcome)
	}
}

type fakeRunner struct {
	result sandbox.Result
	panics bool
	calls  []sandbox.Request
}

func (f *fakeRunner) Run(_ context.Context, req sandbox.Request) sandbox.Result {
	f.calls = append(f.calls, req)
	if f.panics {
		panic("runner blew up")
	}
	return f.result
}

func TestRunSandboxStage(t *testing.T) {
	const sha = "e1fcd82abba34df74614020343be8eb1fe85f0d9"
	poc := []report.Artifact{{Name: "poc_test.go", Content: []byte("package a")}}
	verified := []report.Claim{{Kind: report.ClaimFunction, Value: "a.F", Verified: report.TriYes}}
	missing := []report.Claim{{Kind: report.ClaimFunction, Value: "a.G", Verified: report.TriNo}}
	repro := func() *report.ReproResult {
		return &report.ReproResult{Ref: sha, Reproduced: true, Signal: "panic-in-claimed-code", ControlState: "fixed",
			LogSHA256: map[string]string{"run": "ab"}, Notes: []string{"n"}, Control: &report.ReproResult{Ref: "head"}}
	}
	ok := fakeGrounder{claims: verified, resolved: true, resolvedRef: sha, module: "example.com/a"}
	tests := []struct {
		name       string
		poc        []report.Artifact
		grounder   *fakeGrounder
		runner     *fakeRunner
		wantCalled bool
		want       report.Outcome
	}{
		{"reproduced, fixed at HEAD", poc, &ok, &fakeRunner{result: sandbox.Result{Repro: repro()}}, true, report.OutcomeReproducedFixedAtHead},
		{"ran clean", poc, &ok, &fakeRunner{result: sandbox.Result{Repro: &report.ReproResult{Ref: sha}, Passed: true}}, true, report.OutcomeNotReproduced},
		{"needs info", poc, &ok, &fakeRunner{result: sandbox.Result{NeedsInfo: "no Go files"}}, true, report.OutcomeNeedsInfo},
		{"skipped", poc, &ok, &fakeRunner{result: sandbox.Result{Skipped: "no sandbox rootfs is configured"}}, true, report.OutcomeInconclusive},
		{"runner panics", poc, &ok, &fakeRunner{panics: true}, true, report.OutcomeInconclusive},
		{"runner returns nothing", poc, &ok, &fakeRunner{}, true, report.OutcomeInconclusive},
		{"passed without evidence", poc, &ok, &fakeRunner{result: sandbox.Result{Passed: true}}, true, report.OutcomeInconclusive},
		{"no PoC", nil, &ok, &fakeRunner{result: sandbox.Result{Repro: repro()}}, false, report.OutcomeNeedsInfo},
		{"no grounder", poc, nil, &fakeRunner{result: sandbox.Result{Repro: repro()}}, false, report.OutcomeInconclusive},
		{"ref unresolved", poc, &fakeGrounder{resolved: false}, &fakeRunner{result: sandbox.Result{Repro: repro()}}, false, report.OutcomeNeedsInfo},
		{"hard claim failed", poc, &fakeGrounder{claims: missing, resolved: true, resolvedRef: sha}, &fakeRunner{result: sandbox.Result{Repro: repro()}}, false, report.OutcomeGroundingFailed},
		{"hard claim failed via fallback", poc, &fakeGrounder{claims: missing, resolved: true, resolvedRef: sha, viaFallback: true}, &fakeRunner{result: sandbox.Result{Repro: repro()}}, false, report.OutcomeInconclusive},
		{"no sandbox configured", poc, &ok, nil, false, report.OutcomeInconclusive},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := report.Report{ID: "R1", Repo: "a/b", ClaimedRef: sha, Body: "x", PoC: tt.poc}
			p := New(&fakeStore{})
			if tt.grounder != nil {
				p = p.WithGround(*tt.grounder)
			}
			if tt.runner != nil {
				p = p.WithSandbox(tt.runner)
			}
			v, err := p.Run(context.Background(), r)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if v.Outcome != tt.want {
				t.Errorf("Outcome = %s, want %s (notes %q)", v.Outcome, tt.want, v.Notes)
			}
			called := tt.runner != nil && len(tt.runner.calls) > 0
			if called != tt.wantCalled {
				t.Fatalf("runner called = %v, want %v", called, tt.wantCalled)
			}
			if !called {
				if v.Repro != nil {
					t.Errorf("Repro = %+v, want nil when the sandbox did not run", v.Repro)
				}
				return
			}
			req := tt.runner.calls[0]
			if req.ResolvedRef != sha || req.Module != "example.com/a" || req.Report.ID != "R1" || len(req.Claims) != 1 || req.ViaFallback {
				t.Errorf("Request = %+v, want grounding's ref, module and claims", req)
			}
			if got := tt.runner.result.Repro; got != nil {
				if v.Repro == nil || v.Repro == got || (got.Control != nil && v.Repro.Control == got.Control) {
					t.Fatalf("Repro = %+v, want a deep copy of %+v", v.Repro, got)
				}
				if len(got.Notes) > 0 {
					got.Notes[0] = "mutated"
					got.LogSHA256["run"] = "mutated"
					if v.Repro.Notes[0] != "n" || v.Repro.LogSHA256["run"] != "ab" {
						t.Errorf("verdict Repro shares memory with the runner's result: %+v", v.Repro)
					}
				}
			}
		})
	}
}

func TestRunSandboxPassesFallback(t *testing.T) {
	const sha = "e1fcd82abba34df74614020343be8eb1fe85f0d9"
	fr := &fakeRunner{result: sandbox.Result{Repro: &report.ReproResult{Ref: sha}, Passed: true}}
	r := report.Report{ID: "R1", Repo: "a/b", ClaimedRef: sha, PoC: []report.Artifact{{Name: "p_test.go"}}}
	v, err := New(&fakeStore{}).WithGround(fakeGrounder{resolved: true, resolvedRef: sha, viaFallback: true}).WithSandbox(fr).Run(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != 1 || !fr.calls[0].ViaFallback {
		t.Fatalf("calls = %+v, want one request with ViaFallback", fr.calls)
	}
	if v.Outcome != report.OutcomeInconclusive {
		t.Errorf("Outcome = %s, want INCONCLUSIVE: a clean run at a fallback version is not NOT_REPRODUCED", v.Outcome)
	}
}

func TestRunSandboxLogSink(t *testing.T) {
	const sha = "e1fcd82abba34df74614020343be8eb1fe85f0d9"
	logs := map[string][]byte{"run": []byte("hostile output")}
	fr := &fakeRunner{result: sandbox.Result{Repro: &report.ReproResult{Ref: sha}, Inconclusive: "timeout", Logs: logs}}
	var gotID string
	var gotLogs map[string][]byte
	sink := func(id string, l map[string][]byte) { gotID, gotLogs = id, l }
	p := New(&fakeStore{}).WithGround(fakeGrounder{resolved: true, resolvedRef: sha}).WithSandbox(fr).WithSandboxLogs(sink)

	v, err := p.Run(context.Background(), report.Report{ID: "R1", Repo: "a/b", ClaimedRef: sha, PoC: []report.Artifact{{Name: "p_test.go"}}})
	if err != nil {
		t.Fatal(err)
	}
	if gotID != "R1" || string(gotLogs["run"]) != "hostile output" {
		t.Errorf("sink got (%q, %q), want the run's logs", gotID, gotLogs)
	}
	for _, n := range v.Notes {
		if strings.Contains(n, "hostile output") {
			t.Errorf("log text leaked into the verdict notes: %q", v.Notes)
		}
	}

	gotID = ""
	if _, err := p.Run(context.Background(), report.Report{ID: "R2", Repo: "a/b", ClaimedRef: sha}); err != nil {
		t.Fatal(err)
	}
	if gotID != "" {
		t.Errorf("sink called for a report without a PoC")
	}
}

// A sandbox configured on the pipeline must not change what is stored
// for a report with no PoC: the runner is never called and the stored
// verdict is NEEDS_INFO.
func TestRunSandboxNoPoCStoresNeedsInfo(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const sha = "e1fcd82abba34df74614020343be8eb1fe85f0d9"
	fr := &fakeRunner{result: sandbox.Result{Repro: &report.ReproResult{Ref: sha, Reproduced: true}}}
	r := report.Report{ID: "01ARYZ6S410000000000000001", Source: report.SourceFile, Repo: "a/b", ClaimedRef: sha}
	if _, err := New(st).WithGround(fakeGrounder{resolved: true, resolvedRef: sha}).WithSandbox(fr).Run(ctx, r); err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != 0 {
		t.Errorf("runner called %d times for a report without a PoC", len(fr.calls))
	}
	got, err := st.GetVerdict(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != report.OutcomeNeedsInfo || got.Repro != nil {
		t.Errorf("stored verdict = %s (repro %+v), want NEEDS_INFO with no repro", got.Outcome, got.Repro)
	}
}
