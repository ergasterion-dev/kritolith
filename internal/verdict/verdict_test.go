package verdict

import (
	"strings"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

func TestCompose(t *testing.T) {
	tests := []struct {
		name   string
		ref    string
		hasPoC bool
		want   report.Outcome
	}{
		{"with ref and PoC, no sandbox", "e1fcd82abba34df74614020343be8eb1fe85f0d9", true, report.OutcomeInconclusive},
		{"with ref, no PoC", "e1fcd82abba34df74614020343be8eb1fe85f0d9", false, report.OutcomeNeedsInfo},
		{"no ref", "", true, report.OutcomeNeedsInfo},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := Compose(report.Report{ID: "R1", ClaimedRef: tt.ref}, StageResults{HasPoC: tt.hasPoC})
			if v.ReportID != "R1" || v.Outcome != tt.want || len(v.Notes) == 0 {
				t.Fatalf("Compose = %+v, want %s with notes", v, tt.want)
			}
		})
	}
}

func TestComposeCarriesClaims(t *testing.T) {
	claims := []report.Claim{{Kind: report.ClaimFile, Value: "a.go", Source: "deterministic"}}
	v := Compose(report.Report{ID: "R1", ClaimedRef: "v1"}, StageResults{Claims: claims})
	if len(v.Claims) != 1 || v.Claims[0].Value != "a.go" {
		t.Fatalf("Claims = %+v", v.Claims)
	}
}

func TestRender(t *testing.T) {
	r := report.Report{ID: "R1", Repo: "golang/net", ClaimedRef: "e1fcd82abba34df74614020343be8eb1fe85f0d9"}
	out := Render(r, Compose(r, StageResults{HasPoC: true}))
	if !strings.HasPrefix(out, "Kritolith: INCONCLUSIVE at e1fcd82abba3\n") {
		t.Errorf("header wrong:\n%s", out)
	}
	if !strings.Contains(out, "Report: R1 (golang/net)") {
		t.Errorf("missing report line:\n%s", out)
	}

	tag := report.Report{ID: "R2", Repo: "a/b", ClaimedRef: "v1.2.3"}
	if out := Render(tag, Compose(tag, StageResults{HasPoC: true})); !strings.HasPrefix(out, "Kritolith: INCONCLUSIVE at v1.2.3\n") {
		t.Errorf("tag ref header wrong:\n%s", out)
	}
	none := report.Report{ID: "R3", Repo: "a/b"}
	if out := Render(none, Compose(none, StageResults{})); !strings.HasPrefix(out, "Kritolith: NEEDS_INFO\n") {
		t.Errorf("no-ref header wrong:\n%s", out)
	}
}

func TestRenderSanitizes(t *testing.T) {
	r := report.Report{ID: "R1", Repo: "a/b", ClaimedRef: "v1"}
	v := report.Verdict{
		ReportID: "R1",
		Outcome:  report.OutcomeGroundingFailed,
		Claims: []report.Claim{{
			Kind: report.ClaimFunction, Value: "evil\x1b[2J", Evidence: "not found‮",
		}},
		Notes: []string{"note\x1b]0;pwned\x07"},
	}
	out := Render(r, v)
	if strings.ContainsAny(out, "\x1b\x07‮") {
		t.Fatalf("control characters leaked into output: %q", out)
	}
	if !strings.Contains(out, "• function evil�[2J — not found�") {
		t.Fatalf("claim line wrong: %q", out)
	}
}

func TestComposeRefNotResolved(t *testing.T) {
	v := Compose(report.Report{ID: "R1", ClaimedRef: "deadbeef"}, StageResults{GroundingRan: true, RefResolved: false})
	if v.Outcome != report.OutcomeNeedsInfo {
		t.Errorf("Outcome = %s, want NEEDS_INFO", v.Outcome)
	}
}

func TestComposeGroundingFailedOnHardClaim(t *testing.T) {
	tests := []report.ClaimKind{report.ClaimFile, report.ClaimFunction}
	for _, kind := range tests {
		claims := []report.Claim{{Kind: kind, Value: "x", Verified: report.TriNo}}
		v := Compose(report.Report{ID: "R1", ClaimedRef: "v1"}, StageResults{Claims: claims, GroundingRan: true, RefResolved: true})
		if v.Outcome != report.OutcomeGroundingFailed {
			t.Errorf("kind %s: Outcome = %s, want GROUNDING_FAILED", kind, v.Outcome)
		}
	}
}

func TestComposeLineOnlyFailureNeverGroundingFails(t *testing.T) {
	claims := []report.Claim{{Kind: report.ClaimLine, Value: "a.go:9999", Verified: report.TriNo}}
	v := Compose(report.Report{ID: "R1", ClaimedRef: "v1"}, StageResults{Claims: claims, GroundingRan: true, RefResolved: true, HasPoC: true})
	if v.Outcome != report.OutcomeInconclusive {
		t.Errorf("Outcome = %s, want INCONCLUSIVE (a line claim alone must never cause GROUNDING_FAILED)", v.Outcome)
	}
}

func TestComposeGroundingSucceededNoHardFailure(t *testing.T) {
	claims := []report.Claim{{Kind: report.ClaimFile, Value: "a.go", Verified: report.TriYes}}
	v := Compose(report.Report{ID: "R1", ClaimedRef: "v1"}, StageResults{Claims: claims, GroundingRan: true, RefResolved: true, HasPoC: true})
	if v.Outcome != report.OutcomeInconclusive {
		t.Errorf("Outcome = %s, want INCONCLUSIVE", v.Outcome)
	}
}

func TestComposeNoGrounderConfiguredIsUnaffected(t *testing.T) {
	// GroundingRan defaults to false (the zero value) when no Grounder
	// was wired into the pipeline at all — this must behave exactly
	// like Week 2 (no regression for callers that don't configure one).
	v := Compose(report.Report{ID: "R1", ClaimedRef: "v1"}, StageResults{HasPoC: true})
	if v.Outcome != report.OutcomeInconclusive {
		t.Errorf("Outcome = %s, want INCONCLUSIVE", v.Outcome)
	}
}

func TestComposeStillAppendsLLMUnavailableNote(t *testing.T) {
	claims := []report.Claim{{Kind: report.ClaimFile, Value: "x", Verified: report.TriNo}}
	v := Compose(report.Report{ID: "R1", ClaimedRef: "v1"}, StageResults{Claims: claims, GroundingRan: true, RefResolved: true, LLMUnavailable: true})
	if v.Outcome != report.OutcomeGroundingFailed {
		t.Errorf("Outcome = %s, want GROUNDING_FAILED", v.Outcome)
	}
	found := false
	for _, n := range v.Notes {
		if strings.Contains(n, "LLM extraction unavailable") {
			found = true
		}
	}
	if !found {
		t.Errorf("Notes = %v, want the LLM-unavailable note to still be appended alongside a GROUNDING_FAILED outcome", v.Notes)
	}
}

// Final-review I3: a hard-claim failure against a commit that came
// from a fallback version, not the claimed ref, is never a rejection.
func TestComposeFallbackResolvedHardFailureIsInconclusive(t *testing.T) {
	for _, kind := range []report.ClaimKind{report.ClaimFile, report.ClaimFunction} {
		claims := []report.Claim{{Kind: kind, Value: "x", Verified: report.TriNo}}
		r := report.Report{ID: "R1", ClaimedRef: "e1fcd82abba34df74614020343be8eb1fe85f0d9"}
		v := Compose(r, StageResults{Claims: claims, GroundingRan: true, RefResolved: true, ResolvedViaFallback: true})
		if v.Outcome != report.OutcomeInconclusive {
			t.Errorf("kind %s via fallback: Outcome = %s, want INCONCLUSIVE", kind, v.Outcome)
		}
		found := false
		for _, n := range v.Notes {
			if strings.Contains(n, "fallback version") {
				found = true
			}
		}
		if !found {
			t.Errorf("kind %s via fallback: Notes = %v, want the fallback explanation", kind, v.Notes)
		}
		// The normal path is unaffected.
		direct := Compose(r, StageResults{Claims: claims, GroundingRan: true, RefResolved: true})
		if direct.Outcome != report.OutcomeGroundingFailed {
			t.Errorf("kind %s direct: Outcome = %s, want GROUNDING_FAILED", kind, direct.Outcome)
		}
	}
}

func TestComposeLikelyDuplicate(t *testing.T) {
	r := report.Report{ID: "r1", ClaimedRef: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
	res := StageResults{
		GroundingRan: true, RefResolved: true,
		DedupeRan: true, DedupeExactMatch: true,
		Duplicates: []report.DupMatch{{ReportID: "prior", Score: 1.0}},
	}
	v := Compose(r, res)
	if v.Outcome != report.OutcomeLikelyDuplicate {
		t.Errorf("Outcome = %s, want LIKELY_DUPLICATE", v.Outcome)
	}
	if len(v.Duplicates) != 1 || v.Duplicates[0].ReportID != "prior" {
		t.Errorf("Duplicates = %+v, want the dedupe match carried through", v.Duplicates)
	}
}

func TestComposeGroundingFailedWinsOverDedupe(t *testing.T) {
	r := report.Report{ID: "r1", ClaimedRef: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
	res := StageResults{
		GroundingRan: true, RefResolved: true,
		Claims:           []report.Claim{{Kind: report.ClaimFunction, Verified: report.TriNo}},
		DedupeRan:        true,
		DedupeExactMatch: true,
	}
	v := Compose(r, res)
	if v.Outcome != report.OutcomeGroundingFailed {
		t.Errorf("Outcome = %s, want GROUNDING_FAILED even though dedupe also found an exact match", v.Outcome)
	}
}

func TestComposeFallbackResolutionNeverUpgradesToDuplicate(t *testing.T) {
	r := report.Report{ID: "r1", ClaimedRef: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
	res := StageResults{
		GroundingRan: true, RefResolved: true, ResolvedViaFallback: true,
		Claims:           []report.Claim{{Kind: report.ClaimFunction, Verified: report.TriNo}},
		DedupeRan:        true,
		DedupeExactMatch: true,
	}
	v := Compose(r, res)
	if v.Outcome != report.OutcomeInconclusive {
		t.Errorf("Outcome = %s, want INCONCLUSIVE: a fallback-resolved hard-claim failure must not be upgraded by dedupe", v.Outcome)
	}
}

func TestComposeDedupeRanButNoExactMatch(t *testing.T) {
	r := report.Report{ID: "r1", ClaimedRef: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
	res := StageResults{
		GroundingRan: true, RefResolved: true,
		DedupeRan:  true,
		Duplicates: []report.DupMatch{{ReportID: "lead-only", Score: 0.95}},
		HasPoC:     true,
	}
	v := Compose(r, res)
	if v.Outcome != report.OutcomeInconclusive {
		t.Errorf("Outcome = %s, want INCONCLUSIVE: an embedding-only lead must never set the outcome", v.Outcome)
	}
	if len(v.Duplicates) != 1 {
		t.Errorf("Duplicates = %+v, want the lead still recorded for visibility", v.Duplicates)
	}
}

func TestComposeFallbackResolvedCleanDedupeMatchIsInconclusive(t *testing.T) {
	r := report.Report{ID: "r1", ClaimedRef: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
	res := StageResults{
		GroundingRan: true, RefResolved: true, ResolvedViaFallback: true,
		Claims:           []report.Claim{{Kind: report.ClaimFunction, Value: "(*T).M", Verified: report.TriYes}},
		DedupeRan:        true,
		DedupeExactMatch: true,
		Duplicates:       []report.DupMatch{{ReportID: "prior", Score: 1.0}},
		HasPoC:           true,
	}
	v := Compose(r, res)
	if v.Outcome != report.OutcomeInconclusive {
		t.Errorf("Outcome = %s, want INCONCLUSIVE: claims verified against a fallback commit can't anchor a duplicate match", v.Outcome)
	}
	if !strings.Contains(strings.Join(v.Notes, "\n"), "fallback version") {
		t.Errorf("Notes = %q, want one explaining why the exact match was withheld", v.Notes)
	}
	if len(v.Duplicates) != 1 {
		t.Errorf("Duplicates = %+v, want the match still recorded as a lead", v.Duplicates)
	}
}

func TestComposeDedupeWithoutGroundingStillFires(t *testing.T) {
	r := report.Report{ID: "r1", ClaimedRef: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
	v := Compose(r, StageResults{DedupeRan: true, DedupeExactMatch: true})
	if v.Outcome != report.OutcomeLikelyDuplicate {
		t.Errorf("Outcome = %s, want LIKELY_DUPLICATE when grounding wasn't configured at all", v.Outcome)
	}
}

func TestRenderDuplicates(t *testing.T) {
	r := report.Report{ID: "R1", Repo: "a/b", ClaimedRef: "v1"}
	v := report.Verdict{
		ReportID: "R1",
		Outcome:  report.OutcomeLikelyDuplicate,
		Duplicates: []report.DupMatch{
			{ReportID: "01PRIOR", Score: 1.0, Evidence: "fingerprint match: parser.peek (out-of-bounds read)"},
			{AdvisoryID: "GO-2022-0603", Score: 1.0, Evidence: "OSV symbol match: parser.peek (GO-2022-0603)"},
			{ReportID: "01EVIL\x1b[2J", Score: 0.95, Evidence: "fingerprint match: x.y (race\u202e)"},
		},
	}
	out := Render(r, v)
	for _, want := range []string{
		"• possible duplicate: report 01PRIOR (score 1.00) — fingerprint match: parser.peek (out-of-bounds read)\n",
		"• possible duplicate: advisory GO-2022-0603 (score 1.00) — OSV symbol match: parser.peek (GO-2022-0603)\n",
		"• possible duplicate: report 01EVIL�[2J (score 0.95) — fingerprint match: x.y (race�)\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Render missing %q:\n%s", want, out)
		}
	}
	if strings.ContainsAny(out, "\x1b\u202e") {
		t.Fatalf("control characters leaked into output: %q", out)
	}
}

// weakSignal is ReproResult.Signal as the sandbox Runner writes it for
// signal 3: "<kind>: <detail>".
const weakSignal = "failing-test-reaching-claimed-code: TestPoC failed, and coverage shows claimed code executed: vuln/vuln.go:4.27,6.2"

// TestComposePrecedence has one row per line of Compose's documented
// precedence (and of the spec's "Outcomes and where it plugs in").
func TestComposePrecedence(t *testing.T) {
	const sha = "e1fcd82abba34df74614020343be8eb1fe85f0d9"
	missing := []report.Claim{{Kind: report.ClaimFunction, Value: "x", Verified: report.TriNo}}
	grounded := StageResults{GroundingRan: true, RefResolved: true, ResolvedRef: sha, HasPoC: true}
	with := func(f func(*StageResults)) StageResults { s := grounded; f(&s); return s }
	repro := func(signal, control string) *report.ReproResult {
		return &report.ReproResult{Ref: sha, Reproduced: true, Signal: signal, ControlState: control}
	}
	clean := &report.ReproResult{Ref: sha, Signal: "none"}
	dup := func(s *StageResults) {
		s.DedupeRan, s.DedupeExactMatch = true, true
		s.Duplicates = []report.DupMatch{{ReportID: "prior", Score: 1}}
	}
	tests := []struct {
		name     string
		ref      string
		res      StageResults
		want     report.Outcome
		wantNote string // a note that must appear ("" = none required)
		dupsKept bool
	}{
		{"1 no ref", "", with(func(s *StageResults) {}), report.OutcomeNeedsInfo, "no commit or tag given", false},
		{"1 unresolved ref", sha, StageResults{GroundingRan: true, HasPoC: true}, report.OutcomeNeedsInfo, "did not resolve", false},
		{"2 hard failure via fallback", sha, with(func(s *StageResults) { s.Claims = missing; s.ResolvedViaFallback = true }), report.OutcomeInconclusive, "fallback version", false},
		{"2 hard failure", sha, with(func(s *StageResults) { s.Claims = missing }), report.OutcomeGroundingFailed, "PoC not run: grounding failed on a hard claim", false},
		{"2 hard failure beats a sandbox result", sha, with(func(s *StageResults) {
			s.Claims = missing
			s.SandboxRan = true
			s.Sandbox = SandboxOutcome{Repro: repro("panic-in-claimed-code", "fixed")}
		}), report.OutcomeGroundingFailed, "PoC not run", false},
		{"3a PoC invalid", sha, with(func(s *StageResults) {
			s.SandboxRan = true
			s.Sandbox = SandboxOutcome{NeedsInfo: "no Go files in the PoC"}
		}), report.OutcomeNeedsInfo, "no Go files in the PoC", false},
		{"3b reproduced, control fixed", sha, with(func(s *StageResults) {
			s.SandboxRan = true
			s.Sandbox = SandboxOutcome{Repro: repro("panic-in-claimed-code", "fixed")}
		}), report.OutcomeReproducedFixedAtHead, "", false},
		{"3b weak, control fixed", sha, with(func(s *StageResults) {
			s.SandboxRan = true
			s.Sandbox = SandboxOutcome{Repro: repro(weakSignal, "fixed"), Weak: true}
		}), report.OutcomeReproducedFixedAtHead, "", false},
		{"3b strong, control still reproduces", sha, with(func(s *StageResults) {
			s.SandboxRan = true
			s.Sandbox = SandboxOutcome{Repro: repro("race-in-claimed-code", "still_reproduces")}
		}), report.OutcomeReproduced, "", false},
		{"3b weak, control still reproduces (defensive)", sha, with(func(s *StageResults) {
			s.SandboxRan = true
			s.Sandbox = SandboxOutcome{Repro: repro(weakSignal, "still_reproduces"), Weak: true}
		}), report.OutcomeInconclusive, "the PoC also fails at HEAD", false},
		{"3b weak, control unavailable (defensive)", sha, with(func(s *StageResults) {
			s.SandboxRan = true
			s.Sandbox = SandboxOutcome{Repro: repro(weakSignal, "unavailable"), Weak: true}
		}), report.OutcomeInconclusive, "assertion-only failure counts only", false},
		{"3b weak by signal alone, control still reproduces", sha, with(func(s *StageResults) {
			s.SandboxRan = true
			s.Sandbox = SandboxOutcome{Repro: repro(weakSignal, "still_reproduces")}
		}), report.OutcomeInconclusive, "the PoC also fails at HEAD", false},
		{"3b weak by signal alone, control unavailable", sha, with(func(s *StageResults) {
			s.SandboxRan = true
			s.Sandbox = SandboxOutcome{Repro: repro(weakSignal, "unavailable")}
		}), report.OutcomeInconclusive, "assertion-only failure counts only", false},
		{"3b weak, control still reproduces, exact duplicate", sha, with(func(s *StageResults) {
			dup(s)
			s.SandboxRan = true
			s.Sandbox = SandboxOutcome{Repro: repro(weakSignal, "still_reproduces"), Weak: true}
		}), report.OutcomeLikelyDuplicate, "the PoC also fails at HEAD", true},
		{"3b strong, control unavailable", sha, with(func(s *StageResults) {
			s.SandboxRan = true
			s.Sandbox = SandboxOutcome{Repro: repro("panic-in-claimed-code", "unavailable")}
		}), report.OutcomeReproduced, "could not be re-run at HEAD; whether it is fixed is unknown", false},
		{"3b strong, no control state", sha, with(func(s *StageResults) {
			s.SandboxRan = true
			s.Sandbox = SandboxOutcome{Repro: repro("panic-in-claimed-code", "")}
		}), report.OutcomeReproduced, "could not be re-run at HEAD", false},
		{"3b reproduction outranks an exact duplicate", sha, with(func(s *StageResults) {
			dup(s)
			s.SandboxRan = true
			s.Sandbox = SandboxOutcome{Repro: repro("panic-in-claimed-code", "still_reproduces")}
		}), report.OutcomeReproduced, "also exactly matches an earlier report", true},
		{"3b reproduced via fallback", sha, with(func(s *StageResults) {
			s.ResolvedViaFallback = true
			s.SandboxRan = true
			s.Sandbox = SandboxOutcome{Repro: repro("panic-in-claimed-code", "fixed"), ViaFallback: true}
		}), report.OutcomeReproducedFixedAtHead, "reproduced at a fallback version", false},
		{"3c ran clean at the exact ref", sha, with(func(s *StageResults) {
			s.SandboxRan = true
			s.Sandbox = SandboxOutcome{Repro: clean, Passed: true}
		}), report.OutcomeNotReproduced, "", false},
		{"3c exact duplicate outranks NOT_REPRODUCED", sha, with(func(s *StageResults) {
			dup(s)
			s.SandboxRan = true
			s.Sandbox = SandboxOutcome{Repro: clean, Passed: true}
		}), report.OutcomeLikelyDuplicate, "the PoC ran clean", true},
		{"3c ran clean via fallback", sha, with(func(s *StageResults) {
			s.ResolvedViaFallback = true
			s.SandboxRan = true
			s.Sandbox = SandboxOutcome{Repro: clean, Passed: true, ViaFallback: true}
		}), report.OutcomeInconclusive, "ran clean against a fallback version, not the claimed commit", false},
		{"3c clean run at another ref is not NOT_REPRODUCED", sha, with(func(s *StageResults) {
			s.SandboxRan = true
			s.Sandbox = SandboxOutcome{Repro: &report.ReproResult{Ref: "0123456789abcdef0123456789abcdef01234567"}, Passed: true}
		}), report.OutcomeInconclusive, "not the commit grounding resolved", false},
		{"3c clean run with no ref is not NOT_REPRODUCED", sha, with(func(s *StageResults) {
			s.SandboxRan = true
			s.Sandbox = SandboxOutcome{Repro: &report.ReproResult{}, Passed: true}
		}), report.OutcomeInconclusive, "not the commit grounding resolved", false},
		{"3c passed without evidence is not NOT_REPRODUCED", sha, with(func(s *StageResults) {
			s.SandboxRan = true
			s.Sandbox = SandboxOutcome{Passed: true}
		}), report.OutcomeInconclusive, "sandbox: the run ended without a result", false},
		{"3d inconclusive run", sha, with(func(s *StageResults) {
			s.SandboxRan = true
			s.Sandbox = SandboxOutcome{Repro: clean, Inconclusive: "PoC does not build at this ref"}
		}), report.OutcomeInconclusive, "sandbox: PoC does not build at this ref", false},
		{"3d inconclusive run with exact duplicate", sha, with(func(s *StageResults) {
			dup(s)
			s.SandboxRan = true
			s.Sandbox = SandboxOutcome{Inconclusive: "timeout"}
		}), report.OutcomeLikelyDuplicate, "sandbox: timeout", true},
		{"3d sandbox unavailable", sha, with(func(s *StageResults) {
			s.SandboxRan = true
			s.Sandbox = SandboxOutcome{Skipped: "gVisor needs a Linux host; this host runs darwin"}
		}), report.OutcomeInconclusive, "PoC not run: gVisor needs a Linux host", false},
		{"3d no result at all", sha, with(func(s *StageResults) { s.SandboxRan = true }), report.OutcomeInconclusive, "sandbox: the run ended without a result", false},
		{"4 no PoC", sha, with(func(s *StageResults) { s.HasPoC = false }), report.OutcomeNeedsInfo, "no runnable PoC attached", false},
		{"4 no PoC, exact duplicate", sha, with(func(s *StageResults) { s.HasPoC = false; dup(s) }), report.OutcomeLikelyDuplicate, "exact claim match", true},
		{"4 no PoC, hard failure beats duplicate", sha, with(func(s *StageResults) { s.HasPoC = false; s.Claims = missing; dup(s) }), report.OutcomeGroundingFailed, "", true},
		{"4 no PoC, duplicate via fallback is a lead", sha, with(func(s *StageResults) { s.HasPoC = false; s.ResolvedViaFallback = true; dup(s) }), report.OutcomeNeedsInfo, "recorded as a lead", true},
		{"4 PoC, no sandbox", sha, grounded, report.OutcomeInconclusive, "PoC not run: sandbox not configured", false},
		{"4 PoC, sandbox configured but not run", sha, with(func(s *StageResults) { s.SandboxConfigured = true }), report.OutcomeInconclusive, "PoC not run: the sandbox stage did not run", false},
		{"4 PoC, no sandbox, exact duplicate", sha, with(dup), report.OutcomeLikelyDuplicate, "", true},
		{"4 no grounder, no PoC", sha, StageResults{}, report.OutcomeNeedsInfo, "no runnable PoC attached", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := Compose(report.Report{ID: "R1", ClaimedRef: tt.ref}, tt.res)
			if v.Outcome != tt.want {
				t.Fatalf("Outcome = %s, want %s (notes %q)", v.Outcome, tt.want, v.Notes)
			}
			notes := strings.Join(v.Notes, "\n")
			if tt.wantNote != "" && !strings.Contains(notes, tt.wantNote) {
				t.Errorf("Notes = %q, want one containing %q", v.Notes, tt.wantNote)
			}
			if strings.Contains(notes, "not implemented yet") {
				t.Errorf("Notes = %q still carry the old sandbox-not-implemented note", v.Notes)
			}
			if tt.dupsKept && len(v.Duplicates) != 1 {
				t.Errorf("Duplicates = %+v, want the match still listed", v.Duplicates)
			}
			// Repro is evidence only for outcomes reached from a run:
			// never when the stage did not run or was skipped, and never
			// on GROUNDING_FAILED or NEEDS_INFO.
			sb := tt.res.Sandbox
			wantRepro := tt.res.SandboxRan && sb.Skipped == "" && sb.Repro != nil &&
				v.Outcome != report.OutcomeGroundingFailed && v.Outcome != report.OutcomeNeedsInfo
			if wantRepro && v.Repro != sb.Repro {
				t.Errorf("Repro = %+v, want the sandbox evidence carried through", v.Repro)
			}
			if !wantRepro && v.Repro != nil {
				t.Errorf("Repro = %+v, want nil", v.Repro)
			}
		})
	}
}

func TestRenderRepro(t *testing.T) {
	const sha = "e1fcd82abba34df74614020343be8eb1fe85f0d9"
	r := report.Report{ID: "R1", Repo: "a/b", ClaimedRef: sha}
	tests := []struct {
		name    string
		v       report.Verdict
		want    []string
		notWant []string
	}{
		{"strong, fixed", report.Verdict{Outcome: report.OutcomeReproducedFixedAtHead,
			Repro: &report.ReproResult{Ref: sha, Reproduced: true, Signal: "panic-in-claimed-code", ControlState: "fixed"}},
			[]string{"• PoC: reproduced via panic-in-claimed-code at e1fcd82abba3\n", "• control at HEAD: fixed\n", pocOutputNote + "\n"},
			[]string{"weak"}},
		{"weak, fixed", report.Verdict{Outcome: report.OutcomeReproducedFixedAtHead,
			Repro: &report.ReproResult{Ref: sha, Reproduced: true, Signal: weakSignal, ControlState: "fixed"}},
			[]string{"• PoC: reproduced via " + weakSignal + " at e1fcd82abba3 (weak: assertion-only failure)\n"}, nil},
		{"weak bare kind, fixed", report.Verdict{Outcome: report.OutcomeReproducedFixedAtHead,
			Repro: &report.ReproResult{Ref: sha, Reproduced: true, Signal: SignalFailingTest, ControlState: "fixed"}},
			[]string{"(weak: assertion-only failure)\n"}, nil},
		{"lookalike kind is not weak", report.Verdict{Outcome: report.OutcomeReproducedFixedAtHead,
			Repro: &report.ReproResult{Ref: sha, Reproduced: true, Signal: SignalFailingTest + "-x: detail", ControlState: "fixed"}},
			nil, []string{"weak"}},
		{"still reproduces", report.Verdict{Outcome: report.OutcomeReproduced,
			Repro: &report.ReproResult{Ref: sha, Reproduced: true, Signal: "race-in-claimed-code", ControlState: "still_reproduces"}},
			[]string{"• control at HEAD: still reproduces\n"}, nil},
		{"control unavailable", report.Verdict{Outcome: report.OutcomeReproduced,
			Repro: &report.ReproResult{Ref: sha, Reproduced: true, Signal: "panic-in-claimed-code", ControlState: "unavailable"}},
			[]string{"• control at HEAD: could not be re-run\n"}, nil},
		{"ran clean", report.Verdict{Outcome: report.OutcomeNotReproduced, Repro: &report.ReproResult{Ref: sha, Signal: "none"}},
			[]string{"• PoC ran clean at e1fcd82abba3\n"}, []string{pocOutputNote, "control at HEAD"}},
		{"inconclusive run", report.Verdict{Outcome: report.OutcomeInconclusive, Repro: &report.ReproResult{Ref: sha, Signal: "none"}},
			nil, []string{"PoC ran clean", pocOutputNote}},
		{"hostile values", report.Verdict{Outcome: report.OutcomeReproduced,
			Repro: &report.ReproResult{Ref: "v1\x1b[2J", Reproduced: true, Signal: "panic\u202e\x07"}},
			[]string{"• PoC: reproduced via panic�� at v1�[2J\n"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.v.ReportID = "R1"
			out := Render(r, tt.v)
			for _, w := range tt.want {
				if !strings.Contains(out, w) {
					t.Errorf("Render missing %q:\n%s", w, out)
				}
			}
			for _, w := range tt.notWant {
				if strings.Contains(out, w) {
					t.Errorf("Render has %q:\n%s", w, out)
				}
			}
			if strings.ContainsAny(out, "\x1b\x07\u202e") {
				t.Fatalf("control characters leaked: %q", out)
			}
		})
	}
}

// The verdict, and its rendering, never carry PoC evidence that
// contradicts the outcome: evidence from a run the outcome was not
// derived from is dropped, and Render keys off the outcome.
func TestComposeReproNeverContradictsOutcome(t *testing.T) {
	const sha = "e1fcd82abba34df74614020343be8eb1fe85f0d9"
	reproduced := func() *report.ReproResult {
		return &report.ReproResult{Ref: sha, Reproduced: true, Signal: "panic-in-claimed-code", ControlState: "fixed"}
	}
	missing := []report.Claim{{Kind: report.ClaimFunction, Value: "x", Verified: report.TriNo}}
	tests := []struct {
		name string
		res  StageResults
		want report.Outcome
	}{
		{"sandbox not run, repro present", StageResults{GroundingRan: true, RefResolved: true, ResolvedRef: sha,
			Sandbox: SandboxOutcome{Repro: reproduced()}}, report.OutcomeNeedsInfo},
		{"sandbox not run, PoC, repro present", StageResults{GroundingRan: true, RefResolved: true, ResolvedRef: sha, HasPoC: true,
			Sandbox: SandboxOutcome{Repro: reproduced()}}, report.OutcomeInconclusive},
		{"hard grounding failure, sandbox ran", StageResults{GroundingRan: true, RefResolved: true, ResolvedRef: sha, HasPoC: true, Claims: missing,
			SandboxRan: true, Sandbox: SandboxOutcome{Repro: reproduced()}}, report.OutcomeGroundingFailed},
		{"PoC needs info, repro present", StageResults{GroundingRan: true, RefResolved: true, ResolvedRef: sha, HasPoC: true,
			SandboxRan: true, Sandbox: SandboxOutcome{NeedsInfo: "bad PoC", Repro: reproduced()}}, report.OutcomeNeedsInfo},
		{"skipped, repro present", StageResults{GroundingRan: true, RefResolved: true, ResolvedRef: sha, HasPoC: true,
			SandboxRan: true, Sandbox: SandboxOutcome{Skipped: "no rootfs", Repro: reproduced()}}, report.OutcomeInconclusive},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := report.Report{ID: "R1", Repo: "a/b", ClaimedRef: sha}
			v := Compose(r, tt.res)
			if v.Outcome != tt.want {
				t.Fatalf("Outcome = %s, want %s", v.Outcome, tt.want)
			}
			if v.Repro != nil {
				t.Errorf("Repro = %+v, want nil", v.Repro)
			}
			out := Render(r, v)
			for _, bad := range []string{"PoC: reproduced", "control at HEAD", "PoC ran clean", pocOutputNote} {
				if strings.Contains(out, bad) {
					t.Errorf("Render has %q:\n%s", bad, out)
				}
			}
		})
	}
}

// Render prints reproduction lines only for a reproduction outcome,
// even if a hand-built verdict carries a reproduced Repro.
func TestRenderKeysOffOutcome(t *testing.T) {
	const sha = "e1fcd82abba34df74614020343be8eb1fe85f0d9"
	r := report.Report{ID: "R1", Repo: "a/b", ClaimedRef: sha}
	rr := &report.ReproResult{Ref: sha, Reproduced: true, Signal: "panic-in-claimed-code", ControlState: "fixed"}
	for _, o := range []report.Outcome{report.OutcomeNeedsInfo, report.OutcomeGroundingFailed, report.OutcomeInconclusive, report.OutcomeLikelyDuplicate} {
		out := Render(r, report.Verdict{ReportID: "R1", Outcome: o, Repro: rr})
		if strings.Contains(out, "PoC: reproduced") || strings.Contains(out, "control at HEAD") || strings.Contains(out, "PoC ran clean") {
			t.Errorf("%s: Render shows repro lines:\n%s", o, out)
		}
	}
	out := Render(r, report.Verdict{ReportID: "R1", Outcome: report.OutcomeNotReproduced, Repro: &report.ReproResult{Ref: sha}})
	if !strings.Contains(out, "• PoC ran clean at e1fcd82abba3\n") || strings.Contains(out, "PoC: reproduced") {
		t.Errorf("NOT_REPRODUCED render wrong:\n%s", out)
	}
}
