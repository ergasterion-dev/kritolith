package verdict

import (
	"strings"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

func TestCompose(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want report.Outcome
	}{
		{"with ref", "e1fcd82abba34df74614020343be8eb1fe85f0d9", report.OutcomeInconclusive},
		{"no ref", "", report.OutcomeNeedsInfo},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := Compose(report.Report{ID: "R1", ClaimedRef: tt.ref}, StageResults{})
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
	out := Render(r, Compose(r, StageResults{}))
	if !strings.HasPrefix(out, "Kritolith: INCONCLUSIVE at e1fcd82abba3\n") {
		t.Errorf("header wrong:\n%s", out)
	}
	if !strings.Contains(out, "Report: R1 (golang/net)") {
		t.Errorf("missing report line:\n%s", out)
	}

	tag := report.Report{ID: "R2", Repo: "a/b", ClaimedRef: "v1.2.3"}
	if out := Render(tag, Compose(tag, StageResults{})); !strings.HasPrefix(out, "Kritolith: INCONCLUSIVE at v1.2.3\n") {
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
	v := Compose(report.Report{ID: "R1", ClaimedRef: "v1"}, StageResults{Claims: claims, GroundingRan: true, RefResolved: true})
	if v.Outcome != report.OutcomeInconclusive {
		t.Errorf("Outcome = %s, want INCONCLUSIVE (a line claim alone must never cause GROUNDING_FAILED)", v.Outcome)
	}
}

func TestComposeGroundingSucceededNoHardFailure(t *testing.T) {
	claims := []report.Claim{{Kind: report.ClaimFile, Value: "a.go", Verified: report.TriYes}}
	v := Compose(report.Report{ID: "R1", ClaimedRef: "v1"}, StageResults{Claims: claims, GroundingRan: true, RefResolved: true})
	if v.Outcome != report.OutcomeInconclusive {
		t.Errorf("Outcome = %s, want INCONCLUSIVE", v.Outcome)
	}
}

func TestComposeNoGrounderConfiguredIsUnaffected(t *testing.T) {
	// GroundingRan defaults to false (the zero value) when no Grounder
	// was wired into the pipeline at all — this must behave exactly
	// like Week 2 (no regression for callers that don't configure one).
	v := Compose(report.Report{ID: "R1", ClaimedRef: "v1"}, StageResults{})
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
