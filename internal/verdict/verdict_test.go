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
