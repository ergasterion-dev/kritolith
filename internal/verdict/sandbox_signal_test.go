package verdict_test

import (
	"strings"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/report"
	"github.com/ergasterion-dev/kritolith/internal/sandbox"
	"github.com/ergasterion-dev/kritolith/internal/verdict"
)

// The sandbox Runner writes ReproResult.Signal as "<kind>: <detail>"
// (internal/sandbox/phases.go, signalText). Compose and Render must read
// that shape: the weak fallback and the "(weak: ...)" label key off the
// kind, even when SandboxOutcome.Weak is not set.
func TestComposeRenderSandboxShapedSignal(t *testing.T) {
	const sha = "e1fcd82abba34df74614020343be8eb1fe85f0d9"
	if sandbox.KindFailingTest != verdict.SignalFailingTest {
		t.Fatalf("sandbox kind %q and verdict signal %q drifted apart", sandbox.KindFailingTest, verdict.SignalFailingTest)
	}
	// Exactly the Runner's signalText format.
	weak := sandbox.KindFailingTest + ": " + "TestPoC failed, and coverage shows claimed code executed: vuln/vuln.go:4.27,6.2"
	strong := sandbox.KindPanic + ": " + "example.com/m/vuln.Parse at /src/vuln/vuln.go:5"
	tests := []struct {
		name      string
		signal    string
		control   string
		want      report.Outcome
		wantLabel bool
	}{
		{"weak, control fixed", weak, sandbox.ControlFixed, report.OutcomeReproducedFixedAtHead, true},
		{"weak, control still reproduces", weak, sandbox.ControlStillReproduces, report.OutcomeInconclusive, false},
		{"weak, control unavailable", weak, sandbox.ControlUnavailable, report.OutcomeInconclusive, false},
		{"strong, control fixed", strong, sandbox.ControlFixed, report.OutcomeReproducedFixedAtHead, false},
		{"strong, control unavailable", strong, sandbox.ControlUnavailable, report.OutcomeReproduced, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := report.Report{ID: "R1", Repo: "a/b", ClaimedRef: sha}
			res := verdict.StageResults{
				GroundingRan: true, RefResolved: true, ResolvedRef: sha, HasPoC: true,
				SandboxConfigured: true, SandboxRan: true,
				// Weak deliberately unset: the signal alone must say so.
				Sandbox: verdict.SandboxOutcome{Repro: &report.ReproResult{
					Ref: sha, Reproduced: true, Signal: tt.signal, Phase: sandbox.PhaseControl, ControlState: tt.control,
				}},
			}
			v := verdict.Compose(r, res)
			if v.Outcome != tt.want {
				t.Fatalf("Outcome = %s, want %s (notes %q)", v.Outcome, tt.want, v.Notes)
			}
			out := verdict.Render(r, v)
			if got := strings.Contains(out, "(weak: assertion-only failure)"); got != tt.wantLabel {
				t.Fatalf("weak label shown = %v, want %v:\n%s", got, tt.wantLabel, out)
			}
		})
	}
}
