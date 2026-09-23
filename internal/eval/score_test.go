package eval

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

func TestRunAndScore(t *testing.T) {
	cases := []Case{
		{ID: "r1", Kind: KindReal, Meta: Meta{Expected: report.OutcomeReproducedFixedAtHead}},
		{ID: "r2", Kind: KindReal, Meta: Meta{Expected: report.OutcomeReproduced}},
		{ID: "f1", Kind: KindFabricated, Meta: Meta{Expected: report.OutcomeGroundingFailed}},
		{ID: "f2", Kind: KindFabricated, Meta: Meta{Expected: report.OutcomeGroundingFailed}},
		{ID: "f3", Kind: KindFabricated, Meta: Meta{Expected: report.OutcomeNeedsInfo}},
	}
	got := map[string]report.Outcome{
		"r1": report.OutcomeReproducedFixedAtHead,
		"r2": report.OutcomeGroundingFailed, // the worst possible bug
		"f1": report.OutcomeGroundingFailed,
		"f2": report.OutcomeInconclusive,
	}
	sb := Run(context.Background(), cases, func(_ context.Context, c Case) (report.Outcome, error) {
		if c.ID == "f3" {
			return "", errors.New("boom")
		}
		return got[c.ID], nil
	})
	if sb.Matches() != 2 {
		t.Errorf("Matches = %d, want 2", sb.Matches())
	}
	if sb.RealGroundingFailures() != 1 {
		t.Errorf("RealGroundingFailures = %d, want 1", sb.RealGroundingFailures())
	}
	if c, n := sb.FabricatedCaught(); c != 1 || n != 2 {
		t.Errorf("FabricatedCaught = %d/%d, want 1/2", c, n)
	}
	if sb.Errors() != 1 || !sb.Failed() {
		t.Errorf("Errors = %d Failed = %v", sb.Errors(), sb.Failed())
	}
	var buf bytes.Buffer
	if err := sb.Write(&buf); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"r2", "GROUNDING_FAILED", "must be 0", "boom", "1/2"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("scoreboard missing %q:\n%s", want, buf.String())
		}
	}
}

// TestScoreboardWriteSanitizesError verifies that a hostile error string
// (e.g. from a PoC filename) never reaches the table with raw escape
// bytes intact.
func TestScoreboardWriteSanitizesError(t *testing.T) {
	sb := Scoreboard{Results: []Result{
		{Case: Case{ID: "x", Kind: KindFabricated, Meta: Meta{Expected: report.OutcomeInconclusive}}, Err: errors.New("bad \x1b[31mred\tname")},
	}}
	var buf bytes.Buffer
	if err := sb.Write(&buf); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "\x1b") {
		t.Fatalf("scoreboard output contains a raw ESC byte: %q", buf.String())
	}
}

func TestScoreboardPassing(t *testing.T) {
	sb := Scoreboard{Results: []Result{{Case: Case{ID: "f1", Kind: KindFabricated, Meta: Meta{Expected: report.OutcomeGroundingFailed}}, Got: report.OutcomeInconclusive}}}
	if sb.Failed() {
		t.Fatal("a mismatch alone must not fail the run; only real GROUNDING_FAILED or errors do")
	}
}
