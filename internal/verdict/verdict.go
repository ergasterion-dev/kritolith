// Package verdict composes and renders Kritolith verdicts.
package verdict

import (
	"fmt"
	"strings"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// StageResults carries the outputs of pipeline stages that have run so
// far. It grows one field per milestone (a Grounding field in Week 3,
// Dedupe in Week 4, Repro in Week 5/6); each addition is a
// non-breaking change as long as callers use named-field struct
// literals, which is why this signature changes once, here, rather
// than being widened piecemeal every week.
type StageResults struct {
	Claims []report.Claim
	// LLMUnavailable is true when the pipeline configured an LLM
	// extraction chain but every provider in it failed, so the
	// verdict's claims are deterministic-only even though an operator
	// expected LLM-assisted extraction. It's false, and produces no
	// note, when no LLM was configured at all (the normal, expected,
	// non-error state).
	LLMUnavailable bool
}

// Compose builds the verdict from the stage results available so far.
// Until grounding, dedupe and sandbox exist, the only decidable case is
// a missing ref (NEEDS_INFO); everything else is INCONCLUSIVE, never a
// rejection.
func Compose(r report.Report, res StageResults) report.Verdict {
	v := report.Verdict{ReportID: r.ID, Claims: res.Claims}
	if r.ClaimedRef == "" {
		v.Outcome = report.OutcomeNeedsInfo
		v.Notes = append(v.Notes, "no commit or tag given; can't check claims against the code")
	} else {
		v.Outcome = report.OutcomeInconclusive
		v.Notes = append(v.Notes, "grounding, dedupe and sandbox stages are not implemented yet")
	}
	if res.LLMUnavailable {
		v.Notes = append(v.Notes, "LLM extraction unavailable; deterministic claims only")
	}
	return v
}

// Render formats a verdict as the short plain-text summary maintainers
// read. Every value that could come from a report is passed through
// report.Printable.
func Render(r report.Report, v report.Verdict) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Kritolith: %s", v.Outcome)
	if r.ClaimedRef != "" {
		fmt.Fprintf(&b, " at %s", report.Printable(shortRef(r.ClaimedRef)))
	}
	b.WriteString("\n")
	for _, c := range v.Claims {
		fmt.Fprintf(&b, "• %s %s — %s\n", report.Printable(string(c.Kind)), report.Printable(c.Value), report.Printable(c.Evidence))
	}
	for _, n := range v.Notes {
		fmt.Fprintf(&b, "• %s\n", report.Printable(n))
	}
	fmt.Fprintf(&b, "Report: %s (%s)\n", report.Printable(r.ID), report.Printable(r.Repo))
	return b.String()
}

func shortRef(ref string) string {
	if report.IsFullSHA(ref) {
		return ref[:12]
	}
	return ref
}
