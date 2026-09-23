// Package verdict composes and renders Kritolith verdicts.
package verdict

import (
	"fmt"
	"strings"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// Compose builds the verdict from the stage results available so far.
// Until grounding, dedupe and sandbox exist, the only decidable case is
// a missing ref (NEEDS_INFO); everything else is INCONCLUSIVE, never a
// rejection.
func Compose(r report.Report) report.Verdict {
	v := report.Verdict{ReportID: r.ID}
	if r.ClaimedRef == "" {
		v.Outcome = report.OutcomeNeedsInfo
		v.Notes = []string{"no commit or tag given; can't check claims against the code"}
		return v
	}
	v.Outcome = report.OutcomeInconclusive
	v.Notes = []string{"grounding, dedupe and sandbox stages are not implemented yet"}
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
