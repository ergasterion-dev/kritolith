// Package verdict composes and renders Kritolith verdicts.
package verdict

import (
	"fmt"
	"strings"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// StageResults carries the outputs of pipeline stages that have run so
// far. It grows one field per milestone; each addition is a
// non-breaking change as long as callers use named-field struct
// literals.
type StageResults struct {
	Claims []report.Claim
	// LLMUnavailable is true when the pipeline configured an LLM
	// extraction chain but every provider in it failed, so the
	// verdict's claims are deterministic-only even though an operator
	// expected LLM-assisted extraction. It's false, and produces no
	// note, when no LLM was configured at all (the normal, expected,
	// non-error state).
	LLMUnavailable bool
	// GroundingRan is true when a Grounder was configured and called.
	// It's false (the zero value) when no grounder was wired in at
	// all — a caller that never sets it up keeps Week 2's behavior
	// exactly (no NEEDS_INFO/GROUNDING_FAILED path from this stage).
	GroundingRan bool
	// RefResolved is true when the claimed ref (or a fallback
	// ClaimVersion value) resolved to a commit. Only meaningful when
	// GroundingRan is true.
	RefResolved bool
	// ResolvedRef is the commit grounding actually checked claims
	// against, if RefResolved.
	ResolvedRef string
}

// Compose builds the verdict from the stage results available so far.
// Precedence: no ref given -> NEEDS_INFO; a ref given but grounding
// couldn't resolve it (or any fallback) -> NEEDS_INFO; a hard claim
// (file or function) that grounding found missing -> GROUNDING_FAILED,
// never on a line-only mismatch; otherwise INCONCLUSIVE, since dedupe
// and sandbox aren't implemented yet.
func Compose(r report.Report, res StageResults) report.Verdict {
	v := report.Verdict{ReportID: r.ID, Claims: res.Claims}
	switch {
	case r.ClaimedRef == "":
		v.Outcome = report.OutcomeNeedsInfo
		v.Notes = append(v.Notes, "no commit or tag given; can't check claims against the code")
	case res.GroundingRan && !res.RefResolved:
		v.Outcome = report.OutcomeNeedsInfo
		v.Notes = append(v.Notes, "claimed ref did not resolve to a commit in the repository")
	case res.GroundingRan && hardClaimFailed(res.Claims):
		v.Outcome = report.OutcomeGroundingFailed
		v.Notes = append(v.Notes, "a claimed file or function does not exist at the resolved commit")
	default:
		v.Outcome = report.OutcomeInconclusive
		v.Notes = append(v.Notes, "dedupe and sandbox stages are not implemented yet")
	}
	if res.LLMUnavailable {
		v.Notes = append(v.Notes, "LLM extraction unavailable; deterministic claims only")
	}
	return v
}

// hardClaimFailed reports whether any hard claim (file or function)
// was checked and found missing. A line claim (soft) is never
// consulted here, regardless of its own Verified value.
func hardClaimFailed(claims []report.Claim) bool {
	for _, c := range claims {
		if (c.Kind == report.ClaimFile || c.Kind == report.ClaimFunction) && c.Verified == report.TriNo {
			return true
		}
	}
	return false
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
