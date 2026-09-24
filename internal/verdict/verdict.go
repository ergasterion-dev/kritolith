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
	// ResolvedViaFallback is true when the claimed ref itself didn't
	// resolve and grounding checked claims against a fallback version
	// mentioned in the report instead. That commit isn't the one the
	// reporter named, and a short hex-looking "version" can coincidentally
	// resolve to an unrelated commit, so a hard-claim failure against it
	// is never strong enough to reject the report on.
	ResolvedViaFallback bool
	// Module is the resolved commit's go.mod module path, populated by
	// grounding; empty when ungrounded or the repo has no go.mod. Week
	// 4's dedupe uses it to match a report's own code against the local
	// OSV mirror, which is keyed by Go module path, not GitHub repo.
	Module string
	// DedupeRan is true when a Deduper was configured and called. Only
	// meaningful together with DedupeExactMatch and Duplicates.
	DedupeRan bool
	// DedupeExactMatch is true when dedupe found an exact fingerprint
	// match against a prior report — the only dedupe signal strong
	// enough to set Outcome (OSV symbol and embedding matches are leads).
	DedupeExactMatch bool
	// Duplicates holds up to the top 3 candidate matches dedupe found,
	// one per matched report or advisory, exact-tier first then by
	// score — including OSV and embedding leads that never change
	// Outcome, kept here for maintainer visibility.
	Duplicates []report.DupMatch
}

// Compose builds the verdict from the stage results available so far.
// Precedence: no ref given -> NEEDS_INFO; a ref given but grounding
// couldn't resolve it (or any fallback) -> NEEDS_INFO; a hard claim
// (file or function) that grounding found missing -> GROUNDING_FAILED,
// never on a line-only mismatch, and never when grounding resolved only
// a fallback version rather than the claimed ref (that case is
// INCONCLUSIVE); an exact dedupe match -> LIKELY_DUPLICATE, checked
// only after all of the above grounding branches, so a hard-claim
// failure always wins over a dedupe match and a fallback-resolved
// hard-claim failure stays INCONCLUSIVE rather than being upgraded by
// dedupe, and an exact dedupe match is itself withheld when grounding
// resolved only a fallback version (the Verified: yes claims its
// fingerprint rests on were checked against a commit the reporter never
// named); otherwise INCONCLUSIVE, since sandbox isn't implemented yet.
func Compose(r report.Report, res StageResults) report.Verdict {
	v := report.Verdict{ReportID: r.ID, Claims: res.Claims, Duplicates: res.Duplicates}
	switch {
	case r.ClaimedRef == "":
		v.Outcome = report.OutcomeNeedsInfo
		v.Notes = append(v.Notes, "no commit or tag given; can't check claims against the code")
	case res.GroundingRan && !res.RefResolved:
		v.Outcome = report.OutcomeNeedsInfo
		v.Notes = append(v.Notes, "claimed ref did not resolve to a commit in the repository")
	case res.GroundingRan && hardClaimFailed(res.Claims) && res.ResolvedViaFallback:
		v.Outcome = report.OutcomeInconclusive
		v.Notes = append(v.Notes, "grounded via a fallback version, not the claimed commit — treating a hard-claim failure as inconclusive rather than a rejection")
	case res.GroundingRan && hardClaimFailed(res.Claims):
		v.Outcome = report.OutcomeGroundingFailed
		v.Notes = append(v.Notes, "a claimed file or function does not exist at the resolved commit")
	case res.DedupeRan && res.DedupeExactMatch && !res.ResolvedViaFallback:
		v.Outcome = report.OutcomeLikelyDuplicate
		v.Notes = append(v.Notes, "an exact claim match was found against a prior report")
	default:
		v.Outcome = report.OutcomeInconclusive
		if res.DedupeRan && res.DedupeExactMatch && res.ResolvedViaFallback {
			v.Notes = append(v.Notes, "grounded via a fallback version, not the claimed commit — an exact duplicate match is recorded as a lead, not a verdict")
		}
		v.Notes = append(v.Notes, "sandbox stage is not implemented yet")
	}
	if res.LLMUnavailable {
		v.Notes = append(v.Notes, "LLM extraction unavailable; deterministic claims only")
	}
	return v
}

// hardClaimFailed reports whether any hard claim (file or function)
// was checked and found missing. A line claim (soft) is never
// consulted here, regardless of its own Verified value. This relies on
// grounding's contract that Verified: no means absence was proven, not
// merely that no declaration matched: a claim grounding can't disprove
// (a dependency's function, a field, an exported name that may live in
// another package) comes back unknown and never reaches this check.
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
	for _, d := range v.Duplicates {
		kind, id := "report", d.ReportID
		if id == "" {
			kind, id = "advisory", d.AdvisoryID
		}
		fmt.Fprintf(&b, "• possible duplicate: %s %s (score %.2f) — %s\n",
			kind, report.Printable(id), d.Score, report.Printable(d.Evidence))
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
