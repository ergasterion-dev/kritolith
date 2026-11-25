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
	// HasPoC is true when the report carries a runnable PoC (an
	// explicit attachment; code blocks in the body are not run).
	HasPoC bool
	// SandboxRan is true when a sandbox runner was configured and
	// called. Sandbox is only meaningful when it is.
	SandboxRan bool
	// SandboxConfigured is true when a sandbox runner was wired in,
	// whether or not the stage ran for this report.
	SandboxConfigured bool
	Sandbox           SandboxOutcome
}

// SandboxOutcome is what the sandbox stage found, as Compose needs it.
// The pipeline converts a sandbox.Result into it, so this package does
// not import the sandbox. At most one of Skipped, NeedsInfo and
// Inconclusive is set.
type SandboxOutcome struct {
	// Repro is the evidence, set once the PoC was tried at the ref.
	Repro *report.ReproResult
	// Skipped is why the stage did not run at all (sandbox not
	// configured or unavailable on this host).
	Skipped string
	// NeedsInfo is set when the PoC is invalid or cannot be placed.
	NeedsInfo string
	// Inconclusive is why the run says nothing either way.
	Inconclusive string
	// Passed: the run at the ref exited 0 with tests completed.
	Passed bool
	// Weak: the reproduction is an assertion-only failure (signal 3).
	Weak bool
	// ViaFallback: the ref came from a fallback version.
	ViaFallback bool
}

// Compose builds the verdict from the stage results available so far.
// Precedence, highest first:
//
//  1. No ClaimedRef -> NEEDS_INFO. A ref given but grounding couldn't
//     resolve it (or any fallback) -> NEEDS_INFO.
//  2. A hard claim (file, function or package) grounding proved
//     missing: resolved only via a fallback version -> INCONCLUSIVE;
//     otherwise -> GROUNDING_FAILED (never on a line-only mismatch).
//     The PoC is not run in either case.
//  3. The sandbox stage ran (SandboxRan):
//     a. the PoC is invalid or cannot be placed -> NEEDS_INFO;
//     b. the PoC reproduced at the ref: control at HEAD fixed ->
//     REPRODUCED_FIXED_AT_HEAD; still reproduces -> REPRODUCED for a
//     strong signal; control unavailable or absent -> REPRODUCED with
//     a note that whether HEAD is fixed is unknown. A weak
//     (assertion-only) signal reproduces only with a fixed control;
//     otherwise it falls through to d with the reason. A reproduction
//     outranks an exact duplicate, which stays listed and is noted;
//     c. the PoC ran clean at the exact commit grounding resolved ->
//     NOT_REPRODUCED, unless an exact duplicate (not via a fallback)
//     exists -> LIKELY_DUPLICATE; a clean run at a fallback version, or
//     at a ref other than the resolved one, falls through to d;
//     d. anything else (inconclusive run, stage skipped, no result) ->
//     exact duplicate (not via a fallback) -> LIKELY_DUPLICATE, else
//     INCONCLUSIVE with the sandbox's reason.
//     The verdict carries the Repro evidence only on outcomes reached
//     here from a run (never on NEEDS_INFO or a skipped stage).
//  4. The sandbox stage did not run: an exact duplicate (not via a
//     fallback) -> LIKELY_DUPLICATE; else no runnable PoC (HasPoC
//     false) -> NEEDS_INFO; else (a PoC the sandbox did not run, or
//     no sandbox configured) -> INCONCLUSIVE. The verdict carries no
//     Repro here, nor on steps 1 and 2.
//
// An exact dedupe match is never an outcome when grounding resolved
// only a fallback version: the Verified: yes claims its fingerprint
// rests on were checked against a commit the reporter never named.
func Compose(r report.Report, res StageResults) report.Verdict {
	v := report.Verdict{ReportID: r.ID, Claims: res.Claims, Duplicates: res.Duplicates}
	exactDup := res.DedupeRan && res.DedupeExactMatch && !res.ResolvedViaFallback
	fallbackDup := res.DedupeRan && res.DedupeExactMatch && res.ResolvedViaFallback
	switch {
	case r.ClaimedRef == "":
		v.Outcome = report.OutcomeNeedsInfo
		v.Notes = append(v.Notes, "no commit or tag given; can't check claims against the code")
	case res.GroundingRan && !res.RefResolved:
		v.Outcome = report.OutcomeNeedsInfo
		v.Notes = append(v.Notes, "claimed ref did not resolve to a commit on a branch or tag of the repository")
	case res.GroundingRan && HardClaimFailed(res.Claims) && res.ResolvedViaFallback:
		v.Outcome = report.OutcomeInconclusive
		v.Notes = append(v.Notes, "grounded via a fallback version, not the claimed commit — treating a hard-claim failure as inconclusive rather than a rejection")
	case res.GroundingRan && HardClaimFailed(res.Claims):
		v.Outcome = report.OutcomeGroundingFailed
		v.Notes = append(v.Notes, "a claimed file, function or package does not exist at the resolved commit")
		v.Notes = append(v.Notes, "PoC not run: grounding failed on a hard claim")
	case res.SandboxRan:
		composeSandbox(&v, res, exactDup, fallbackDup)
	case exactDup:
		v.Outcome = report.OutcomeLikelyDuplicate
		v.Notes = append(v.Notes, "an exact claim match was found against a prior report")
	case !res.HasPoC:
		v.Outcome = report.OutcomeNeedsInfo
		if fallbackDup {
			v.Notes = append(v.Notes, fallbackDupNote)
		}
		v.Notes = append(v.Notes, "no runnable PoC attached")
	default:
		v.Outcome = report.OutcomeInconclusive
		if fallbackDup {
			v.Notes = append(v.Notes, fallbackDupNote)
		}
		if res.SandboxConfigured {
			v.Notes = append(v.Notes, "PoC not run: the sandbox stage did not run")
		} else {
			v.Notes = append(v.Notes, "PoC not run: sandbox not configured")
		}
	}
	if res.LLMUnavailable {
		v.Notes = append(v.Notes, "LLM extraction unavailable; deterministic claims only")
	}
	return v
}

const fallbackDupNote = "grounded via a fallback version, not the claimed commit — an exact duplicate match is recorded as a lead, not a verdict"

// composeSandbox sets the outcome for a report the sandbox stage ran
// on (Compose's step 3). v.Repro is set only when the outcome comes
// from what the sandbox ran: never on NEEDS_INFO, and never when the
// stage was skipped.
func composeSandbox(v *report.Verdict, res StageResults, exactDup, fallbackDup bool) {
	sb := res.Sandbox
	viaFallback := sb.ViaFallback || res.ResolvedViaFallback
	rr := sb.Repro
	if sb.NeedsInfo != "" {
		v.Outcome = report.OutcomeNeedsInfo
		v.Notes = append(v.Notes, "PoC not run: "+sb.NeedsInfo)
		return
	}
	ran := sb.Skipped == "" && sb.Inconclusive == "" && rr != nil
	var reason string // why a run that looked conclusive is not
	switch {
	case ran && rr.Reproduced:
		weak := sb.Weak || isWeakSignal(rr.Signal)
		switch {
		case rr.ControlState == ControlFixed:
			v.Outcome = report.OutcomeReproducedFixedAtHead
		case weak && rr.ControlState == ControlStillReproduces:
			// The Runner reports these as inconclusive itself; this
			// is the defensive twin of that rule.
			reason = weakAtHeadNote
		case weak:
			reason = "an assertion-only failure counts only when the same PoC passes at HEAD, and the PoC could not be re-run at HEAD"
		case rr.ControlState == ControlStillReproduces:
			v.Outcome = report.OutcomeReproduced
		default:
			v.Outcome = report.OutcomeReproduced
			v.Notes = append(v.Notes, "could not be re-run at HEAD; whether it is fixed is unknown")
		}
		if v.Outcome != "" {
			v.Repro = rr
			if viaFallback {
				v.Notes = append(v.Notes, "reproduced at a fallback version, not the exact claimed commit")
			}
			if exactDup {
				v.Notes = append(v.Notes, "the report also exactly matches an earlier report; see the possible duplicates")
			}
			if fallbackDup {
				v.Notes = append(v.Notes, fallbackDupNote)
			}
			return
		}
	case ran && sb.Passed && viaFallback:
		reason = "ran clean against a fallback version, not the claimed commit"
	case ran && sb.Passed && (res.ResolvedRef == "" || rr.Ref != res.ResolvedRef):
		reason = "the clean run's ref is not the commit grounding resolved"
	case ran && sb.Passed:
		v.Repro = rr
		if exactDup {
			v.Outcome = report.OutcomeLikelyDuplicate
			v.Notes = append(v.Notes, "an exact claim match was found against a prior report", "the PoC ran clean at the claimed commit")
			return
		}
		v.Outcome = report.OutcomeNotReproduced
		v.Notes = append(v.Notes, "the PoC ran to completion and exited 0; the claimed behaviour was not observed")
		return
	}
	if exactDup {
		v.Outcome = report.OutcomeLikelyDuplicate
		v.Notes = append(v.Notes, "an exact claim match was found against a prior report")
	} else {
		v.Outcome = report.OutcomeInconclusive
	}
	switch {
	case reason != "":
		v.Notes = append(v.Notes, "sandbox: "+reason)
	case sb.Skipped != "":
		v.Notes = append(v.Notes, "PoC not run: "+sb.Skipped)
	case sb.Inconclusive != "":
		v.Notes = append(v.Notes, "sandbox: "+sb.Inconclusive)
	default:
		v.Notes = append(v.Notes, "sandbox: the run ended without a result")
	}
	if sb.Skipped == "" {
		v.Repro = rr // evidence of what ran, if anything
	}
	if fallbackDup {
		v.Notes = append(v.Notes, fallbackDupNote)
	}
}

// Control states and signal kinds as the sandbox records them in a
// ReproResult. This package does not import internal/sandbox; a
// pipeline test keeps these equal to the sandbox's constants.
const (
	ControlFixed           = "fixed"
	ControlStillReproduces = "still_reproduces"
	// SignalFailingTest is the weak, assertion-only signal: it counts
	// only when the control at HEAD is fixed.
	SignalFailingTest = "failing-test-reaching-claimed-code"
)

const (
	weakAtHeadNote = "the PoC also fails at HEAD, and an assertion-only failure cannot be told from a test that always fails"
	pocOutputNote  = "Note: a PoC controls its own output; read the PoC before trusting this evidence."
)

// HardClaimFailed reports whether any hard claim (file or function)
// was checked and found missing. A line claim (soft) is never
// consulted here, regardless of its own Verified value. This relies on
// grounding's contract that Verified: no means absence was proven, not
// merely that no declaration matched: a claim grounding can't disprove
// (a dependency's function, a field, an exported name that may live in
// another package) comes back unknown and never reaches this check.
func HardClaimFailed(claims []report.Claim) bool {
	for _, c := range claims {
		if (c.Kind == report.ClaimFile || c.Kind == report.ClaimFunction || c.Kind == report.ClaimPackage) && c.Verified == report.TriNo {
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
	renderRepro(&b, v)
	renderReproNotes(&b, v)
	for _, n := range v.Notes {
		fmt.Fprintf(&b, "• %s\n", report.Printable(n))
	}
	fmt.Fprintf(&b, "Report: %s (%s)\n", report.Printable(r.ID), report.Printable(r.Repo))
	if len(v.Signature) > 0 {
		fmt.Fprintf(&b, "Signed: %s (ed25519)\n", v.SignedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	return b.String()
}

// isWeakSignal reports whether a ReproResult.Signal is the weak,
// assertion-only signal. The sandbox writes "<kind>: <detail>", so the
// kind is matched as a prefix followed by ':' or the end of the string;
// a longer kind that merely starts with the same text does not match.
func isWeakSignal(sig string) bool {
	rest, ok := strings.CutPrefix(sig, SignalFailingTest)
	return ok && (rest == "" || rest[0] == ':')
}

// renderRepro writes the PoC evidence lines, keyed off the outcome:
// reproduction lines only for a reproduction outcome, a clean-run line
// only for NOT_REPRODUCED, and nothing otherwise (the notes say why). Every value in a
// ReproResult came through the sandbox from a hostile PoC's run, so
// each one is passed through report.Printable.
func renderRepro(b *strings.Builder, v report.Verdict) {
	rr := v.Repro
	if rr == nil {
		return
	}
	ref := report.Printable(shortRef(rr.Ref))
	switch v.Outcome {
	case report.OutcomeReproduced, report.OutcomeReproducedFixedAtHead:
		fmt.Fprintf(b, "• PoC: reproduced via %s at %s", report.Printable(rr.Signal), ref)
		if isWeakSignal(rr.Signal) {
			b.WriteString(" (weak: assertion-only failure)")
		}
		b.WriteString("\n")
		switch rr.ControlState {
		case ControlFixed:
			b.WriteString("• control at HEAD: fixed\n")
		case ControlStillReproduces:
			b.WriteString("• control at HEAD: still reproduces\n")
		default:
			b.WriteString("• control at HEAD: could not be re-run\n")
		}
		b.WriteString(pocOutputNote + "\n")
	case report.OutcomeNotReproduced:
		fmt.Fprintf(b, "• PoC ran clean at %s\n", ref)
	}
}

// renderReproNotes writes the sandbox's own notes on the run (the race
// detector was unavailable, cgroup limits were not in force, ...) for
// every outcome that carries a Repro: they qualify what the run shows,
// whatever the outcome. A note the composed notes already carry, as is
// or as "sandbox: <note>", and repeats are written once.
func renderReproNotes(b *strings.Builder, v report.Verdict) {
	if v.Repro == nil {
		return
	}
	seen := map[string]bool{}
	for _, n := range v.Notes {
		seen[n] = true
	}
	for _, n := range v.Repro.Notes {
		if n == "" || seen[n] || seen["sandbox: "+n] {
			continue
		}
		seen[n] = true
		fmt.Fprintf(b, "• sandbox note: %s\n", report.Printable(n))
	}
}

func shortRef(ref string) string {
	if report.IsFullSHA(ref) {
		return ref[:12]
	}
	return ref
}
