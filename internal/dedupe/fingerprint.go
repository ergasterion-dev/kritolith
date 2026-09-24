// Package dedupe flags likely-duplicate reports by matching grounded
// claims against prior reports and the local OSV mirror, and by
// embedding similarity when an LLM provider is configured. Only an
// exact fingerprint match against a prior report is strong enough to
// set a report's outcome to LIKELY_DUPLICATE — a false one is exactly
// as bad as a false GROUNDING_FAILED. Weaker signals (OSV symbol
// matches, which don't yet check affected versions or vuln_class, and
// embedding similarity) are recorded as leads only.
package dedupe

import (
	"strings"

	"github.com/ergasterion-dev/kritolith/internal/ground"
	"github.com/ergasterion-dev/kritolith/internal/report"
)

// fingerprint is a normalized, exact-match-only identity for one
// (verified function claim, vuln_class claim) pair. qualifier is the
// literal "pkg"/"T" text the reporter wrote — never resolved to an
// import path, since grounding itself has no import resolution (see
// the design spec's Gap G1 discussion). All four fields must be
// non-empty for two fingerprints to match; this, plus requiring the
// same repo, is what keeps a same-named-symbol coincidence in a
// different package from producing a false duplicate.
type fingerprint struct {
	repo      string
	qualifier string
	name      string
	vulnClass string
}

// matches reports whether a and b identify the same claimed
// vulnerability.
func (a fingerprint) matches(b fingerprint) bool {
	return a.repo != "" && a.repo == b.repo &&
		a.qualifier != "" && a.qualifier == b.qualifier &&
		a.name != "" && a.name == b.name &&
		a.vulnClass != "" && a.vulnClass == b.vulnClass
}

// claimFingerprints returns every exact-tier-eligible fingerprint
// derivable from claims: the cross product of every verified
// (Verified: yes) function claim with a non-empty qualifier, and every
// vuln_class claim. A function claim with an empty qualifier (a bare
// name like "Read") never contributes — the same reasoning grounding
// itself uses for refusing to disprove bare names applies here: a bare
// name is too easily a stdlib or dependency symbol to anchor an
// identity claim on.
func claimFingerprints(repo string, claims []report.Claim) []fingerprint {
	type funcName struct{ qualifier, name string }
	var funcs []funcName
	var vulnClasses []string
	for _, c := range claims {
		switch c.Kind {
		case report.ClaimFunction:
			if c.Verified != report.TriYes {
				continue
			}
			qualifier, name := ground.SplitFunctionClaim(c.Value)
			if qualifier == "" || name == "" {
				continue
			}
			funcs = append(funcs, funcName{qualifier: qualifier, name: name})
		case report.ClaimVulnClass:
			if v := strings.ToLower(strings.TrimSpace(c.Value)); v != "" {
				vulnClasses = append(vulnClasses, v)
			}
		}
	}
	var out []fingerprint
	for _, f := range funcs {
		for _, vc := range vulnClasses {
			out = append(out, fingerprint{repo: repo, qualifier: f.qualifier, name: f.name, vulnClass: vc})
		}
	}
	return out
}
