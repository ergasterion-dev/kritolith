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

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// fingerprint is a normalized, exact-match-only identity for one
// (resolved function declaration, vuln_class claim) pair. pkgDir,
// receiver, and name come from where grounding actually found the
// declaration — never from the claim's literal written text — and
// only when that declaration is unique in the repo (see
// ground.resolveUnique, via report.Claim.DeclPkgDir/DeclReceiver/DeclName):
// a claim whose resolution is ambiguous carries no declaration
// identity at all and can never fingerprint. repo, pkgDir, name, and
// vulnClass must all be non-empty for two fingerprints to match;
// receiver may legitimately be empty on both sides (a plain function,
// not an unresolved one).
type fingerprint struct {
	repo      string
	pkgDir    string
	receiver  string
	name      string
	vulnClass string
}

// matches reports whether a and b identify the same claimed
// vulnerability.
func (a fingerprint) matches(b fingerprint) bool {
	return a.repo != "" && a.repo == b.repo &&
		a.pkgDir != "" && a.pkgDir == b.pkgDir &&
		a.receiver == b.receiver &&
		a.name != "" && a.name == b.name &&
		a.vulnClass != "" && a.vulnClass == b.vulnClass
}

// claimFingerprints returns every exact-tier-eligible fingerprint
// derivable from claims: the cross product of every verified
// (Verified: yes) function claim whose declaration grounding resolved
// uniquely (DeclPkgDir and DeclName both set — see
// ground.groundFunctionClaim) with every vuln_class claim. A function
// claim grounding couldn't resolve to one unambiguous declaration
// never contributes, regardless of whether the claim text itself was
// qualified or bare.
func claimFingerprints(repo string, claims []report.Claim) []fingerprint {
	type decl struct{ pkgDir, receiver, name string }
	var funcs []decl
	var vulnClasses []string
	for _, c := range claims {
		switch c.Kind {
		case report.ClaimFunction:
			if c.Verified != report.TriYes {
				continue
			}
			if c.DeclPkgDir == "" || c.DeclName == "" {
				continue
			}
			funcs = append(funcs, decl{pkgDir: c.DeclPkgDir, receiver: c.DeclReceiver, name: c.DeclName})
		case report.ClaimVulnClass:
			if v := strings.ToLower(strings.TrimSpace(c.Value)); v != "" {
				vulnClasses = append(vulnClasses, v)
			}
		}
	}
	var out []fingerprint
	for _, f := range funcs {
		for _, vc := range vulnClasses {
			out = append(out, fingerprint{repo: repo, pkgDir: f.pkgDir, receiver: f.receiver, name: f.name, vulnClass: vc})
		}
	}
	return out
}
