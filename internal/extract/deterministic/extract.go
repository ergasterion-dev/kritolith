// Package deterministic extracts checkable claims from report text
// using regex and structural parsing. It never trusts the LLM, never
// panics, and bounds its own output on hostile input.
package deterministic

import (
	"regexp"
	"strings"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// maxPerKind bounds how many claims of one kind a single Extract call
// can produce, so pathological input can't create unbounded output.
const maxPerKind = 50

var (
	fileRe    = regexp.MustCompile(`\b[A-Za-z0-9_][A-Za-z0-9_./-]{0,200}\.go\b`)
	lineRe    = regexp.MustCompile(`\b([A-Za-z0-9_][A-Za-z0-9_./-]{0,200}\.go):(\d{1,6})\b`)
	methodRe  = regexp.MustCompile(`\(\*?[A-Za-z_][A-Za-z0-9_]{1,60}\)\.[A-Za-z_][A-Za-z0-9_]{1,60}`)
	dotRe     = regexp.MustCompile(`\b[A-Za-z_][A-Za-z0-9_]{1,60}\.[A-Za-z_][A-Za-z0-9_]{1,60}\b`)
	versionRe = regexp.MustCompile(`\bv[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?\b`)
	shaRe     = regexp.MustCompile(`\b[0-9a-f]{7,40}\b`)
	fenceRe   = regexp.MustCompile("(?s)```[A-Za-z0-9_+-]*\\n(.*?)```")
)

// vulnKeywords maps a report phrase to a vuln class. Order matters: the
// first matching phrase for a class wins, which keeps output
// deterministic for tests.
var vulnKeywords = []struct{ phrase, class string }{
	{"sql injection", "injection"},
	{"command injection", "injection"},
	{"race condition", "race"},
	{"data race", "race"},
	{"buffer overflow", "memory-safety"},
	{"use after free", "memory-safety"},
	{"out of bounds", "memory-safety"},
	{"nil pointer dereference", "crash"},
	{"path traversal", "path-traversal"},
	{"directory traversal", "path-traversal"},
	{"denial of service", "dos"},
	{"resource exhaustion", "dos"},
	{"infinite loop", "dos"},
	{"authentication bypass", "auth-bypass"},
	{"privilege escalation", "auth-bypass"},
}

// Extract parses body for concrete, checkable claims. It never panics
// and never returns more than maxPerKind claims of any one kind.
func Extract(body string) []report.Claim {
	var claims []report.Claim
	claims = append(claims, fileClaims(body)...)
	claims = append(claims, lineClaims(body)...)
	claims = append(claims, funcClaims(body)...)
	claims = append(claims, versionAndSHAClaims(body)...)
	claims = append(claims, vulnClassClaims(body)...)
	return dedupe(claims)
}

// PoCCandidates returns the fenced code blocks in body, capped at
// maxPerKind, as candidate PoC bodies. Nothing here is executed or
// written to disk; the caller decides what to do with them.
func PoCCandidates(body string) []string {
	matches := fenceRe.FindAllStringSubmatch(body, maxPerKind)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, report.Printable(m[1]))
	}
	return out
}

func newClaim(kind report.ClaimKind, value string) report.Claim {
	return report.Claim{
		Kind:     kind,
		Value:    report.Printable(value),
		Source:   "deterministic",
		Verified: report.TriUnknown,
		Evidence: "found in report text; not yet checked against code",
	}
}

func matchClaims(re *regexp.Regexp, body string, kind report.ClaimKind) []report.Claim {
	matches := re.FindAllString(body, maxPerKind)
	out := make([]report.Claim, 0, len(matches))
	for _, m := range matches {
		out = append(out, newClaim(kind, m))
	}
	return out
}

func fileClaims(body string) []report.Claim { return matchClaims(fileRe, body, report.ClaimFile) }

// versionAndSHAClaims matches version tags and commit SHAs, both under the
// shared ClaimVersion kind. Capped once per kind to enforce maxPerKind.
func versionAndSHAClaims(body string) []report.Claim {
	var out []report.Claim
	add := func(matches []string) {
		for _, m := range matches {
			if len(out) >= maxPerKind {
				return
			}
			out = append(out, newClaim(report.ClaimVersion, m))
		}
	}
	add(versionRe.FindAllString(body, maxPerKind))
	add(shaRe.FindAllString(body, maxPerKind))
	return out
}

func lineClaims(body string) []report.Claim {
	matches := lineRe.FindAllStringSubmatch(body, maxPerKind)
	out := make([]report.Claim, 0, len(matches))
	for _, m := range matches {
		out = append(out, newClaim(report.ClaimLine, m[1]+":"+m[2]))
	}
	return out
}

// funcClaims matches "pkg.Func", "Type.Method" and "(*Type).Method"
// shapes. Matches whose segment after the dot is literally "go"
// (case-insensitive) are dropped: dotRe alone can't tell "decode.go"
// (a filename) from a genuine two-segment identifier, so this is the
// one collision worth excluding explicitly for a Go-only project.
func funcClaims(body string) []report.Claim {
	var out []report.Claim
	seen := make(map[string]bool)
	add := func(matches []string) {
		for _, m := range matches {
			if len(out) >= maxPerKind {
				return
			}
			if seen[m] {
				continue
			}
			if idx := strings.LastIndexByte(m, '.'); idx >= 0 && strings.EqualFold(m[idx+1:], "go") {
				continue
			}
			seen[m] = true
			out = append(out, newClaim(report.ClaimFunction, m))
		}
	}
	add(methodRe.FindAllString(body, maxPerKind))
	add(dotRe.FindAllString(body, maxPerKind))
	return out
}

func vulnClassClaims(body string) []report.Claim {
	lower := strings.ToLower(body)
	seenClass := make(map[string]bool)
	var out []report.Claim
	for _, kw := range vulnKeywords {
		if len(out) >= maxPerKind {
			break
		}
		if seenClass[kw.class] || !strings.Contains(lower, kw.phrase) {
			continue
		}
		seenClass[kw.class] = true
		out = append(out, report.Claim{
			Kind:     report.ClaimVulnClass,
			Value:    kw.class,
			Source:   "deterministic",
			Verified: report.TriUnknown,
			Evidence: "keyword match in report text; not yet checked",
		})
	}
	return out
}

func dedupe(claims []report.Claim) []report.Claim {
	seen := make(map[string]bool, len(claims))
	out := make([]report.Claim, 0, len(claims))
	for _, c := range claims {
		key := string(c.Kind) + "\x00" + c.Value
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	return out
}
