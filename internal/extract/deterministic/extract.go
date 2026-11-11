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

// maxExamined bounds how many candidate matches one extractor looks
// at while filling its maxPerKind claims, when some candidates are
// skipped rather than kept.
const maxExamined = 20 * maxPerKind

var (
	fileRe          = regexp.MustCompile(`\b[A-Za-z0-9_][A-Za-z0-9_./-]{0,200}\.go\b`)
	lineRe          = regexp.MustCompile(`\b([A-Za-z0-9_][A-Za-z0-9_./-]{0,200}\.go):(\d{1,6})\b`)
	methodRe        = regexp.MustCompile(`\(\*?[A-Za-z_][A-Za-z0-9_]{1,60}\)\.[A-Za-z_][A-Za-z0-9_]{1,60}`)
	dotRe           = regexp.MustCompile(`\b[A-Za-z_][A-Za-z0-9_]{1,60}\.[A-Za-z_][A-Za-z0-9_]{1,60}\b`)
	backtickIdentRe = regexp.MustCompile("`([A-Za-z][A-Za-z0-9]*[A-Z][A-Za-z0-9]*)`")
	versionRe       = regexp.MustCompile(`\bv[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?\b`)
	shaRe           = regexp.MustCompile(`\b[0-9a-f]{7,40}\b`)
	fenceRe         = regexp.MustCompile("(?s)```[A-Za-z0-9_+-]*\\n(.*?)```")
	reproduceHdrRe  = regexp.MustCompile(`(?m)^##\s+Reproduce\b`)
)

// domainLikeSuffixes are segments after the last dot in a dotRe match
// that mean the match is an import path or URL host, not a genuine
// pkg.Func / Type.Method claim: common TLD-like suffixes and Go module
// version suffixes (e.g. "yaml.v3"), on top of the original "go"
// (a Go filename like "decode.go").
var domainLikeSuffixes = map[string]bool{
	"go": true, "com": true, "org": true, "net": true, "io": true,
	"dev": true, "sh": true, "app": true, "co": true, "in": true,
	"v2": true, "v3": true,
}

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
	{"panic", "crash"},
	{"path traversal", "path-traversal"},
	{"directory traversal", "path-traversal"},
	{"denial of service", "dos"},
	{"resource exhaustion", "dos"},
	{"infinite loop", "dos"},
	{"endless loop", "dos"},
	{"authentication bypass", "auth-bypass"},
	{"privilege escalation", "auth-bypass"},
	{"cors allow-list", "access-control-bypass"},
}

// Extract parses body for concrete, checkable claims. It never panics
// and never returns more than maxPerKind claims of any one kind.
func Extract(body string) []report.Claim {
	prose := stripFencedCodeBlocks(body)
	// Files, lines and functions are read from the text with links
	// removed; versions and commit SHAs are read with links in place,
	// because a link to a commit or a blob is a fair way to name one.
	plain := stripURLs(prose)
	var claims []report.Claim
	claims = append(claims, fileClaims(plain)...)
	claims = append(claims, lineClaims(plain)...)
	claims = append(claims, funcClaims(plain)...)
	claims = append(claims, versionAndSHAClaims(prose)...)
	claims = append(claims, vulnClassClaims(stripReproduceSection(prose))...)
	return dedupe(claims)
}

// stripFencedCodeBlocks removes ```...``` fenced code blocks from body,
// replacing each with a single space, so claim extraction only scans
// prose text. Code blocks are handled separately via PoCCandidates:
// scanning their content as if it were prose produces systematic false
// positives — a struct field access or a stdlib call reads exactly
// like a "pkg.Func" claim to funcClaims, but isn't one.
func stripFencedCodeBlocks(body string) string {
	return fenceRe.ReplaceAllString(body, " ")
}

// stripURLs removes URLs from body, replacing each with a single
// space. A URL is not a claim about the repository: its host can look
// like a file ("pkg.go.dev" contains "pkg.go") or a qualified name
// ("cwe.mitre.org"), and its path names a location on a web server.
// Read as claims, these are files and functions that never exist in
// the repository, which is exactly what marks a report as fabricated.
// Real advisories link to documentation constantly, so this would
// reject genuine reports. The visible text of a markdown link is kept.
func stripURLs(body string) string {
	if !strings.Contains(body, "://") {
		return body
	}
	var b strings.Builder
	b.Grow(len(body))
	for {
		i := strings.Index(body, "://")
		if i < 0 {
			b.WriteString(body)
			return b.String()
		}
		end := i + len("://")
		for end < len(body) && !endsURL(body[end]) {
			end++
		}
		if start := urlSchemeStart(body, i); start >= 0 {
			b.WriteString(body[:start])
			b.WriteByte(' ')
		} else {
			b.WriteString(body[:end])
		}
		body = body[end:]
	}
}

// urlSchemeStart returns where the http, https or ftp scheme that
// ends at body[i] begins, or -1 if the text before "://" is not one of
// those as a whole word.
func urlSchemeStart(body string, i int) int {
	for _, scheme := range []string{"https", "http", "ftp"} {
		start := i - len(scheme)
		if start < 0 || !strings.EqualFold(body[start:i], scheme) {
			continue
		}
		if start > 0 && isWordByte(body[start-1]) {
			continue
		}
		return start
	}
	return -1
}

// endsURL reports whether c cannot be part of a URL as people write
// them in prose and markdown: whitespace, quotes, and the brackets
// that close a markdown link or an autolink.
func endsURL(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '<', '>', '"', '\'', '`', ')', ']':
		return true
	}
	return false
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

// fileClaims matches "path/to/file.go" shapes. A match that runs
// straight on into ".word" or "/" is the start of a host name written
// without a scheme ("pkg.go.dev/strings", "docs.go.example.org"), not
// a file, and is skipped.
func fileClaims(body string) []report.Claim {
	var out []report.Claim
	// Matches are taken one at a time so a huge input costs no more
	// than the text up to the last claim kept. Skipped matches are
	// bounded too, so input made only of host names can't turn this
	// into a scan of everything.
	for examined := 0; len(out) < maxPerKind && examined < maxExamined; examined++ {
		loc := fileRe.FindStringIndex(body)
		if loc == nil {
			break
		}
		match, rest := body[loc[0]:loc[1]], body[loc[1]:]
		body = rest
		if strings.HasPrefix(rest, "/") || (len(rest) > 1 && rest[0] == '.' && isWordByte(rest[1])) {
			continue
		}
		out = append(out, newClaim(report.ClaimFile, match))
	}
	return out
}

func isWordByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

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
// shapes, plus bare backtick-wrapped CamelCase identifiers (e.g.
// “ `lexInlineTableDeep` “) that name a symbol without a surrounding
// "pkg." or "Type." prefix. Matches whose segment after the dot is a
// domain-like suffix (a Go filename, a common TLD, or a module version
// suffix like "yaml.v3") are dropped: dotRe alone can't tell
// "github.com" or "decode.go" from a genuine two-segment identifier,
// so this is the collision worth excluding explicitly for a Go-only
// project.
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
			if idx := strings.LastIndexByte(m, '.'); idx >= 0 && domainLikeSuffixes[strings.ToLower(m[idx+1:])] {
				continue
			}
			seen[m] = true
			out = append(out, newClaim(report.ClaimFunction, m))
		}
	}
	add(methodRe.FindAllString(body, maxPerKind))
	add(dotRe.FindAllString(body, maxPerKind))
	for _, m := range backtickIdentRe.FindAllStringSubmatch(body, maxPerKind) {
		if len(out) >= maxPerKind {
			break
		}
		ident := m[1]
		if seen[ident] {
			continue
		}
		seen[ident] = true
		out = append(out, newClaim(report.ClaimFunction, ident))
	}
	return out
}

// stripReproduceSection removes a "## Reproduce" heading and everything
// after it, so vuln-class keyword matching only sees the vulnerability
// description, not the procedural PoC-running instructions. This
// project's own report convention (see the architecture doc) puts a
// boilerplate sentence in that section — "It fails (or panics) on the
// affected code and passes once the issue is fixed" — that mentions
// "panics" regardless of the actual vuln class; scanning it would tag
// unrelated reports (SQL injection, path traversal, a CORS bypass, ...)
// with a spurious "crash" claim. Reports with no such heading are
// returned unchanged.
func stripReproduceSection(body string) string {
	if loc := reproduceHdrRe.FindStringIndex(body); loc != nil {
		return body[:loc[0]]
	}
	return body
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
