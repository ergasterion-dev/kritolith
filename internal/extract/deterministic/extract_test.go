package deterministic

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

func hasClaim(claims []report.Claim, kind report.ClaimKind, value string) bool {
	for _, c := range claims {
		if c.Kind == kind && c.Value == value {
			return true
		}
	}
	return false
}

func TestExtractFileAndLine(t *testing.T) {
	body := "The bug is in internal/hpack/decode.go:412, inside parseHeader."
	claims := Extract(body)
	if !hasClaim(claims, report.ClaimFile, "internal/hpack/decode.go") {
		t.Errorf("missing file claim: %+v", claims)
	}
	if !hasClaim(claims, report.ClaimLine, "internal/hpack/decode.go:412") {
		t.Errorf("missing line claim: %+v", claims)
	}
}

func TestExtractFunctionAndMethod(t *testing.T) {
	body := "http2.parseHeader panics; the fix is in (*Framer).ReadFrame."
	claims := Extract(body)
	if !hasClaim(claims, report.ClaimFunction, "http2.parseHeader") {
		t.Errorf("missing pkg.Func claim: %+v", claims)
	}
	if !hasClaim(claims, report.ClaimFunction, "(*Framer).ReadFrame") {
		t.Errorf("missing method claim: %+v", claims)
	}
}

func TestExtractFileNotAlsoFunction(t *testing.T) {
	body := "See decode.go for details."
	claims := Extract(body)
	if hasClaim(claims, report.ClaimFunction, "decode.go") {
		t.Errorf("file extension wrongly extracted as function claim: %+v", claims)
	}
}

func TestExtractVersionAndSHA(t *testing.T) {
	body := "Reproduced on v1.2.3, fixed in commit a3f9c1e2b7d4."
	claims := Extract(body)
	if !hasClaim(claims, report.ClaimVersion, "v1.2.3") {
		t.Errorf("missing version claim: %+v", claims)
	}
	if !hasClaim(claims, report.ClaimVersion, "a3f9c1e2b7d4") {
		t.Errorf("missing SHA claim (reuses ClaimVersion: both pin a specific tested code state): %+v", claims)
	}
}

func TestExtractVulnClass(t *testing.T) {
	body := "This is a classic path traversal in the file handler."
	claims := Extract(body)
	if !hasClaim(claims, report.ClaimVulnClass, "path-traversal") {
		t.Errorf("missing vuln class claim: %+v", claims)
	}
}

func TestExtractDedupes(t *testing.T) {
	body := "See internal/hpack/decode.go and again internal/hpack/decode.go."
	claims := Extract(body)
	count := 0
	for _, c := range claims {
		if c.Kind == report.ClaimFile && c.Value == "internal/hpack/decode.go" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("file claim not deduped: got %d", count)
	}
}

func TestExtractSanitizesValue(t *testing.T) {
	body := "internal/hpack/decode.go is the file, reported by e\x1b[2Ivil."
	claims := Extract(body)
	for _, c := range claims {
		if strings.ContainsRune(c.Value, 0x1b) {
			t.Errorf("unsanitized control char in claim value: %q", c.Value)
		}
	}
}

func TestExtractCapsPerKind(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxPerKind+20; i++ {
		fmt.Fprintf(&b, "pkg%d.Func%d ", i, i)
	}
	claims := Extract(b.String())
	count := 0
	for _, c := range claims {
		if c.Kind == report.ClaimFunction {
			count++
		}
	}
	if count > maxPerKind {
		t.Errorf("func claims not capped: got %d, want <= %d", count, maxPerKind)
	}
}

func TestExtractLargeInputCompletesQuickly(t *testing.T) {
	// Go's regexp package is RE2-based (no backtracking), so this can't
	// exhibit catastrophic ReDoS blowup by construction. This test pins
	// that guarantee as a regression check.
	body := strings.Repeat("a.b.c/d.go:1 ", 100000)
	done := make(chan struct{})
	go func() {
		Extract(body)
		PoCCandidates(body)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Extract took too long on large input")
	}
}

func TestExtractNoPanic(t *testing.T) {
	inputs := []string{
		"",
		strings.Repeat("a.b ", 10000),
		"\x00\x01\x02 file.go:99999999999999999999",
		"‮reversed bidi text‬",
		strings.Repeat("```\ncode\n", 500),
	}
	for _, in := range inputs {
		Extract(in)
		PoCCandidates(in)
	}
}

func TestPoCCandidates(t *testing.T) {
	body := "Here:\n```go\npackage main\nfunc main() {}\n```\nDone."
	blocks := PoCCandidates(body)
	if len(blocks) != 1 || !strings.Contains(blocks[0], "package main") {
		t.Errorf("PoCCandidates = %v", blocks)
	}
}

func FuzzExtract(f *testing.F) {
	seeds := []string{
		"internal/hpack/decode.go:412 parseHeader v1.2.3 a3f9c1e",
		"\x1b]0;pwned\x07 (*Type).Method path traversal",
		"‮bidi override‬ file.go",
		strings.Repeat("a.b ", 5000),
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body string) {
		Extract(body)
		PoCCandidates(body)
	})
}
