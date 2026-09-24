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

func TestExtractVulnClassPanicCrash(t *testing.T) {
	body := "Feeding it malformed input makes the decoder panic instead of returning an error."
	claims := Extract(body)
	if !hasClaim(claims, report.ClaimVulnClass, "crash") {
		t.Errorf("missing vuln class claim for panic wording: %+v", claims)
	}
}

func TestExtractVulnClassDosSynonyms(t *testing.T) {
	for _, body := range []string{
		"This causes an infinite loop that pins a goroutine at 100% CPU.",
		"The parser gets stuck in an endless loop on this input.",
	} {
		claims := Extract(body)
		if !hasClaim(claims, report.ClaimVulnClass, "dos") {
			t.Errorf("body %q: missing dos vuln class claim: %+v", body, claims)
		}
	}
}

func TestExtractVulnClassCORSAllowList(t *testing.T) {
	body := "The CORS allow-list bypass lets an attacker read cross-origin responses."
	claims := Extract(body)
	if !hasClaim(claims, report.ClaimVulnClass, "access-control-bypass") {
		t.Errorf("missing vuln class claim for CORS allow-list bypass: %+v", claims)
	}
}

// TestExtractVulnClassIgnoresReproduceSection guards the fix for the
// Week 4 corpus gap: a report's "## Reproduce" section carries this
// project's own boilerplate ("It fails (or panics) on the affected
// code..."), unrelated to the report's actual vulnerability class.
// Scanning it would tag an unrelated report (here: a path traversal)
// with a spurious "crash" claim just because it also panics in its
// PoC-running instructions.
func TestExtractVulnClassIgnoresReproduceSection(t *testing.T) {
	body := "This is a classic path traversal in the file handler.\n\n" +
		"## Reproduce\n\nRun the PoC. It fails (or panics) on the affected code " +
		"and passes once the issue is fixed."
	claims := Extract(body)
	if hasClaim(claims, report.ClaimVulnClass, "crash") {
		t.Errorf("vuln class wrongly derived from the Reproduce section's boilerplate: %+v", claims)
	}
	if !hasClaim(claims, report.ClaimVulnClass, "path-traversal") {
		t.Errorf("missing the real vuln class claim: %+v", claims)
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

func TestExtractCapsVersionPerKind(t *testing.T) {
	// Verify that ClaimVersion is capped per kind, not per regex.
	// versionRe and shaRe both produce ClaimVersion; they should share
	// a single cap of maxPerKind total, not each get their own.
	var b strings.Builder
	// Add 60 distinct version tags
	for i := 0; i < 60; i++ {
		fmt.Fprintf(&b, "v1.%d.0 ", i)
	}
	// Add 60 distinct SHA-like tokens (7+ hex chars)
	for i := 0; i < 60; i++ {
		fmt.Fprintf(&b, "%07x ", i)
	}
	claims := Extract(b.String())
	count := 0
	for _, c := range claims {
		if c.Kind == report.ClaimVersion {
			count++
		}
	}
	if count > maxPerKind {
		t.Errorf("version claims not capped: got %d, want <= %d", count, maxPerKind)
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

// TestExtractIgnoresFencedCodeBlockNoise pins the fix for a bug where
// funcClaims scanned fenced code block content as if it were prose: a
// struct field access or method call on a local variable reads exactly
// like a "pkg.Func" claim shape, but isn't a declared symbol anywhere,
// so grounding correctly reports it "not found" and wrongly escalates
// the whole report to GROUNDING_FAILED. Only prose claims should survive.
func TestExtractIgnoresFencedCodeBlockNoise(t *testing.T) {
	body := "The bug is in pkg.RealFunc, see below.\n" +
		"```go\n" +
		"resp := doThing()\n" +
		"if resp.Errors != nil {\n" +
		"    localVar.someField()\n" +
		"}\n" +
		"```\n"
	claims := Extract(body)
	if !hasClaim(claims, report.ClaimFunction, "pkg.RealFunc") {
		t.Errorf("missing prose claim: %+v", claims)
	}
	if hasClaim(claims, report.ClaimFunction, "resp.Errors") {
		t.Errorf("code block noise wrongly extracted as function claim: %+v", claims)
	}
	if hasClaim(claims, report.ClaimFunction, "localVar.someField") {
		t.Errorf("code block noise wrongly extracted as function claim: %+v", claims)
	}
}

// TestExtractIgnoresGo20220300StyleNoise directly pins the real-world
// bug found via the go-2022-0300 corpus case: a PoC embedded as a
// fenced ```go block contains a package-level var reference
// (starwars.Schema), a method call on a local (schema.Exec), a stdlib
// call (context.Background), and a struct field access (resp.Errors) —
// none of which are legitimate claims about the vulnerability, but all
// of which match funcClaims' "pkg.Func"/"Type.Method" shape.
func TestExtractIgnoresGo20220300StyleNoise(t *testing.T) {
	body := "The circular fragment causes unbounded recursion during validation.\n\n" +
		"```go\n" +
		"package graphql_test\n\n" +
		"import (\n" +
		"\t\"context\"\n" +
		"\t\"testing\"\n\n" +
		"\tgraphql \"github.com/graph-gophers/graphql-go\"\n" +
		"\t\"github.com/graph-gophers/graphql-go/example/starwars\"\n" +
		")\n\n" +
		"func TestPoCCircularFragmentMaxDepth(t *testing.T) {\n" +
		"\tschema := graphql.MustParseSchema(starwars.Schema, &starwars.Resolver{}, graphql.MaxDepth(2))\n" +
		"\tquery := `...`\n" +
		"\tresp := schema.Exec(context.Background(), query, \"\", nil)\n" +
		"\tif len(resp.Errors) == 0 {\n" +
		"\t\tt.Fatal(\"expected validation errors for a fragment cycle, got none\")\n" +
		"\t}\n" +
		"}\n" +
		"```\n"
	claims := Extract(body)
	bogus := []string{
		"starwars.Schema",
		"starwars.Resolver",
		"schema.Exec",
		"context.Background",
		"resp.Errors",
		"graphql.MustParseSchema",
		"graphql.MaxDepth",
	}
	for _, b := range bogus {
		if hasClaim(claims, report.ClaimFunction, b) {
			t.Errorf("claim from fenced code block leaked into prose claims: %q; all claims: %+v", b, claims)
		}
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
