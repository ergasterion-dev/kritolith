package deterministic

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// FuzzExtractInvariants checks what the rest of the pipeline relies on
// from Extract, for any report body: output is bounded per kind, every
// value is already safe to print, nothing is marked verified, there
// are no duplicate claims, and the same body always gives the same
// claims. FuzzExtract (extract_test.go) only checks for panics.
func FuzzExtractInvariants(f *testing.F) {
	for _, s := range []string{
		"",
		"internal/hpack/decode.go:412 parseHeader v1.2.3 a3f9c1e",
		"The function `(*Framer).ReadContinuationUnsafe` in http2/frame.go has an out of bounds read.",
		"\x1b]0;pwned\x07 (*Type).Method path traversal",
		"‮bidi override‬ file.go",
		"```go\nfmt.Println(os.Args)\n```\nsee pkg.Func\n## Reproduce\nIt panics.",
		"```\nunterminated fence a.b c.go:1",
		strings.Repeat("a.b ", 5000),
		strings.Repeat("`AbCd` x/y.go:1 v1.2.3 deadbeef ", 200),
		"\xff\xfe.go:999999 \xc3\x28.Func",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body string) {
		claims := Extract(body)
		perKind := map[report.ClaimKind]int{}
		seen := map[string]bool{}
		for _, c := range claims {
			perKind[c.Kind]++
			if c.Value == "" {
				t.Fatalf("empty claim value: %+v", c)
			}
			if c.Value != report.Printable(c.Value) {
				t.Fatalf("claim value %q is not printable", c.Value)
			}
			if c.Source != "deterministic" {
				t.Fatalf("claim source = %q", c.Source)
			}
			if c.Verified != report.TriUnknown {
				t.Fatalf("extraction marked a claim %q: only grounding may verify", c.Verified)
			}
			key := string(c.Kind) + "\x00" + c.Value
			if seen[key] {
				t.Fatalf("duplicate claim %+v", c)
			}
			seen[key] = true
		}
		for kind, n := range perKind {
			if n > maxPerKind {
				t.Fatalf("%d claims of kind %s; limit is %d", n, kind, maxPerKind)
			}
		}
		if again := Extract(body); !reflect.DeepEqual(claims, again) {
			t.Fatalf("Extract is not deterministic:\n%+v\n%+v", claims, again)
		}

		blocks := PoCCandidates(body)
		if len(blocks) > maxPerKind {
			t.Fatalf("%d PoC candidates; limit is %d", len(blocks), maxPerKind)
		}
		for _, b := range blocks {
			if b != report.Printable(b) {
				t.Fatalf("PoC candidate %q is not printable", b)
			}
		}
	})
}
