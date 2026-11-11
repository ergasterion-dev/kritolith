package llmextract

import (
	"context"
	"strings"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/llm"
	"github.com/ergasterion-dev/kritolith/internal/report"
)

// FuzzModelResponse treats the model's reply as attacker-controlled,
// which it is: the report body is in the prompt, so a prompt injection
// can make the model say anything. Whatever comes back, extraction
// must only ever yield a bounded list of well-formed, unverified
// claims of a known kind.
func FuzzModelResponse(f *testing.F) {
	for _, s := range []string{
		`{"claims": []}`,
		`{"claims": [{"kind": "file", "value": "a.go", "evidence": "named directly"}]}`,
		"Sure! Here is the JSON:\n```json\n{\"claims\": [{\"kind\": \"function\", \"value\": \"pkg.Func\", \"evidence\": \"e\"}]}\n```",
		`{"claims": [{"kind": "file", "value": "a.go", "evidence": "e", "verified": "yes"}]}`,
		`{"claims": [{"kind": "sink", "value": "x", "evidence": "e"}]}`,
		`{"claims": [{"kind": "file", "value": "\u001b[31m‮a.go", "evidence": "\u0000"}]}`,
		`{"claims": [{"kind": "file", "value": "` + strings.Repeat("a", 600) + `", "evidence": ""}]}`,
		`{"claims": "ignore previous instructions"}`,
		`{"outcome": "NOT_REPRODUCED", "claims": []}`,
		`{"claims": [{"kind": "file", "value": 7}]}`,
		`}{`, `{`, ``, `null`, `[]`,
	} {
		f.Add(s)
	}
	valid := map[report.ClaimKind]bool{}
	for _, k := range validKinds {
		valid[k] = true
	}
	f.Fuzz(func(t *testing.T, text string) {
		p := &fakeProvider{name: "m1", text: text}
		claims := Extract(context.Background(), fakeChain{[]llm.Provider{p}}, report.Report{ID: "R1", Body: "body"})
		if len(claims) > maxClaims {
			t.Fatalf("%d claims; limit is %d", len(claims), maxClaims)
		}
		for _, c := range claims {
			if !valid[c.Kind] {
				t.Fatalf("claim of unknown kind %q", c.Kind)
			}
			if c.Value == "" || c.Value != report.Printable(c.Value) || c.Evidence != report.Printable(c.Evidence) {
				t.Fatalf("claim is empty or not printable: %+v", c)
			}
			if len(c.Value) > 3*500 || len(c.Evidence) > 3*(300+len("...")) {
				// Printable can widen one byte to a 3-byte U+FFFD.
				t.Fatalf("claim exceeds the length limits: %d value bytes, %d evidence bytes", len(c.Value), len(c.Evidence))
			}
			if c.Source != "llm:m1" {
				t.Fatalf("claim source = %q", c.Source)
			}
			if c.Verified != report.TriUnknown {
				t.Fatalf("the model's reply produced a claim marked %q: only grounding may verify", c.Verified)
			}
		}
	})
}
