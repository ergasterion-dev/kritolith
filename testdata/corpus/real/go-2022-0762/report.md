# XSS in bluemonday: <scrİpt> is lower-cased to <script> and its content is left unescaped

bluemonday (v1.0.4, commit 3cce251c9ed2a9ee66c8f8984fff3d19d45999df) can be tricked into emitting a live script.

`(*Policy).sanitize` in `sanitize.go` tracks the most recently opened element with
`strings.ToLower(token.Data)`. `strings.ToLower("scrİpt")` (U+0130, capital I with dot)
is `"script"`, so text after a disallowed `<scrİpt>` tag is treated as script content
and written out raw instead of HTML-escaped. The escaped `&lt;script&gt;` in the
input comes out as a real `<script>` element.

Impact: stored XSS in any application that relies on `UGCPolicy()` / `NewPolicy()`
to clean user HTML.

## Reproduce

Drop this test into the repository root at commit `3cce251c9ed2a9ee66c8f8984fff3d19d45999df` and run `go test -run TestPoC -count=1 .` from that directory. It fails (or panics) on the affected code and passes once the issue is fixed.

```go
package bluemonday

import "testing"

// Input from the fix commit's sanitize_test.go (TestIssue111ScriptTags), written
// as an interpreted string so \u0130 is the real U+0130 character (the upstream
// test used a raw string, which passes the escape through literally).
// Vulnerable: the policies emit a live <script> element. Fixed: it is escaped.
func TestPoCIssue111ScriptTags(t *testing.T) {
	in := "<scr\u0130pt>&lt;script&gt;alert(document.domain)&lt;/script&gt;"
	want := `&lt;script&gt;alert(document.domain)&lt;/script&gt;`
	for name, p := range map[string]*Policy{
		"NewPolicy":        NewPolicy(),
		"UGCPolicy":        UGCPolicy(),
		"UGCPolicy+script": UGCPolicy().AllowElements("script"),
	} {
		if got := p.Sanitize(in); got != want {
			t.Errorf("%s: Sanitize(%q) = %q, want %q", name, in, got, want)
		}
	}
}
```
