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
