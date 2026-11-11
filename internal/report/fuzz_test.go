package report

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// FuzzPrintable checks the promise Printable makes to every caller
// that puts report text on a terminal or in a verdict: the result is
// valid UTF-8 with no control or bidirectional formatting characters,
// and sanitizing twice changes nothing.
func FuzzPrintable(f *testing.F) {
	for _, s := range []string{
		"",
		"plain text",
		"\x1b]0;title\x07\x1b[31mred",
		"line one\nline two\r\n\ttabbed",
		"\u202Eevil\u202C \u2066x\u2069 \u200F \u061C",
		"\xff\xfe invalid \xc3\x28 utf8",
		"\x00\x7f\u0085\u009b",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := Printable(s)
		if !utf8.ValidString(out) {
			t.Fatalf("Printable(%q) = %q: not valid UTF-8", s, out)
		}
		for _, r := range out {
			if unicode.IsControl(r) || isBidiControl(r) {
				t.Fatalf("Printable(%q) = %q: kept %U", s, out, r)
			}
		}
		if again := Printable(out); again != out {
			t.Fatalf("Printable is not idempotent: %q then %q", out, again)
		}
	})
}

// FuzzValidateRef checks that nothing ValidateRef accepts can be read
// by git as an option, a revision expression or a path escape. A ref
// reaches git's command line, so this is the property the validator
// exists for.
func FuzzValidateRef(f *testing.F) {
	for _, s := range []string{
		"main", "v1.2.3", "release/1.x", "a3f9c1e",
		"e1fcd82abba34df74614020343be8eb1fe85f0d9",
		"--upload-pack=touch /tmp/x", "-n", "a..b", "HEAD~1", "HEAD^", "a:b",
		"@{upstream}", "refs/heads/.hidden", "x.lock", "a//b", "a/", "a.",
		"main\n--exec", "a b", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if ValidateRef(s) != nil {
			return
		}
		if s == "" || len(s) > 255 {
			t.Fatalf("accepted ref of length %d", len(s))
		}
		if s[0] == '-' || s[0] == '.' || s[0] == '/' {
			t.Fatalf("accepted ref %q with a leading %q", s, s[0])
		}
		if strings.Contains(s, "..") || strings.Contains(s, "//") {
			t.Fatalf("accepted ref %q containing \"..\" or \"//\"", s)
		}
		for _, r := range s {
			if r > unicode.MaxASCII || unicode.IsControl(r) || strings.ContainsRune(" ~^:?*[\\@{}\"'`$;&|<>()!#%=+,", r) {
				t.Fatalf("accepted ref %q containing %q", s, r)
			}
		}
		for _, part := range strings.Split(s, "/") {
			if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
				t.Fatalf("accepted ref %q with path component %q", s, part)
			}
		}
	})
}

// FuzzValidateRepo checks that an accepted repo is exactly one owner
// and one name, safe to place in a clone URL and in a directory name
// under the data dir.
func FuzzValidateRepo(f *testing.F) {
	for _, s := range []string{
		"golang/net", "owner/name.go", "a/b", "o/..", "o/.", "../x", "a/b/c",
		"-o/name", "o/-name", "o/na me", "o/name\n", "o/n?x=1", "o/n#frag", "/", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if ValidateRepo(s) != nil {
			return
		}
		owner, name, ok := strings.Cut(s, "/")
		if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
			t.Fatalf("accepted repo %q that is not owner/name", s)
		}
		if owner[0] == '-' || name == "." || name == ".." {
			t.Fatalf("accepted repo %q", s)
		}
		for _, r := range s {
			if r > unicode.MaxASCII || unicode.IsControl(r) || strings.ContainsRune(" \\:@?#%&=+~^*[]{}<>|;'\"`$!(),", r) {
				t.Fatalf("accepted repo %q containing %q", s, r)
			}
		}
	})
}
