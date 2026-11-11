package file

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// FuzzTitle checks the title taken from a report body. It is printed
// in every verdict, so it must be one printable line of bounded
// length whatever the report starts with.
func FuzzTitle(f *testing.F) {
	for _, s := range []string{
		"",
		"# Out-of-bounds read in http2\n\nbody",
		"\n\n   \n###   \n## Real title ##\n",
		"\x1b]0;pwned\x07\x1b[2J# title",
		"‮eltit‬",
		strings.Repeat("#", 1000),
		strings.Repeat("é", 500),
		"\xff\xfe\xfd",
		"title\r\nnext",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body string) {
		got := title(body)
		if got != report.Printable(got) {
			t.Fatalf("title %q is not printable", got)
		}
		if n := utf8.RuneCountInString(got); n > maxTitleRunes {
			t.Fatalf("title has %d runes; limit is %d", n, maxTitleRunes)
		}
	})
}
