package eml

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

func opts() Options {
	return Options{
		Repo: "owner/name",
		Now:  func() time.Time { return time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC) },
		Rand: bytes.NewReader(make([]byte, 16)),
	}
}

// crlf turns a readable test message into wire format.
func crlf(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }

func load(t *testing.T, msg string) report.Report {
	t.Helper()
	r, err := Load(strings.NewReader(crlf(msg)), opts())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestLoadPlainMessage(t *testing.T) {
	r := load(t, `From: Reporter <reporter@example.org>
To: security@example.org
Subject: Over-read in http2 frame parsing
Message-ID: <abc123@example.org>
Content-Type: text/plain; charset=utf-8

The method (*Framer).ReadFrame in http2/frame.go:1257 over-reads.

Affects v0.38.0.
`)
	if r.Source != report.SourceEML || r.SourceRef != "<abc123@example.org>" || r.Repo != "owner/name" {
		t.Errorf("report = %+v", r)
	}
	if r.Title != "Over-read in http2 frame parsing" {
		t.Errorf("title = %q", r.Title)
	}
	if want := "The method (*Framer).ReadFrame in http2/frame.go:1257 over-reads.\n\nAffects v0.38.0."; r.Body != want {
		t.Errorf("body = %q, want %q", r.Body, want)
	}
	if r.ID == "" || r.ReceivedAt.IsZero() || len(r.PoC) != 0 || r.ClaimedRef != "" {
		t.Errorf("report = %+v", r)
	}
	// The sender is deliberately not kept anywhere.
	if strings.Contains(fmt.Sprintf("%+v", r), "reporter@example.org") {
		t.Error("the sender's address ended up in the report")
	}
}

func TestLoadMultipartWithAttachments(t *testing.T) {
	poc := "package p\n\nfunc TestPoC(t *testing.T) {}\n"
	msg := `Subject: =?utf-8?B?` + base64.StdEncoding.EncodeToString([]byte("Déni de service in parser")) + `?=
Message-ID: <m1@example.org>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

preamble, ignored
--outer
Content-Type: multipart/alternative; boundary="inner"

--inner
Content-Type: text/plain; charset=iso-8859-1
Content-Transfer-Encoding: quoted-printable

The parser in lex.go loops forever. Caf=E9.
--inner
Content-Type: text/html; charset=utf-8

<html><body><p>The parser in <b>other.go</b> loops forever.</p></body></html>
--inner--
--outer
Content-Type: text/x-go; name="poc_test.go"
Content-Disposition: attachment; filename="poc_test.go"
Content-Transfer-Encoding: base64

` + wrap(base64.StdEncoding.EncodeToString([]byte(poc)), 20) + `
--outer
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="../../.ssh/authorized_keys"

key material
--outer
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="authorized_keys"

second
--outer
Content-Type: image/png
Content-Transfer-Encoding: base64

iVBORw0KGgo=
--outer--
`
	r := load(t, msg)
	if r.Title != "Déni de service in parser" {
		t.Errorf("title = %q", r.Title)
	}
	// Plain text wins over HTML, and latin-1 is converted.
	if r.Body != "The parser in lex.go loops forever. Café." {
		t.Errorf("body = %q", r.Body)
	}
	var names []string
	for _, a := range r.PoC {
		names = append(names, a.Name)
	}
	if got, want := strings.Join(names, " "), "poc_test.go authorized_keys 2-authorized_keys attachment.png"; got != want {
		t.Fatalf("attachment names = %q, want %q", got, want)
	}
	if string(r.PoC[0].Content) != poc {
		t.Errorf("attachment content = %q", r.PoC[0].Content)
	}
	if string(r.PoC[1].Content) != "key material" {
		t.Errorf("attachment content = %q", r.PoC[1].Content)
	}
}

func wrap(s string, n int) string {
	var b strings.Builder
	for len(s) > n {
		b.WriteString(s[:n] + "\n")
		s = s[n:]
	}
	return b.String() + s
}

func TestLoadHTMLOnly(t *testing.T) {
	r := load(t, `Subject: html only
Content-Type: text/html; charset=utf-8

<html><head><style>p { color: red } .x::after { content: "style.go" }</style>
<script>var hidden = "script.go"; if (a < b) {}</script></head>
<body><!-- comment.go --><h1>Bug</h1><p>See <code>pkg.Func</code> in <b>real.go</b>.</p>
<P>a &lt; b &amp;&amp; c &gt; d</P><div>line<br>break</div><SCRIPT>x</SCRIPT>tail</body></html>
`)
	for _, want := range []string{"Bug", "See pkg.Func in real.go.", "a < b && c > d", "line\nbreak", "tail"} {
		if !strings.Contains(r.Body, want) {
			t.Errorf("body missing %q:\n%s", want, r.Body)
		}
	}
	for _, bad := range []string{"style.go", "script.go", "comment.go", "<", "color"} {
		if strings.Contains(strings.ReplaceAll(r.Body, "a < b", ""), bad) {
			t.Errorf("body contains %q:\n%s", bad, r.Body)
		}
	}
}

func TestLoadNoContentTypeAndNoMessageID(t *testing.T) {
	msg := "Subject:   spaced   out\n  folded subject  \n\nJust text with a.go in it.\n"
	r := load(t, msg)
	if r.Body != "Just text with a.go in it." {
		t.Errorf("body = %q", r.Body)
	}
	if r.Title != "spaced out folded subject" {
		t.Errorf("title = %q", r.Title)
	}
	if !strings.HasPrefix(r.SourceRef, "sha256:") || len(r.SourceRef) != len("sha256:")+64 {
		t.Errorf("source ref = %q", r.SourceRef)
	}
	// The same bytes give the same reference; different bytes don't.
	if again := load(t, msg); again.SourceRef != r.SourceRef {
		t.Error("the same message got a different source reference")
	}
	if other := load(t, msg+"more\n"); other.SourceRef == r.SourceRef {
		t.Error("a different message got the same source reference")
	}
}

func TestLoadSanitizesHeaders(t *testing.T) {
	r := load(t, "Subject: =?utf-8?Q?=1B]0;pwned=07_title_=E2=80=AEdesrever?= "+strings.Repeat("x", 400)+"\n"+
		"Message-ID: <id\x1b[31m@example.org> "+strings.Repeat("y", 600)+"\n\nbody\n")
	if r.Title != report.Printable(r.Title) || utf8.RuneCountInString(r.Title) > maxTitleRunes {
		t.Errorf("title = %q", r.Title)
	}
	if r.SourceRef != report.Printable(r.SourceRef) || utf8.RuneCountInString(r.SourceRef) > maxRefRunes {
		t.Errorf("source ref = %q", r.SourceRef)
	}
}

func TestLoadRejects(t *testing.T) {
	big := strings.Repeat("a", MaxBodyBytes+10)
	nested := func(depth int) string {
		var b strings.Builder
		b.WriteString("Subject: nested\n")
		for i := range depth {
			fmt.Fprintf(&b, "Content-Type: multipart/mixed; boundary=b%d\n\n--b%d\n", i, i)
		}
		b.WriteString("Content-Type: text/plain\n\ndeep\n")
		for i := depth - 1; i >= 0; i-- {
			fmt.Fprintf(&b, "--b%d--\n", i)
		}
		return b.String()
	}
	manyParts := func(n int, header string) string {
		var b strings.Builder
		b.WriteString("Subject: many\nContent-Type: multipart/mixed; boundary=B\n\n")
		for range n {
			b.WriteString("--B\n" + header + "\n\nx\n")
		}
		b.WriteString("--B--\n")
		return b.String()
	}
	cases := map[string]struct {
		msg  string
		mut  func(*Options)
		want string
	}{
		"empty":            {msg: "", want: "empty message"},
		"whitespace":       {msg: "\n\n  \n", want: "empty message"},
		"not mail":         {msg: "this is not\na mail message\n", want: "not a mail message"},
		"bad repo":         {msg: "Subject: s\n\nb\n", mut: func(o *Options) { o.Repo = "nope" }, want: "invalid repo"},
		"bad ref":          {msg: "Subject: s\n\nb\n", mut: func(o *Options) { o.Ref = "--upload-pack=x" }, want: "invalid ref"},
		"text too large":   {msg: "Subject: s\n\n" + big + "\n", want: "message text is"},
		"no boundary":      {msg: "Subject: s\nContent-Type: multipart/mixed\n\nbody\n", want: "no boundary"},
		"nested too deep":  {msg: nested(maxDepth + 2), want: "nests multipart"},
		"too many parts":   {msg: manyParts(maxParts+5, "Content-Type: text/plain"), want: "MIME parts"},
		"too many files":   {msg: manyParts(MaxPoCFiles+1, "Content-Type: application/octet-stream"), want: "too many attachments"},
		"truncated":        {msg: "Subject: s\nContent-Type: multipart/mixed; boundary=B\n\n--B\nContent-Type: text/plain\n\nx\n", want: "unexpected EOF"},
		"attachments size": {msg: "Subject: s\nContent-Type: multipart/mixed; boundary=B\n\n--B\nContent-Type: application/octet-stream\n\n" + strings.Repeat("z", MaxPoCBytes+10) + "\n--B--\n", want: "attachments are larger"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			o := opts()
			if tc.mut != nil {
				tc.mut(&o)
			}
			_, err := Load(strings.NewReader(crlf(tc.msg)), o)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}

	t.Run("message too large", func(t *testing.T) {
		_, err := Load(io64(MaxMessageBytes+1), opts())
		if err == nil || !strings.Contains(err.Error(), "larger than") {
			t.Fatalf("err = %v", err)
		}
	})
}

// io64 is a reader of n bytes that look like a header line that never
// ends, without allocating them up front.
func io64(n int) *strings.Reader { return strings.NewReader("Subject: " + strings.Repeat("a", n)) }

func TestAcceptsNestingAtTheLimit(t *testing.T) {
	var b strings.Builder
	b.WriteString("Subject: nested\n")
	for i := range maxDepth {
		fmt.Fprintf(&b, "Content-Type: multipart/mixed; boundary=b%d\n\n--b%d\n", i, i)
	}
	b.WriteString("Content-Type: text/plain\n\ndeep text\n")
	for i := maxDepth - 1; i >= 0; i-- {
		fmt.Fprintf(&b, "--b%d--\n", i)
	}
	if r := load(t, b.String()); r.Body != "deep text" {
		t.Errorf("body = %q", r.Body)
	}
}

func TestAttachmentNames(t *testing.T) {
	c := &collector{names: map[string]bool{}}
	// Names depend on what came before, so the cases are an ordered
	// list.
	for _, tc := range []struct{ in, mediaType, want string }{
		{"poc_test.go", "text/x-go", "poc_test.go"},
		{"../../etc/passwd", "text/plain", "passwd"},
		{`C:\Users\x\evil.go`, "text/plain", "evil.go"},
		{"/abs/path/a.go", "text/plain", "a.go"},
		{"..", "application/zip", "attachment.zip"},
		{"...hidden", "text/plain", "hidden"},
		{".bashrc", "text/plain", "bashrc"},
		{"", "application/x-weird+thing", "attachment"},
		{"", "application/zip", "2-attachment.zip"},
		{"a\x1b[31mb.go", "text/plain", "a_[31mb.go"},
		{"dir/", "text/plain", "dir"},
		{"passwd", "text/plain", "2-passwd"},
		{"passwd", "text/plain", "3-passwd"},
		{strings.Repeat("n", 300) + ".go", "text/plain", strings.Repeat("n", 97) + ".go"},
	} {
		if got := c.uniqueName(tc.in, tc.mediaType); got != tc.want {
			t.Errorf("uniqueName(%q, %q) = %q, want %q", tc.in, tc.mediaType, got, tc.want)
		}
	}
}

func FuzzLoad(f *testing.F) {
	for _, s := range []string{
		"Subject: s\r\n\r\nbody a.go\r\n",
		"Subject: s\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/html\r\n\r\n<p>x</p>\r\n--B\r\nContent-Disposition: attachment; filename=\"../x\"\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJD\r\n--B--\r\n",
		"Subject: =?x?Q?=ff?=\r\nContent-Type: text/plain; charset=latin1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n=E9=\r\n",
		"Content-Type: text/html\r\n\r\n<script><script></scr<!-- <style>",
		"",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		r, err := Load(bytes.NewReader(raw), Options{Repo: "owner/name"})
		if err != nil {
			return
		}
		if len(r.Body) > MaxBodyBytes || !utf8.ValidString(r.Body) {
			t.Fatalf("body: %d bytes, valid UTF-8 %v", len(r.Body), utf8.ValidString(r.Body))
		}
		if r.Title != report.Printable(r.Title) || utf8.RuneCountInString(r.Title) > maxTitleRunes {
			t.Fatalf("title %q", r.Title)
		}
		if r.SourceRef == "" || r.SourceRef != report.Printable(r.SourceRef) {
			t.Fatalf("source ref %q", r.SourceRef)
		}
		if len(r.PoC) > MaxPoCFiles {
			t.Fatalf("%d attachments", len(r.PoC))
		}
		total, seen := 0, map[string]bool{}
		for _, a := range r.PoC {
			total += len(a.Content)
			if a.Name == "" || a.Name != report.Printable(a.Name) || strings.ContainsAny(a.Name, `/\`) || strings.HasPrefix(a.Name, ".") || seen[a.Name] {
				t.Fatalf("attachment name %q", a.Name)
			}
			seen[a.Name] = true
		}
		if total > MaxPoCBytes {
			t.Fatalf("attachments total %d bytes", total)
		}
	})
}
