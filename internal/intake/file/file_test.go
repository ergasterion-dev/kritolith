package file

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

var fixedNow = func() time.Time { return time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC) }

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func opts(t *testing.T, reportPath string) Options {
	return Options{
		Repo:       "golang/net",
		Ref:        "e1fcd82abba34df74614020343be8eb1fe85f0d9",
		ReportPath: reportPath,
		Now:        fixedNow,
		Rand:       bytes.NewReader(make([]byte, 10)),
	}
}

func TestLoadBasic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "report.md")
	writeFile(t, p, "\n\n## HTTP/2 over-read in parseContinuationFrame\n\nDetails here.\n")
	r, err := Load(opts(t, p))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.ID) != 26 {
		t.Errorf("ID = %q, want a 26-char ULID", r.ID)
	}
	if r.Source != report.SourceFile || r.SourceRef != p || r.Repo != "golang/net" {
		t.Errorf("unexpected source fields: %+v", r)
	}
	if r.Title != "HTTP/2 over-read in parseContinuationFrame" {
		t.Errorf("Title = %q", r.Title)
	}
	if !r.ReceivedAt.Equal(fixedNow()) || r.PoC != nil {
		t.Errorf("ReceivedAt=%v PoC=%v", r.ReceivedAt, r.PoC)
	}
}

func TestLoadEmptyRefAllowed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "report.md")
	writeFile(t, p, "no ref given")
	o := opts(t, p)
	o.Ref = ""
	r, err := Load(o)
	if err != nil || r.ClaimedRef != "" {
		t.Fatalf("r.ClaimedRef=%q err=%v", r.ClaimedRef, err)
	}
}

func TestLoadTitleSanitized(t *testing.T) {
	p := filepath.Join(t.TempDir(), "report.md")
	writeFile(t, p, "# evil\x1b[2J ‮title\n"+strings.Repeat("x", 500))
	r, err := Load(opts(t, p))
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(r.Title, "\x1b‮") {
		t.Errorf("title not sanitized: %q", r.Title)
	}
	p2 := filepath.Join(t.TempDir(), "long.md")
	writeFile(t, p2, strings.Repeat("y", 500))
	r2, err := Load(opts(t, p2))
	if err != nil {
		t.Fatal(err)
	}
	if n := len([]rune(r2.Title)); n != maxTitleRunes {
		t.Errorf("title length = %d, want %d", n, maxTitleRunes)
	}
}

func TestLoadInvalidUTF8Replaced(t *testing.T) {
	p := filepath.Join(t.TempDir(), "report.md")
	writeFile(t, p, "bad \xff\xfe bytes")
	r, err := Load(opts(t, p))
	if err != nil {
		t.Fatal(err)
	}
	if r.Body != "bad � bytes" {
		t.Errorf("Body = %q", r.Body)
	}
}

func TestLoadRejects(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "report.md")
	writeFile(t, good, "ok")
	big := filepath.Join(dir, "big.md")
	writeFile(t, big, strings.Repeat("a", MaxReportBytes+1))

	tests := []struct {
		name    string
		mutate  func(*Options)
		wantErr string
	}{
		{"bad repo", func(o *Options) { o.Repo = "not-a-repo" }, "invalid repo"},
		{"option-like ref", func(o *Options) { o.Ref = "--upload-pack=touch /tmp/pwned" }, "invalid ref"},
		{"missing file", func(o *Options) { o.ReportPath = filepath.Join(dir, "missing.md") }, "no such file"},
		{"directory", func(o *Options) { o.ReportPath = dir }, "not a regular file"},
		{"too big", func(o *Options) { o.ReportPath = big }, "limit"},
		{"poc dir missing", func(o *Options) { o.PoCDir = filepath.Join(dir, "nope") }, "poc"},
		{"poc dir is a file", func(o *Options) { o.PoCDir = good }, "not a directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := opts(t, good)
			tt.mutate(&o)
			_, err := Load(o)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadPoC(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "report.md")
	writeFile(t, p, "report")
	poc := filepath.Join(dir, "poc")
	writeFile(t, filepath.Join(poc, "sub", "b.txt"), "B")
	writeFile(t, filepath.Join(poc, "a_test.go"), "package x")
	o := opts(t, p)
	o.PoCDir = poc
	r, err := Load(o)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.PoC) != 2 || r.PoC[0].Name != "a_test.go" || r.PoC[1].Name != "sub/b.txt" || string(r.PoC[1].Content) != "B" {
		t.Fatalf("PoC = %+v", r.PoC)
	}
}

func TestLoadPoCRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "report.md")
	writeFile(t, p, "report")
	secret := filepath.Join(dir, "secret")
	writeFile(t, secret, "PRIVATE KEY")
	poc := filepath.Join(dir, "poc")
	if err := os.MkdirAll(poc, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(poc, "leak")); err != nil {
		t.Fatal(err)
	}
	o := opts(t, p)
	o.PoCDir = poc
	_, err := Load(o)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("err = %v, want symlink rejection", err)
	}
}

func TestLoadPoCRejectsSymlinkedDir(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "report.md")
	writeFile(t, p, "report")

	elsewhere := t.TempDir()
	writeFile(t, filepath.Join(elsewhere, "secret.txt"), "PRIVATE KEY")

	poc := filepath.Join(dir, "poc")
	if err := os.MkdirAll(poc, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(poc, "sub")); err != nil {
		t.Fatal(err)
	}
	o := opts(t, p)
	o.PoCDir = poc
	r, err := Load(o)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("err = %v, want symlink rejection", err)
	}
	for _, a := range r.PoC {
		if strings.Contains(string(a.Content), "PRIVATE KEY") {
			t.Fatalf("secret leaked into PoC artifacts: %+v", a)
		}
	}
}

func TestLoadPoCLimits(t *testing.T) {
	t.Run("too many files", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "report.md")
		writeFile(t, p, "report")
		poc := filepath.Join(dir, "poc")
		for i := 0; i <= MaxPoCFiles; i++ {
			writeFile(t, filepath.Join(poc, fmt.Sprintf("f%03d", i)), "x")
		}
		o := opts(t, p)
		o.PoCDir = poc
		if _, err := Load(o); err == nil || !strings.Contains(err.Error(), "too many") {
			t.Fatalf("err = %v, want too-many-files", err)
		}
	})
	t.Run("too many bytes", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "report.md")
		writeFile(t, p, "report")
		poc := filepath.Join(dir, "poc")
		writeFile(t, filepath.Join(poc, "a"), strings.Repeat("a", MaxPoCBytes/2))
		writeFile(t, filepath.Join(poc, "b"), strings.Repeat("b", MaxPoCBytes/2+1))
		o := opts(t, p)
		o.PoCDir = poc
		if _, err := Load(o); err == nil || !strings.Contains(err.Error(), "limit") {
			t.Fatalf("err = %v, want size limit", err)
		}
	})
}
