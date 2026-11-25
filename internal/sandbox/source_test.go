package sandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

func TestRunArgsQuoteEveryName(t *testing.T) {
	p := PoC{Shape: ShapeTest, TestNames: []string{"TestA", "TestB"}}
	args := runArgs(p, 10*time.Second, false)
	if !hasArg(args, "-test.run=^(?:TestA|TestB)$") || !hasArg(args, "-test.timeout=9s") || hasArg(args, "-test.coverprofile=/out/cover.out") {
		t.Fatalf("args %q", args)
	}
	f := PoC{Shape: ShapeFuzz, FuzzName: "FuzzX", Files: []report.Artifact{{Name: "testdata/fuzz/FuzzX/a.b"}, {Name: "testdata/fuzz/FuzzX/c-d"}}}
	if args := runArgs(f, time.Second, true); !hasArg(args, `-test.run=^FuzzX$/^(?:a\.b|c-d)$`) || !hasArg(args, "-test.timeout=1s") {
		t.Fatalf("fuzz args %q", args)
	}
}

func TestClaimRangesDropsTestHelpers(t *testing.T) {
	root := t.TempDir()
	src := &fakeSource{trees: map[string]map[string]string{refSHA: withFiles(baseTree(),
		"vuln/linux.go", "package vuln\n\nfunc (t T) Plat() {}\n",
		"vuln/x_test.go", "package vuln\n\nfunc (t T) Plat() {}\n")}}
	dst := filepath.Join(root, "src")
	if err := src.Archive(context.Background(), refSHA, dst); err != nil {
		t.Fatal(err)
	}
	claims := []report.Claim{parseClaim, helperClaim,
		{Kind: report.ClaimFunction, Verified: report.TriYes, DeclPkgDir: "vuln", DeclReceiver: "T", DeclName: "M"},
		{Kind: report.ClaimFunction, Verified: report.TriYes, DeclPkgDir: "vuln", DeclReceiver: "T", DeclName: "Plat"},
		{Kind: report.ClaimFunction, Verified: report.TriYes, DeclPkgDir: "vuln", DeclName: "Gone"},
	}
	kept, ranges := claimRanges(DirTree(dst), ".", moduleClaims(DirTree(dst), ".", claims))
	var names []string
	for _, c := range kept {
		names = append(names, c.DeclName)
	}
	if strings.Join(names, ",") != "Parse,M,Plat" {
		t.Fatalf("kept %v, want Parse,M,Plat (test-only helper and missing func dropped)", names)
	}
	want := map[string][]FuncRange{
		"vuln/vuln.go":  {{Name: "Parse", Start: 4, End: 6}, {Name: "T.M", Start: 10, End: 12}},
		"vuln/linux.go": {{Name: "T.Plat", Start: 3, End: 3}},
	}
	if fmt.Sprint(ranges) != fmt.Sprint(want) {
		t.Fatalf("ranges %v, want %v", ranges, want)
	}
}

func TestCopyTreeDropsEscapingLinks(t *testing.T) {
	src := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "d", "f.go"), []byte("package d\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{
		"in":      "d/f.go",
		"abs":     filepath.Join(outside, "secret"),
		"up":      "../" + filepath.Base(outside) + "/secret",
		"d/par":   "..",
		"through": "d/par/..",
		"dangle":  "nope",
	}
	for n, target := range links {
		if err := os.Symlink(target, filepath.Join(src, filepath.FromSlash(n))); err != nil {
			t.Fatal(err)
		}
	}
	dst := filepath.Join(t.TempDir(), "copy")
	if err := copyTree(src, dst); err != nil {
		t.Fatal(err)
	}
	got := listFiles(dst)
	sort.Strings(got)
	if strings.Join(got, ",") != "d/f.go,d/par,in" {
		t.Fatalf("copied %v, want d/f.go, d/par, in only", got)
	}
	if fi, err := os.Stat(filepath.Join(dst, "d", "f.go")); err != nil || fi.Mode().Perm()&0o100 == 0 {
		t.Fatalf("exec bit lost: %v %v", fi, err)
	}
}

func TestReadBoundedRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("host secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(dir, coverFile)); err != nil {
		t.Fatal(err)
	}
	if b, err := readBounded(filepath.Join(dir, coverFile), 100); err == nil {
		t.Fatalf("read %q through a symlink", b)
	}
	if err := os.WriteFile(filepath.Join(dir, "big"), []byte(strings.Repeat("x", 50)), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := readBounded(filepath.Join(dir, "big"), 10); err != nil || len(b) != 10 {
		t.Fatalf("bounded read = %d bytes, %v", len(b), err)
	}
}

func TestGoModModule(t *testing.T) {
	for in, want := range map[string]string{
		"module example.com/m\n":                "example.com/m",
		"// c\nmodule \"example.com/q\" // x\n": "example.com/q",
		"\xef\xbb\xbfmodule a.b/c\ngo 1.21\n":   "a.b/c",
		"go 1.21\n":                             "",
		"module ../evil\n":                      "",
		"module example.com/m extra\n":          "",
		"module (\n":                            "",
	} {
		if got := goModModule([]byte(in)); got != want {
			t.Errorf("goModModule(%q) = %q, want %q", in, got, want)
		}
	}
}
