package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

const testSrc = "package graphql_test\n\nimport \"testing\"\n\nfunc TestX(t *testing.T) {}\n"

func art(name, content string) report.Artifact {
	return report.Artifact{Name: name, Content: []byte(content)}
}

func isNeedsInfo(err error) bool {
	var n *NeedsInfo
	return errors.As(err, &n)
}

func TestValidatePoCRejects(t *testing.T) {
	many := make([]report.Artifact, 65)
	for i := range many {
		many[i] = art(fmt.Sprintf("f%d_test.go", i), testSrc)
	}
	big := art("big_test.go", testSrc+strings.Repeat("//x\n", 70000))
	cases := []struct {
		name string
		arts []report.Artifact
	}{
		{"empty poc", nil},
		{"dotdot", []report.Artifact{art("../x", testSrc)}},
		{"absolute", []report.Artifact{art("/abs", testSrc)}},
		{"subdir", []report.Artifact{art("a/b.go", testSrc)}},
		{"dot", []report.Artifact{art(".", testSrc)}},
		{"empty name", []report.Artifact{art("", testSrc)}},
		{"nul", []report.Artifact{art("a\x00_test.go", testSrc)}},
		{"backslash", []report.Artifact{art(`a\b_test.go`, testSrc)}},
		{"control char", []report.Artifact{art("a\n_test.go", testSrc)}},
		{"too long", []report.Artifact{art(strings.Repeat("a", 250)+"_test.go", testSrc)}},
		{"duplicates", []report.Artifact{art("a_test.go", testSrc), art("a_test.go", testSrc)}},
		{"65 files", many},
		{"oversize file", []report.Artifact{big}},
		{"fuzz dotdot", []report.Artifact{art("testdata/fuzz/../x", "x")}},
		{"fuzz dotdot seed", []report.Artifact{art("testdata/fuzz/FuzzA/../x", "x")}},
		{"fuzz too deep", []report.Artifact{art("testdata/fuzz/FuzzA/b/seed", "x")}},
		{"fuzz abs", []report.Artifact{art("/testdata/fuzz/FuzzA/seed", "x")}},
		{"fuzz bad name", []report.Artifact{art("testdata/fuzz/Fuzz.*/seed", "x")}},
		{"fuzz two targets", []report.Artifact{art("testdata/fuzz/FuzzA/s", "x"), art("testdata/fuzz/FuzzB/s", "x")}},
		{"seed alternation", []report.Artifact{art("testdata/fuzz/FuzzA/a|.*", "x")}},
		{"seed space", []report.Artifact{art("testdata/fuzz/FuzzA/a b", "x")}},
		{"seed dollar", []report.Artifact{art("testdata/fuzz/FuzzA/a$", "x")}},
		{"seed paren", []report.Artifact{art("testdata/fuzz/FuzzA/a(", "x")}},
		{"fuzz mixed with go", []report.Artifact{art("testdata/fuzz/FuzzA/s", "x"), art("a_test.go", testSrc)}},
		{"no test func", []report.Artifact{art("a_test.go", "package a\n")}},
		{"syntax error", []report.Artifact{art("a_test.go", "package a\nfunc (")}},
		{"non go file", []report.Artifact{art("poc.txt", "hello")}},
		{"hidden go file", []report.Artifact{art("_a_test.go", testSrc)}},
		{"two programs", []report.Artifact{art("a.go", "package main\nfunc main(){}\n"), art("b.go", "package main\nfunc main(){}\n")}},
		{"program not main", []report.Artifact{art("a.go", "package a\nfunc main(){}\n")}},
		{"main without func", []report.Artifact{art("a.go", "package main\n")}},
		{"mixed packages", []report.Artifact{art("a_test.go", testSrc), art("b_test.go", "package other\nimport \"testing\"\nfunc TestY(t *testing.T){}\n")}},
		{"TestMain only", []report.Artifact{art("a_test.go", "package a\nimport \"testing\"\nfunc TestMain(m *testing.M){}\n")}},
		{"lowercase after Test", []report.Artifact{art("a_test.go", "package a\nimport \"testing\"\nfunc Testx(t *testing.T){}\n")}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ValidatePoC(c.arts)
			if !isNeedsInfo(err) {
				t.Fatalf("err = %v, want *NeedsInfo", err)
			}
			if err.Error() == "" {
				t.Fatal("empty reason")
			}
		})
	}
}

func TestValidatePoCShapes(t *testing.T) {
	cases := []struct {
		name string
		arts []report.Artifact
		want PoC
	}{
		{
			"test", []report.Artifact{art("poc_test.go", testSrc)},
			PoC{Shape: ShapeTest, TestNames: []string{"TestX"}, PkgName: "graphql"},
		},
		{
			"test same package, sorted names",
			[]report.Artifact{
				art("b_test.go", "package a\nimport \"testing\"\nfunc TestB(t *testing.T){}\nfunc helper(){}\n"),
				art("a_test.go", "package a_test\nimport \"testing\"\nfunc TestA(t *testing.T){}\n"),
			},
			PoC{Shape: ShapeTest, TestNames: []string{"TestA", "TestB"}, PkgName: "a"},
		},
		{
			"program", []report.Artifact{art("main.go", "package main\nfunc main(){}\n")},
			PoC{Shape: ShapeProgram, PkgName: "main"},
		},
		{
			"fuzz seed", []report.Artifact{art("testdata/fuzz/FuzzA/seed1", "go test fuzz v1\n")},
			PoC{Shape: ShapeFuzz, FuzzName: "FuzzA"},
		},
		{
			"fuzz seed with dot and dash", []report.Artifact{art("testdata/fuzz/FuzzA/seed-1.bin", "x")},
			PoC{Shape: ShapeFuzz, FuzzName: "FuzzA"},
		},
		{
			"fuzz several seeds", []report.Artifact{art("testdata/fuzz/FuzzA/s1", "x"), art("testdata/fuzz/FuzzA/s2", "y")},
			PoC{Shape: ShapeFuzz, FuzzName: "FuzzA"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ValidatePoC(c.arts)
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Files) != len(c.arts) {
				t.Fatalf("files = %d, want %d", len(got.Files), len(c.arts))
			}
			got.Files = nil
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestValidatePoCSizeBoundary(t *testing.T) {
	pad := strings.Repeat("a", maxFileBytes-len(testSrc)-2)
	ok := art("a_test.go", testSrc+"//"+pad)
	if len(ok.Content) != maxFileBytes {
		t.Fatalf("setup: %d", len(ok.Content))
	}
	if _, err := ValidatePoC([]report.Artifact{ok}); err != nil {
		t.Fatalf("exactly the limit: %v", err)
	}
	ok.Content = append(ok.Content, 'a')
	if _, err := ValidatePoC([]report.Artifact{ok}); !isNeedsInfo(err) {
		t.Fatalf("limit+1: %v", err)
	}
	// 64 files is fine.
	many := make([]report.Artifact, 64)
	for i := range many {
		many[i] = art(fmt.Sprintf("f%d_test.go", i), testSrc)
	}
	if _, err := ValidatePoC(many); err != nil {
		t.Fatalf("64 files: %v", err)
	}
}

// memTree is an in-memory Tree. Keys are slash paths of files.
type memTree map[string]string

func (m memTree) ReadDir(rel string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	prefix := ""
	if rel != "." {
		prefix = rel + "/"
	}
	found := rel == "."
	for p := range m {
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		found = true
		rest := strings.TrimPrefix(p, prefix)
		name := rest
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			name = rest[:i+1]
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	if !found {
		return nil, os.ErrNotExist
	}
	return out, nil
}

func (m memTree) ReadFile(rel string) ([]byte, error) {
	s, ok := m[rel]
	if !ok {
		return nil, os.ErrNotExist
	}
	return []byte(s), nil
}

func pkgFile(pkg string) string { return "package " + pkg + "\n" }

func claim(kind report.ClaimKind, dir string, v report.Tri) report.Claim {
	return report.Claim{Kind: kind, Value: "X", Verified: v, DeclPkgDir: dir}
}

func TestPlacePoC(t *testing.T) {
	poc := PoC{Shape: ShapeTest, PkgName: "graphql", TestNames: []string{"TestX"}}
	two := memTree{"go.mod": "module m\n", "a/a.go": pkgFile("graphql"), "b/b.go": pkgFile("graphql")}
	cases := []struct {
		name    string
		poc     PoC
		tree    memTree
		hint    string
		claims  []report.Claim
		want    string
		wantErr bool
	}{
		{"hint wins", poc, two, "b", []report.Claim{claim(report.ClaimFunction, "a", report.TriYes)}, "b", false},
		{"hint dot-slash cleaned", poc, two, "./b/", nil, "b", false},
		{"hint escapes", poc, two, "../x", nil, "", true},
		{"hint absolute", poc, two, "/etc", nil, "", true},
		{"hint missing", poc, two, "nope", nil, "", true},
		{"claim dir wins over second candidate", poc, two, "", []report.Claim{claim(report.ClaimFunction, "b", report.TriYes)}, "b", false},
		{"file claim counts", poc, two, "", []report.Claim{claim(report.ClaimFile, "a", report.TriYes)}, "a", false},
		{"unverified claim ignored, two candidates", poc, two, "", []report.Claim{claim(report.ClaimFunction, "a", report.TriUnknown)}, "", true},
		{"line claim ignored", poc, two, "", []report.Claim{claim(report.ClaimLine, "a", report.TriYes)}, "", true},
		{"claim dir without the package falls through to single", poc,
			memTree{"x/x.go": pkgFile("other"), "y/y.go": pkgFile("graphql")}, "",
			[]report.Claim{claim(report.ClaimFunction, "x", report.TriYes)}, "y", false},
		{"two candidates no claim", poc, two, "", nil, "", true},
		{"zero candidates", poc, memTree{"x/x.go": pkgFile("other")}, "", nil, "", true},
		{"go-2022-0300 style: graphql_test PoC places at root", poc,
			memTree{"go.mod": "module m\n", "graphql.go": pkgFile("graphql"), "internal/validation/v.go": pkgFile("validation")},
			"", []report.Claim{claim(report.ClaimFunction, "internal/validation", report.TriYes)}, ".", false},
		{"external test package in dir counts", poc,
			memTree{"q/q_test.go": pkgFile("graphql_test")}, "", nil, "q", false},
		{"skips testdata vendor hidden", poc,
			memTree{"a/a.go": pkgFile("graphql"), "testdata/t.go": pkgFile("graphql"), "vendor/v/v.go": pkgFile("graphql"), ".hid/h.go": pkgFile("graphql")},
			"", nil, "a", false},
		{"invalid claim dir ignored", poc, two, "", []report.Claim{claim(report.ClaimFunction, "../a", report.TriYes)}, "", true},
		{"fuzz with claim", PoC{Shape: ShapeFuzz, FuzzName: "FuzzA"}, two, "", []report.Claim{claim(report.ClaimFunction, "a", report.TriYes)}, "a", false},
		{"fuzz without claim", PoC{Shape: ShapeFuzz, FuzzName: "FuzzA"}, two, "", nil, "", true},
		{"program default root", PoC{Shape: ShapeProgram, PkgName: "main"}, two, "", nil, ".", false},
		{"program claim dir", PoC{Shape: ShapeProgram, PkgName: "main"}, two, "", []report.Claim{claim(report.ClaimFunction, "b", report.TriYes)}, "b", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := PlacePoC(c.poc, c.tree, c.hint, c.claims)
			if c.wantErr {
				if !isNeedsInfo(err) {
					t.Fatalf("err = %v, want *NeedsInfo", err)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("got %q, %v; want %q", got, err, c.want)
			}
		})
	}
}

func TestModuleRoot(t *testing.T) {
	tree := memTree{
		"go.mod": "module big\n", "big.go": pkgFile("big"),
		"math/go.mod": "module big/math\n", "math/m.go": pkgFile("math"), "math/sub/s.go": pkgFile("sub"),
		"other/o.go": pkgFile("o"),
	}
	cases := []struct {
		dir, want string
		wantErr   bool
	}{
		{"math", "math", false},
		{"math/sub", "math", false},
		{"other", ".", false},
		{".", ".", false},
		{"../x", "", true},
	}
	for _, c := range cases {
		got, err := ModuleRoot(tree, c.dir)
		if c.wantErr {
			if err == nil {
				t.Fatalf("%s: want error", c.dir)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Fatalf("%s: got %q, %v; want %q", c.dir, got, err, c.want)
		}
	}
	if _, err := ModuleRoot(memTree{"a/a.go": "x"}, "a"); err == nil {
		t.Fatal("no go.mod anywhere: want error")
	}
}

func TestCheckGoMod(t *testing.T) {
	cases := []struct {
		name, src string
		reject    bool
	}{
		{"ordinary", "module x\n\ngo 1.22\n\nrequire (\n\ta v1.0.0\n)\n", false},
		{"local replace outside", "module x\nreplace x => ../../etc\n", true},
		{"absolute replace", "module x\nreplace x => /abs\n", true},
		{"toolchain", "module x\ngo 1.22\ntoolchain go1.99\n", true},
		{"local replace inside", "module x\nreplace x => ./local\n", false},
		{"module replace", "module x\nreplace a v1.0.0 => b v1.2.0\n", false},
		{"block outside", "module x\nreplace (\n\ta => ../evil\n)\n", true},
		{"block inside", "module x\nreplace (\n\ta => ./a\n\tb v1 => c v2\n)\n", false},
		{"block with comments", "module x\nreplace (\n\t// note\n\ta => ./a // ok\n\tb => ../b\n)\n", true},
		{"quoted path", "module x\nreplace x => \"../../etc\"\n", true},
		{"backquoted path", "module x\nreplace x => `../..`\n", true},
		{"escaping via inside prefix", "module x\nreplace x => ./a/../../b\n", true},
		{"dotdot alone", "module x\nreplace x => ..\n", true},
		{"backslash path", "module x\nreplace x => ..\\evil\n", true},
		{"windows drive", "module x\nreplace x => C:\\evil\n", true},
		{"comment mentions toolchain", "module x\n// toolchain go1.99\n", false},
		{"toolchain in block", "module x\ntoolchain (\n\tgo1.99\n)\n", true},
		{"attached paren and arrow", "module x\nreplace(\n\ta=>../x\n)\n", true},
		{"version-ish local", "module x\nreplace x v1.0.0 => ../y\n", true},
		{"unterminated quote tolerated", "module x\nreplace x => \"../y\n", true},
		{"garbage tolerated", "\x00\xff((( ))) => =>\n", false},
		{"crlf", "module x\r\nreplace x => ../y\r\n", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := CheckGoMod([]byte(c.src))
			if c.reject {
				var inc *Inconclusive
				if !errors.As(err, &inc) || inc.Reason == "" {
					t.Fatalf("err = %v, want *Inconclusive", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected: %v", err)
			}
		})
	}
}

func TestDirTree(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{filepath.Join(root, "pkg"), outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "go.mod"), "module m\n")
	write(filepath.Join(root, "pkg", "p.go"), "package p\n")
	write(filepath.Join(outside, "secret"), "s3cret")
	link := func(target, name string) {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Skip("symlinks unavailable:", err)
		}
	}
	link(outside, "escape")
	link(filepath.Join(outside, "secret"), "secretlink")
	link("pkg", "inner")
	link("pkg/p.go", "innerfile")

	tr := DirTree(root)
	names, err := tr.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, n := range names {
		got[n] = true
	}
	for _, want := range []string{"go.mod", "pkg/", "inner/", "innerfile"} {
		if !got[want] {
			t.Errorf("missing %q in %v", want, names)
		}
	}
	for _, bad := range []string{"escape", "escape/", "secretlink"} {
		if got[bad] {
			t.Errorf("escaping entry %q listed", bad)
		}
	}
	if b, err := tr.ReadFile("pkg/p.go"); err != nil || string(b) != "package p\n" {
		t.Fatalf("ReadFile: %q %v", b, err)
	}
	if b, err := tr.ReadFile("innerfile"); err != nil || string(b) != "package p\n" {
		t.Fatalf("inside symlink: %q %v", b, err)
	}
	for _, rel := range []string{"escape/secret", "secretlink", "../outside/secret", "/etc/passwd", "pkg/../../outside/secret", "missing"} {
		if _, err := tr.ReadFile(rel); err == nil {
			t.Errorf("ReadFile(%q) succeeded", rel)
		}
	}
	for _, rel := range []string{"escape", "..", "/"} {
		if _, err := tr.ReadDir(rel); err == nil {
			t.Errorf("ReadDir(%q) succeeded", rel)
		}
	}
	if _, err := tr.ReadFile("pkg"); err == nil {
		t.Error("ReadFile of a directory succeeded")
	}
}

func FuzzValidatePoC(f *testing.F) {
	f.Add("poc_test.go", testSrc, "", "")
	f.Add("main.go", "package main\nfunc main(){}\n", "", "")
	f.Add("testdata/fuzz/FuzzA/seed1", "go test fuzz v1\n", "testdata/fuzz/FuzzA/seed2", "x")
	f.Add("../x", testSrc, "/abs", "x")
	f.Add("a_test.go", testSrc, "a_test.go", testSrc)
	f.Add("testdata/fuzz/../x", "x", "", "")
	f.Add("a\x00_test.go", testSrc, "a\\b", "x")
	f.Fuzz(func(t *testing.T, n1, c1, n2, c2 string) {
		arts := []report.Artifact{art(n1, c1)}
		if n2 != "" {
			arts = append(arts, art(n2, c2))
		}
		p, err := ValidatePoC(arts)
		if err != nil {
			if !isNeedsInfo(err) {
				t.Fatalf("non-NeedsInfo error %T", err)
			}
			return
		}
		if len(p.Files) == 0 || len(p.Files) > maxFiles {
			t.Fatalf("bad file count %d", len(p.Files))
		}
		for _, a := range p.Files {
			if len(a.Content) > maxFileBytes {
				t.Fatal("oversize accepted")
			}
			if checkName(a.Name) != nil && checkFuzzName(a.Name) == nil {
				continue
			}
			if err := checkName(a.Name); err != nil {
				t.Fatalf("accepted bad name %q: %v", a.Name, err)
			}
		}
		if p.Shape != ShapeTest && p.Shape != ShapeProgram && p.Shape != ShapeFuzz {
			t.Fatalf("bad shape %q", p.Shape)
		}
	})
}

func TestPlacePoCWalkTruncated(t *testing.T) {
	old := maxWalkDirs
	maxWalkDirs = 3
	defer func() { maxWalkDirs = old }()
	tree := memTree{"a/a.go": pkgFile("other"), "b/b.go": pkgFile("other"), "c/c.go": pkgFile("other"), "d/d.go": pkgFile("graphql")}
	poc := PoC{Shape: ShapeTest, PkgName: "graphql"}
	if _, err := PlacePoC(poc, tree, "", nil); !isNeedsInfo(err) || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("err = %v, want too-large NeedsInfo", err)
	}
	// A hint or a verified claim directory decides before any walk.
	if d, err := PlacePoC(poc, tree, "d", nil); err != nil || d != "d" {
		t.Fatalf("hint: %q %v", d, err)
	}
	if d, err := PlacePoC(poc, tree, "", []report.Claim{claim(report.ClaimFunction, "d", report.TriYes)}); err != nil || d != "d" {
		t.Fatalf("claim: %q %v", d, err)
	}
}

func TestPlaceProgramModules(t *testing.T) {
	tree := memTree{
		"go.mod": "module m\n", "x/x.go": pkgFile("x"), "y/y.go": pkgFile("y"),
		"sub/go.mod": "module m/sub\n", "sub/s.go": pkgFile("s"),
	}
	prog := PoC{Shape: ShapeProgram, PkgName: "main"}
	two := func(a, b string) []report.Claim {
		return []report.Claim{claim(report.ClaimFunction, a, report.TriYes), claim(report.ClaimFunction, b, report.TriYes)}
	}
	if d, err := PlacePoC(prog, tree, "", two("x", "y")); err != nil || d != "x" {
		t.Fatalf("same module: %q %v", d, err)
	}
	if _, err := PlacePoC(prog, tree, "", two("x", "sub")); !isNeedsInfo(err) {
		t.Fatalf("different modules: %v", err)
	}
}
