package sandbox

import (
	"errors"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// The sandbox integration fixtures live in testdata/sandbox and every
// file there ends in fixtureSuffix, so no Go tool ever builds, vets or
// runs them outside the sandbox. This file holds what the tagged
// integration tests share with the plain suite, plus plain tests that
// keep the fixtures inert and well-formed on any OS, without runsc.

// fixtureSuffix marks a sandbox fixture file; the loader strips it.
const fixtureSuffix = ".fixture"

// Placeholders a fixture may contain; the integration test fills them
// with the real host paths and addresses of the run.
const (
	phDataDir    = "@@DATA_DIR@@"
	phHostCanary = "@@HOST_CANARY@@"
	phHostHTTP   = "@@HOST_HTTP@@"
	phHostIPHTTP = "@@HOST_IP_HTTP@@"
	phOrigin     = "@@ORIGIN@@"
)

// escapeMarker is what a hostile fixture prints when an attempt that
// must fail succeeded.
const escapeMarker = "KRITOLITH-ESCAPE"

// hostileFixture is one directory under testdata/sandbox/hostile.
type hostileFixture struct {
	name string
	// needsCgroups: only meaningful with cgroup limits in force (the
	// memory cap); skipped under ignore_cgroups.
	needsCgroups bool
	// repoLinks: the hostile repository commits symlinks pointing out
	// of the tree next to the claimed code.
	repoLinks bool
	// reason is a substring of the Inconclusive/NeedsInfo reason; ""
	// accepts any.
	reason string
	// noContainer: refused before any container runs.
	noContainer bool
}

var hostileFixtures = []hostileFixture{
	{name: "fork-bomb"},
	{name: "memory-bomb", needsCgroups: true},
	{name: "infinite-loop"},
	{name: "output-flood"},
	{name: "out-flood"},
	{name: "network"},
	{name: "read-host"},
	{name: "write-source"},
	{name: "read-data-dir"},
	{name: "symlink-names", repoLinks: true},
	{name: "gomod-replace", reason: "replaces a module", noContainer: true},
	{name: "gomod-toolchain", reason: "toolchain line", noContainer: true},
	{name: "exit-1"},
	{name: "panic-outside-claimed-code"},
}

// hostilePoCNames are PoC file names that must be refused (NEEDS_INFO)
// before anything is written or run.
var hostilePoCNames = []string{
	"../escape_test.go",
	"a/../escape_test.go",
	"/abs_test.go",
	"..",
	".",
	"sub/escape_test.go",
	`..\escape_test.go`,
	"escape_test.go\x00.txt",
	"testdata/fuzz/FuzzX/../../../../escape",
	"testdata/fuzz/FuzzParse/..",
	"testdata/fuzz/../../escape_test.go",
}

// fixturePath is a path under testdata/sandbox at the repository root.
func fixturePath(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "testdata", "sandbox"}, parts...)...)
}

// readFixtureTree reads every *.fixture file under dir, keyed by its
// slash path relative to dir without the suffix, with placeholders
// replaced. A missing dir is an empty tree.
func readFixtureTree(t *testing.T, dir string, subst map[string]string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, fixtureSuffix) {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		s := string(b)
		for k, v := range subst {
			s = strings.ReplaceAll(s, k, v)
		}
		out[strings.TrimSuffix(filepath.ToSlash(rel), fixtureSuffix)] = []byte(s)
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("read fixture %s: %v", dir, err)
	}
	return out
}

// fixtureArtifacts reads a PoC fixture directory as report artifacts,
// sorted by name.
func fixtureArtifacts(t *testing.T, dir string, subst map[string]string) []report.Artifact {
	t.Helper()
	tree := readFixtureTree(t, dir, subst)
	if len(tree) == 0 {
		t.Fatalf("PoC fixture %s is empty", dir)
	}
	names := make([]string, 0, len(tree))
	for n := range tree {
		names = append(names, n)
	}
	sort.Strings(names)
	arts := make([]report.Artifact, 0, len(names))
	for _, n := range names {
		arts = append(arts, report.Artifact{Name: n, Content: tree[n]})
	}
	return arts
}

// dummySubst fills placeholders with plausible values for the checks
// that run without a sandbox.
var dummySubst = map[string]string{
	phDataDir: "/var/lib/kritolith-test", phHostCanary: "/tmp/kritolith-canary/canary.txt",
	phHostHTTP: "127.0.0.1:9", phHostIPHTTP: "192.0.2.1:9", phOrigin: "/tmp/kritolith-origin",
}

// TestSandboxFixturesAreInert keeps the hostile programs away from the
// Go tooling: every file under testdata/sandbox ends in .fixture (so
// `go build/vet/test ./...` and gofmt never see Go source or a go.mod
// there) and nothing is a symlink.
func TestSandboxFixturesAreInert(t *testing.T) {
	n := 0
	err := filepath.WalkDir(fixturePath(), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			t.Errorf("%s is a symlink; fixtures must be regular files", p)
		case d.IsDir():
		case !strings.HasSuffix(p, fixtureSuffix):
			t.Errorf("%s does not end in %s; a Go tool could pick it up", p, fixtureSuffix)
		default:
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no fixtures found")
	}
}

// TestSandboxFixturesWellFormed checks, without runsc, that each fixture
// is what the integration tests expect: the set of hostile directories
// matches the table, every Go file parses, every PoC is a valid test
// PoC, the base repository's go.mod is accepted and the hostile ones are
// refused for the stated reason, and every bad PoC name is NEEDS_INFO.
func TestSandboxFixturesWellFormed(t *testing.T) {
	ents, err := os.ReadDir(fixturePath("hostile"))
	if err != nil {
		t.Fatal(err)
	}
	var dirs, want []string
	for _, e := range ents {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	for _, f := range hostileFixtures {
		want = append(want, f.name)
	}
	sort.Strings(want)
	if strings.Join(dirs, ",") != strings.Join(want, ",") {
		t.Fatalf("hostile fixture dirs = %v, table = %v", dirs, want)
	}

	parseAll := func(name string, tree map[string][]byte) {
		for p, b := range tree {
			if strings.HasSuffix(p, ".go") {
				if _, err := parser.ParseFile(token.NewFileSet(), p, b, parser.AllErrors); err != nil {
					t.Errorf("%s: %s does not parse: %v", name, p, err)
				}
			}
		}
	}
	base := readFixtureTree(t, fixturePath("repo"), dummySubst)
	parseAll("repo", base)
	parseAll("repo-fixed", readFixtureTree(t, fixturePath("repo-fixed"), dummySubst))
	if err := CheckGoMod(base["go.mod"]); err != nil {
		t.Errorf("base repo go.mod refused: %v", err)
	}
	if goModModule(base["go.mod"]) != "example.com/victim" {
		t.Errorf("base repo module = %q", goModModule(base["go.mod"]))
	}

	checkPoC := func(name, dir string) {
		arts := fixtureArtifacts(t, dir, dummySubst)
		tree := map[string][]byte{}
		for _, a := range arts {
			tree[a.Name] = a.Content
		}
		parseAll(name, tree)
		p, err := ValidatePoC(arts)
		if err != nil {
			t.Errorf("%s: PoC invalid: %v", name, err)
			return
		}
		if p.Shape != ShapeTest || p.PkgName != "vuln" {
			t.Errorf("%s: PoC shape %s package %q, want a test PoC of package vuln", name, p.Shape, p.PkgName)
		}
	}
	checkPoC("poc/benign", fixturePath("poc", "benign"))
	checkPoC("poc/panic", fixturePath("poc", "panic"))
	for _, f := range hostileFixtures {
		checkPoC(f.name, fixturePath("hostile", f.name, "poc"))
		overlay := readFixtureTree(t, fixturePath("hostile", f.name, "repo"), dummySubst)
		parseAll(f.name+"/repo", overlay)
		gomod, ok := overlay["go.mod"]
		if !ok {
			if f.noContainer {
				t.Errorf("%s: refused before a container, but has no go.mod overlay", f.name)
			}
			continue
		}
		err := CheckGoMod(gomod)
		var inc *Inconclusive
		if !errors.As(err, &inc) || !strings.Contains(inc.Reason, f.reason) {
			t.Errorf("%s: CheckGoMod = %v, want Inconclusive containing %q", f.name, err, f.reason)
		}
	}

	for _, n := range hostilePoCNames {
		_, err := ValidatePoC([]report.Artifact{{Name: n, Content: []byte("package vuln\n")}})
		var ni *NeedsInfo
		if !errors.As(err, &ni) {
			t.Errorf("ValidatePoC(name %q) = %v, want NeedsInfo", n, err)
		}
	}
}
