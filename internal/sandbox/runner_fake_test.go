package sandbox

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/config"
	"github.com/ergasterion-dev/kritolith/internal/report"
)

var (
	refSHA  = strings.Repeat("1", 40)
	headSHA = strings.Repeat("2", 40)
)

// vulnGo puts Parse on lines 4-6.
const vulnGo = `package vuln

// Parse indexes b.
func Parse(b []byte) byte {
	return b[3]
}

type T struct{}

func (t *T) M() int {
	return 1
}
`

func baseTree() map[string]string {
	return map[string]string{
		"go.mod":              "module example.com/m\n\ngo 1.21\n",
		"vuln/vuln.go":        vulnGo,
		"vuln/helper_test.go": "package vuln\n\nfunc helperOnly() { panic(1) }\n",
		"vuln/fuzz_test.go":   "package vuln\n\nimport \"testing\"\n\nfunc FuzzParse(f *testing.F) {}\n",
		"README.md":           "hi\n",
	}
}

func withFiles(t map[string]string, kv ...string) map[string]string {
	out := map[string]string{}
	for k, v := range t {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			delete(out, kv[i])
			continue
		}
		out[kv[i]] = kv[i+1]
	}
	return out
}

var parseClaim = report.Claim{Kind: report.ClaimFunction, Value: "vuln.Parse", Verified: report.TriYes, DeclPkgDir: "vuln", DeclName: "Parse"}
var helperClaim = report.Claim{Kind: report.ClaimFunction, Value: "helperOnly", Verified: report.TriYes, DeclPkgDir: "vuln", DeclName: "helperOnly"}

var testPoC = []report.Artifact{{Name: "poc_test.go", Content: []byte("package vuln\n\nimport \"testing\"\n\nfunc TestPoC(t *testing.T) { Parse(nil) }\n")}}

// fakeSource serves trees by commit.
type fakeSource struct {
	trees   map[string]map[string]string
	head    string
	headErr error
}

func (s *fakeSource) Archive(_ context.Context, commit, dst string) error {
	files, ok := s.trees[commit]
	if !ok {
		return fmt.Errorf("unknown commit %s", commit)
	}
	if err := os.Mkdir(dst, 0o700); err != nil {
		return err
	}
	for name, content := range files {
		p := filepath.Join(dst, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func (s *fakeSource) DefaultBranchRef(context.Context) (string, error) {
	return s.head, s.headErr
}

// step is one scripted container run.
type step struct {
	out      RunOutput
	err      error
	noBinary bool   // build: exit 0 but no binary written
	cover    string // run: coverage profile to leave in /out
	lock     bool   // leave a read-only tree (and a link to outside) in each writable mount
	panic    bool
}

type call struct {
	who, phase string // who: ref|head
	spec       RunSpec
	pocInFetch bool     // a PoC file was visible in a mount during fetch
	srcFiles   []string // files under the /src mount, for build and run
}

type fakeDriver struct {
	t       *testing.T
	mu      sync.Mutex
	script  map[string]step // "ref/fetch", "head/run", ...
	calls   []call
	fetches int
	pocName string
	outside string // target of the escaping link a lock step leaves
}

func phaseOf(args []string) string {
	switch {
	case len(args) >= 3 && args[0] == "go" && args[1] == "mod":
		return PhaseFetch
	case len(args) >= 2 && args[0] == "go":
		return PhaseBuild
	}
	return PhaseRun
}

func mountSource(s RunSpec, dest string) string {
	for _, m := range s.Container.Mounts {
		if m.Dest == dest {
			return m.Source
		}
	}
	return ""
}

func listFiles(root string) []string {
	var out []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(root, p)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(out)
	return out
}

func (f *fakeDriver) Run(ctx context.Context, s RunSpec) (RunOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := BuildOCI(s.Container); err != nil {
		f.t.Errorf("the runner built a spec BuildOCI refuses: %v", err)
	}
	phase := phaseOf(s.Container.Args)
	if phase == PhaseFetch {
		f.fetches++
	}
	who := "ref"
	if f.fetches > 1 {
		who = "head"
	}
	c := call{who: who, phase: phase, spec: s}
	if phase == PhaseFetch && f.pocName != "" {
		for _, m := range s.Container.Mounts {
			if m.Tmpfs {
				continue
			}
			for _, name := range listFiles(m.Source) {
				if strings.HasSuffix(name, f.pocName) {
					c.pocInFetch = true
				}
			}
		}
	}
	if src := mountSource(s, ctrSrc); src != "" {
		c.srcFiles = listFiles(src)
	}
	f.calls = append(f.calls, c)
	st, ok := f.script[who+"/"+phase]
	if !ok && phase == PhaseRun {
		st = step{out: RunOutput{Output: []byte(passOut)}}
	}
	if st.panic {
		panic("driver exploded")
	}
	if phase == PhaseBuild && st.err == nil && st.out.ExitCode == 0 && !st.noBinary {
		bin := testBinary
		if strings.Contains(strings.Join(s.Container.Args, " "), "go build") {
			bin = progBinary
		}
		if err := os.WriteFile(filepath.Join(mountSource(s, ctrOut), bin), []byte("bin"), 0o755); err != nil {
			f.t.Fatal(err)
		}
	}
	if st.lock {
		for _, m := range s.Container.Mounts {
			if m.Writable && !m.Tmpfs {
				readOnlyTree(f.t, m.Source, f.outside)
			}
		}
	}
	if phase == PhaseRun && st.cover != "" {
		if err := os.WriteFile(filepath.Join(mountSource(s, ctrOut), coverFile), []byte(st.cover), 0o644); err != nil {
			f.t.Fatal(err)
		}
	}
	if st.err == nil && ctx.Err() != nil {
		return RunOutput{ExitCode: -1}, ctx.Err()
	}
	return st.out, st.err
}

func (f *fakeDriver) phases() []string {
	var out []string
	for _, c := range f.calls {
		out = append(out, c.who+"/"+c.phase)
	}
	return out
}

const passOut = "=== RUN   TestPoC\n--- PASS: TestPoC (0.00s)\nPASS\n"

const panicOut = `=== RUN   TestPoC
--- FAIL: TestPoC (0.00s)
panic: runtime error: index out of range [3] with length 0 [recovered]

goroutine 4 [running]:
testing.tRunner.func1.2({0x1, 0x2})
	/usr/local/go/src/testing/testing.go:1974 +0x1a0
panic({0x1, 0x2})
	/usr/local/go/src/runtime/panic.go:860 +0x12c
example.com/m/vuln.Parse(...)
	/src/vuln/vuln.go:5
example.com/m/vuln.TestPoC(0x1)
	/src/vuln/poc_test.go:5 +0x20
testing.tRunner(0x1, 0x2)
	/usr/local/go/src/testing/testing.go:2036 +0xc4
created by testing.(*T).Run in goroutine 1
	/usr/local/go/src/testing/testing.go:2101 +0x3a8
`

const helperPanicOut = `=== RUN   TestPoC
--- FAIL: TestPoC (0.00s)
panic: 1 [recovered]

goroutine 4 [running]:
panic({0x1, 0x2})
	/usr/local/go/src/runtime/panic.go:860 +0x12c
example.com/m/vuln.helperOnly(...)
	/src/vuln/helper_test.go:3
example.com/m/vuln.TestPoC(0x1)
	/src/vuln/poc_test.go:5 +0x20
`

const assertOut = "=== RUN   TestPoC\n    poc_test.go:5: wrong\n--- FAIL: TestPoC (0.00s)\nFAIL\n"

// parseCover marks a statement inside Parse (lines 4-6) executed.
const parseCover = "mode: atomic\nexample.com/m/vuln/vuln.go:4.27,6.2 1 1\nexample.com/m/vuln/vuln.go:10.21,12.2 1 0\n"

var (
	stepPanic  = step{out: RunOutput{ExitCode: 2, Output: []byte(panicOut)}}
	stepAssert = step{out: RunOutput{ExitCode: 1, Output: []byte(assertOut)}, cover: parseCover}
	stepPass   = step{out: RunOutput{Output: []byte(passOut)}, cover: "mode: atomic\n"}
	stepBuildE = step{out: RunOutput{ExitCode: 1, Output: []byte("# example.com/m/vuln\nvuln/poc_test.go:5:30: undefined: Parse\n")}}
)

func testCfg(rootfs string) config.Sandbox {
	return config.Sandbox{Rootfs: rootfs, GoProxy: "https://proxy.example.org", MemoryMB: 1024, CPUs: 3, PIDs: 200,
		FetchTimeoutSeconds: 50, BuildTimeoutSeconds: 60, RunTimeoutSeconds: 30, OutputLimitKB: 64}
}

type fixture struct {
	src     *fakeSource
	drv     *fakeDriver
	runner  *Runner
	scratch string
	rootfs  string
}

func newFixture(t *testing.T, script map[string]step) *fixture {
	t.Helper()
	rootfs := t.TempDir()
	scratch := t.TempDir()
	src := &fakeSource{trees: map[string]map[string]string{refSHA: baseTree(), headSHA: baseTree()}, head: headSHA}
	drv := &fakeDriver{t: t, script: script, pocName: "poc_test.go"}
	return &fixture{src: src, drv: drv, runner: NewRunner(testCfg(rootfs), src, drv, scratch), scratch: scratch, rootfs: rootfs}
}

func (fx *fixture) run(t *testing.T, req Request) Result {
	t.Helper()
	if req.ResolvedRef == "" {
		req.ResolvedRef = refSHA
	}
	if req.Report.PoC == nil {
		req.Report.PoC = testPoC
	}
	if req.Claims == nil {
		req.Claims = []report.Claim{parseClaim}
	}
	res := fx.runner.Run(context.Background(), req)
	assertScratchEmpty(t, fx.scratch)
	return res
}

func assertScratchEmpty(t *testing.T, scratch string) {
	t.Helper()
	ents, err := os.ReadDir(scratch)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Fatalf("scratch directories left behind: %v", ents)
	}
}
