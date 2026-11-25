package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

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

// TestRunnerOutcomes covers the spec's phase table and every failure
// path: none may escape as an error or a panic, and every one that is
// not a reproduction or a clean pass is Inconclusive with its phase.
func TestRunnerOutcomes(t *testing.T) {
	tests := []struct {
		name         string
		script       map[string]step
		claims       []report.Claim
		headErr      error
		headIsRef    bool
		headTree     map[string]string
		viaFallback  bool
		reproduced   bool
		weak         bool
		passed       bool
		control      string
		phase        string
		inconclusive string // substring; "" means none
		signal       string // substring of Repro.Signal
		note         string // substring of some Repro note
		phases       []string
	}{
		{name: "panic at ref, passes at HEAD", script: map[string]step{"ref/run": stepPanic, "head/run": stepPass},
			reproduced: true, control: ControlFixed, phase: PhaseControl, signal: KindPanic,
			phases: []string{"ref/fetch", "ref/build", "ref/run", "head/fetch", "head/build", "head/run"}},
		{name: "panic at ref and at HEAD", script: map[string]step{"ref/run": stepPanic, "head/run": stepPanic},
			reproduced: true, control: ControlStillReproduces, phase: PhaseControl, signal: KindPanic},
		{name: "assertion at ref, passes at HEAD", script: map[string]step{"ref/run": stepAssert, "head/run": stepPass},
			reproduced: true, weak: true, control: ControlFixed, phase: PhaseControl, signal: KindFailingTest},
		{name: "assertion at ref and at HEAD", script: map[string]step{"ref/run": stepAssert, "head/run": stepAssert},
			weak: true, control: ControlStillReproduces, phase: PhaseControl, inconclusive: weakAtHeadNote, note: weakAtHeadNote},
		{name: "panic, control does not build", script: map[string]step{"ref/run": stepPanic, "head/build": stepBuildE},
			reproduced: true, control: ControlUnavailable, phase: PhaseControl, note: "could not be re-run at HEAD"},
		{name: "assertion, control does not build", script: map[string]step{"ref/run": stepAssert, "head/build": stepBuildE},
			weak: true, control: ControlUnavailable, phase: PhaseControl, inconclusive: "could not be re-run at HEAD"},
		{name: "panic, control fetch fails", script: map[string]step{"ref/run": stepPanic, "head/fetch": {out: RunOutput{ExitCode: 1}}},
			reproduced: true, control: ControlUnavailable},
		{name: "panic, control times out", script: map[string]step{"ref/run": stepPanic, "head/run": {out: RunOutput{ExitCode: -1, TimedOut: true}}},
			reproduced: true, control: ControlUnavailable},
		{name: "panic, control crashes outside claimed code", script: map[string]step{"ref/run": stepPanic, "head/run": {out: RunOutput{ExitCode: 2, Output: []byte(helperPanicOut)}}},
			reproduced: true, control: ControlUnavailable},
		{name: "panic, HEAD unresolvable", script: map[string]step{"ref/run": stepPanic}, headErr: errors.New("offline"),
			reproduced: true, control: ControlUnavailable, phases: []string{"ref/fetch", "ref/build", "ref/run"}},
		{name: "panic, ref is HEAD", script: map[string]step{"ref/run": stepPanic}, headIsRef: true,
			reproduced: true, control: ControlStillReproduces, phases: []string{"ref/fetch", "ref/build", "ref/run"}},
		{name: "panic, PoC directory gone at HEAD", script: map[string]step{"ref/run": stepPanic},
			headTree:   map[string]string{"go.mod": "module example.com/m\n", "other/o.go": "package other\n"},
			reproduced: true, control: ControlUnavailable, phases: []string{"ref/fetch", "ref/build", "ref/run"}},
		{name: "passes at ref", script: map[string]step{"ref/run": stepPass},
			passed: true, phase: PhaseRun, signal: ReasonPassed, phases: []string{"ref/fetch", "ref/build", "ref/run"}},
		{name: "passes at ref through a fallback version", script: map[string]step{"ref/run": stepPass}, viaFallback: true,
			passed: true, phase: PhaseRun, note: "fallback version"},
		{name: "fetch exits non-zero", script: map[string]step{"ref/fetch": {out: RunOutput{ExitCode: 1, Output: []byte("go: bad")}}},
			phase: PhaseFetch, inconclusive: "go mod download failed", phases: []string{"ref/fetch"}},
		{name: "fetch driver error", script: map[string]step{"ref/fetch": {err: errors.New("runsc would not start")}},
			phase: PhaseFetch, inconclusive: "could not run"},
		{name: "fetch timeout", script: map[string]step{"ref/fetch": {out: RunOutput{ExitCode: -1, TimedOut: true}}},
			phase: PhaseFetch, inconclusive: "time limit"},
		{name: "fetch needs newer go", script: map[string]step{"ref/fetch": {out: RunOutput{ExitCode: 1, Output: []byte("go: go.mod requires go >= 1.99 (running go 1.26.0; GOTOOLCHAIN=local)\n")}}},
			phase: PhaseFetch, inconclusive: "newer Go"},
		{name: "build error", script: map[string]step{"ref/build": stepBuildE},
			phase: PhaseBuild, inconclusive: "does not build at this ref", signal: ReasonBuild, phases: []string{"ref/fetch", "ref/build"}},
		{name: "build needs newer go", script: map[string]step{"ref/build": {out: RunOutput{ExitCode: 1, Output: []byte("go: go.mod requires go >= 1.99\n")}}},
			phase: PhaseBuild, inconclusive: "newer Go"},
		{name: "build timeout", script: map[string]step{"ref/build": {out: RunOutput{ExitCode: -1, TimedOut: true}}},
			phase: PhaseBuild, inconclusive: "time limit"},
		{name: "build makes no binary (build constraints)", script: map[string]step{"ref/build": {noBinary: true, out: RunOutput{Output: []byte("?   \texample.com/m/vuln\t[no test files]\n")}}},
			phase: PhaseBuild, inconclusive: "no test ran", phases: []string{"ref/fetch", "ref/build"}},
		{name: "run timeout", script: map[string]step{"ref/run": {out: RunOutput{ExitCode: -1, TimedOut: true}}},
			phase: PhaseRun, inconclusive: "time limit", signal: ReasonTimeout},
		{name: "run odd exit code", script: map[string]step{"ref/run": {out: RunOutput{ExitCode: 137}}},
			phase: PhaseRun, inconclusive: "exited 137"},
		{name: "run os.Exit(1)", script: map[string]step{"ref/run": {out: RunOutput{ExitCode: 1, Output: []byte("=== RUN   TestPoC\n")}}},
			phase: PhaseRun, inconclusive: "without a signal"},
		{name: "run no tests to run", script: map[string]step{"ref/run": {out: RunOutput{Output: []byte("testing: warning: no tests to run\nPASS\n")}}},
			phase: PhaseRun, inconclusive: "no test ran"},
		{name: "run exit 0 without a test result", script: map[string]step{"ref/run": {out: RunOutput{Output: []byte("hello\n")}}},
			phase: PhaseRun, inconclusive: "no test result"},
		{name: "build text in run output is not a build failure", script: map[string]step{"ref/run": {out: RunOutput{ExitCode: 1, Output: []byte("FAIL\texample.com/m/vuln [build failed]\n")}}},
			phase: PhaseRun, inconclusive: "without a signal", signal: ReasonExitNoSignal},
		{name: "run truncated", script: map[string]step{"ref/run": {out: RunOutput{ExitCode: 1, Truncated: true, Output: []byte("x\n")}}},
			phase: PhaseRun, inconclusive: "truncated"},
		{name: "run driver error", script: map[string]step{"ref/run": {err: errors.New("delete failed")}},
			phase: PhaseRun, inconclusive: "could not run"},
		{name: "panic in a repo test helper does not count", script: map[string]step{"ref/run": {out: RunOutput{ExitCode: 2, Output: []byte(helperPanicOut)}}},
			claims: []report.Claim{helperClaim}, phase: PhaseRun, inconclusive: "not in claimed code", note: "no verified claim"},
		{name: "panic with no verified claims", script: map[string]step{"ref/run": stepPanic},
			claims: []report.Claim{{Kind: report.ClaimFunction, Value: "vuln.Parse", Verified: report.TriUnknown}}, phase: PhaseRun, inconclusive: "not in claimed code"},
		{name: "driver panic", script: map[string]step{"ref/build": {panic: true}},
			inconclusive: "failed internally"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newFixture(t, tt.script)
			fx.src.headErr = tt.headErr
			if tt.headIsRef {
				fx.src.head = refSHA
			}
			if tt.headTree != nil {
				fx.src.trees[headSHA] = tt.headTree
			}
			res := fx.run(t, Request{Claims: tt.claims, ViaFallback: tt.viaFallback})
			if res.Skipped != "" || res.NeedsInfo != "" {
				t.Fatalf("Skipped %q NeedsInfo %q", res.Skipped, res.NeedsInfo)
			}
			if tt.inconclusive == "" && res.Inconclusive != "" || !strings.Contains(res.Inconclusive, tt.inconclusive) {
				t.Fatalf("Inconclusive = %q, want %q", res.Inconclusive, tt.inconclusive)
			}
			if tt.name == "driver panic" {
				return
			}
			rr := res.Repro
			if rr == nil {
				t.Fatal("Repro is nil")
			}
			if rr.Reproduced != tt.reproduced || res.Weak != tt.weak || res.Passed != tt.passed {
				t.Fatalf("Reproduced %v Weak %v Passed %v, want %v %v %v (signal %q, notes %q)", rr.Reproduced, res.Weak, res.Passed, tt.reproduced, tt.weak, tt.passed, rr.Signal, rr.Notes)
			}
			if rr.ControlState != tt.control {
				t.Fatalf("ControlState = %q, want %q (notes %q)", rr.ControlState, tt.control, rr.Notes)
			}
			if tt.control != "" && tt.headErr == nil && rr.Control == nil {
				t.Fatal("ControlState set without a Control result")
			}
			if tt.phase != "" && rr.Phase != tt.phase {
				t.Fatalf("Phase = %q, want %q", rr.Phase, tt.phase)
			}
			if !strings.Contains(rr.Signal, tt.signal) {
				t.Fatalf("Signal = %q, want it to contain %q", rr.Signal, tt.signal)
			}
			if tt.note != "" && !strings.Contains(strings.Join(rr.Notes, "\n"), tt.note) {
				t.Fatalf("Notes = %q, want one containing %q", rr.Notes, tt.note)
			}
			if res.ViaFallback != tt.viaFallback {
				t.Fatalf("ViaFallback = %v", res.ViaFallback)
			}
			if rr.Ref != refSHA || rr.Shape != string(ShapeTest) {
				t.Fatalf("Ref %q Shape %q", rr.Ref, rr.Shape)
			}
			if tt.phases != nil && strings.Join(fx.drv.phases(), ",") != strings.Join(tt.phases, ",") {
				t.Fatalf("phases run = %v, want %v", fx.drv.phases(), tt.phases)
			}
			// A log hash for every phase that ran, and a capped log.
			for _, c := range fx.drv.calls {
				if c.who != "ref" {
					continue
				}
				if len(rr.LogSHA256[c.phase]) != 64 {
					t.Fatalf("no log hash for phase %s: %v", c.phase, rr.LogSHA256)
				}
				if _, ok := res.Logs[c.phase]; !ok {
					t.Fatalf("no log for phase %s", c.phase)
				}
			}
		})
	}
}

// TestRunnerBeforeContainers covers what is decided before any
// container runs (and the PoC collision, decided after fetch).
func TestRunnerBeforeContainers(t *testing.T) {
	fuzzSeed := []report.Artifact{{Name: "testdata/fuzz/FuzzMissing/seed1", Content: []byte("go test fuzz v1\n")}}
	tests := []struct {
		name      string
		tree      map[string]string
		poc       []report.Artifact
		ref       string
		cfg       func(*config.Sandbox)
		nilDriver bool
		scratch   string
		skipped   string
		needsInfo string
		inconc    string
		calls     int
	}{
		{name: "sandbox not enabled", cfg: func(c *config.Sandbox) { c.Rootfs = "" }, skipped: "not configured"},
		{name: "no driver", nilDriver: true, skipped: "unavailable"},
		{name: "relative scratch root", scratch: "scratch", skipped: "misconfigured"},
		{name: "unknown ref", ref: strings.Repeat("9", 40), inconc: "could not extract"},
		{name: "no PoC", poc: []report.Artifact{}, needsInfo: "no PoC"},
		{name: "PoC name with ..", poc: []report.Artifact{{Name: "../x_test.go", Content: []byte("package vuln")}}, needsInfo: "not allowed"},
		{name: "PoC package nowhere", poc: []report.Artifact{{Name: "p_test.go", Content: []byte("package nope\n\nimport \"testing\"\n\nfunc TestX(t *testing.T) {}\n")}},
			needsInfo: "no directory"},
		{name: "go.mod toolchain line", tree: withFiles(baseTree(), "go.mod", "module example.com/m\n\ngo 1.21\ntoolchain go1.99\n"), inconc: "toolchain"},
		{name: "go.mod replace to a host path", tree: withFiles(baseTree(), "go.mod", "module example.com/m\n\nreplace example.com/x => /etc\n"), inconc: "replace"},
		{name: "go.mod replace outside the module", tree: withFiles(baseTree(), "go.mod", "module example.com/m\n\nreplace example.com/x => ../../x\n"), inconc: "outside"},
		{name: "no go.mod", tree: withFiles(baseTree(), "go.mod", ""), inconc: "no go.mod"},
		{name: "go.mod without module", tree: withFiles(baseTree(), "go.mod", "go 1.21\n"), inconc: "module path"},
		{name: "fuzz target missing", poc: fuzzSeed, needsInfo: "no fuzz target"},
		{name: "PoC file collides with a repository file", poc: []report.Artifact{{Name: "fuzz_test.go", Content: []byte("package vuln\n\nimport \"testing\"\n\nfunc TestX(t *testing.T) {}\n")}},
			needsInfo: "already in the repository", calls: 1},
		{name: "program PoC with an existing cmd/kritolith-poc", tree: withFiles(baseTree(), "cmd/kritolith-poc/x.go", "package main\n"),
			poc: []report.Artifact{{Name: "main.go", Content: []byte("package main\n\nfunc main() {}\n")}}, inconc: "already has a cmd/kritolith-poc", calls: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newFixture(t, nil)
			if tt.tree != nil {
				fx.src.trees[refSHA] = tt.tree
			}
			cfg := testCfg(fx.rootfs)
			if tt.cfg != nil {
				tt.cfg(&cfg)
			}
			var d driver = fx.drv
			if tt.nilDriver {
				d = nil
			}
			scratch := fx.scratch
			if tt.scratch != "" {
				scratch = tt.scratch
			}
			fx.runner = NewRunner(cfg, fx.src, d, scratch)
			ref := refSHA
			if tt.ref != "" {
				ref = tt.ref
			}
			poc := testPoC
			if tt.poc != nil {
				poc = tt.poc
			}
			res := fx.runner.Run(context.Background(), Request{Report: report.Report{PoC: poc}, ResolvedRef: ref, Claims: []report.Claim{parseClaim}})
			assertScratchEmpty(t, fx.scratch)
			if !strings.Contains(res.Skipped, tt.skipped) || (tt.skipped == "") != (res.Skipped == "") {
				t.Fatalf("Skipped = %q, want %q", res.Skipped, tt.skipped)
			}
			if !strings.Contains(res.NeedsInfo, tt.needsInfo) || (tt.needsInfo == "") != (res.NeedsInfo == "") {
				t.Fatalf("NeedsInfo = %q, want %q", res.NeedsInfo, tt.needsInfo)
			}
			if !strings.Contains(res.Inconclusive, tt.inconc) || (tt.inconc == "") != (res.Inconclusive == "") {
				t.Fatalf("Inconclusive = %q, want %q", res.Inconclusive, tt.inconc)
			}
			if len(fx.drv.calls) != tt.calls {
				t.Fatalf("containers run = %v, want %d", fx.drv.phases(), tt.calls)
			}
			if res.Passed || (res.Repro != nil && res.Repro.Reproduced) {
				t.Fatalf("a refused run passed or reproduced: %+v", res)
			}
		})
	}
}

func envMap(t *testing.T, env []string) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			t.Fatalf("malformed env entry %q", e)
		}
		if _, dup := m[k]; dup {
			t.Fatalf("duplicate env key %q", k)
		}
		m[k] = v
	}
	return m
}

func keys(m map[string]string) string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return strings.Join(ks, ",")
}

func mountOf(t *testing.T, s RunSpec, dest string) Mount {
	t.Helper()
	for _, m := range s.Container.Mounts {
		if m.Dest == dest {
			return m
		}
	}
	t.Fatalf("no mount at %s in %+v", dest, s.Container.Mounts)
	return Mount{}
}

func hasArg(args []string, a string) bool {
	for _, x := range args {
		if x == a {
			return true
		}
	}
	return false
}

// TestRunnerContainerSpecs checks the containers the Runner asks for:
// network only in fetch, exact environments built from scratch, no
// PoC during fetch, mounts writable only where intended, and limits
// from the config.
func TestRunnerContainerSpecs(t *testing.T) {
	t.Setenv("KRITOLITH_HOST_SECRET", "hunter2-host-only")
	for _, race := range []bool{false, true} {
		t.Run(fmt.Sprintf("race=%v", race), func(t *testing.T) {
			fx := newFixture(t, map[string]step{"ref/run": stepPanic, "head/run": stepPass})
			if race {
				if err := os.MkdirAll(filepath.Join(fx.rootfs, "usr", "bin"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(fx.rootfs, "usr", "bin", "gcc"), nil, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			res := fx.run(t, Request{})
			if !res.Repro.Reproduced || res.Repro.ControlState != ControlFixed {
				t.Fatalf("setup: %+v", res.Repro)
			}
			raceNote := strings.Contains(strings.Join(res.Repro.Notes, "\n"), "race detector unavailable")
			if raceNote == race {
				t.Fatalf("race %v but race note %v: %q", race, raceNote, res.Repro.Notes)
			}
			cfg := testCfg(fx.rootfs)
			fetchSrc := map[string]string{}
			for _, c := range fx.drv.calls {
				s := c.spec
				ctr := s.Container
				if ctr.Network != (c.phase == PhaseFetch) {
					t.Errorf("%s/%s: Network = %v", c.who, c.phase, ctr.Network)
				}
				if ctr.MemoryMB != cfg.MemoryMB || ctr.CPUs != cfg.CPUs || ctr.PIDs != cfg.PIDs || ctr.UID <= 0 || ctr.GID <= 0 {
					t.Errorf("%s/%s: limits %+v", c.who, c.phase, ctr)
				}
				if ctr.CPUSeconds <= 0 || ctr.FileSizeKB <= 0 || ctr.Rootfs != fx.rootfs {
					t.Errorf("%s/%s: rlimits/rootfs %+v", c.who, c.phase, ctr)
				}
				if s.OutputLimit != cfg.OutputLimitKB*1024 {
					t.Errorf("%s/%s: OutputLimit = %d", c.who, c.phase, s.OutputLimit)
				}
				env := envMap(t, ctr.Env)
				for _, e := range ctr.Env {
					if strings.Contains(e, "hunter2-host-only") || strings.HasPrefix(e, "KRITOLITH_") {
						t.Errorf("%s/%s: host variable leaked: %q", c.who, c.phase, e)
					}
				}
				for _, m := range ctr.Mounts {
					if !m.Tmpfs && !strings.HasPrefix(m.Source, fx.scratch) {
						t.Errorf("%s/%s: mount source %s outside the scratch root", c.who, c.phase, m.Source)
					}
				}
				switch c.phase {
				case PhaseFetch:
					fetchSrc[c.who] = mountOf(t, s, ctrSrc).Source
					if c.pocInFetch {
						t.Errorf("%s: a PoC file is visible during fetch", c.who)
					}
					if s.Timeout != 50*time.Second {
						t.Errorf("fetch timeout %v", s.Timeout)
					}
					if want := "GOCACHE,GOENV,GOFLAGS,GOMODCACHE,GOPATH,GOPROXY,GOTOOLCHAIN,GOWORK,HOME,PATH,TMPDIR"; keys(env) != want {
						t.Errorf("fetch env keys = %s, want %s", keys(env), want)
					}
					if env["GOPROXY"] != cfg.GoProxy || env["GOFLAGS"] != "-mod=mod" || env["GOTOOLCHAIN"] != "local" || env["GOWORK"] != "off" {
						t.Errorf("fetch env = %v", env)
					}
					if strings.Join(ctr.Args, " ") != "go mod download" || ctr.Cwd != ctrSrc {
						t.Errorf("fetch args %q cwd %q", ctr.Args, ctr.Cwd)
					}
					if !mountOf(t, s, ctrSrc).Writable || !mountOf(t, s, ctrModCache).Writable || !mountOf(t, s, ctrTmp).Tmpfs {
						t.Errorf("fetch mounts %+v", ctr.Mounts)
					}
				case PhaseBuild:
					if s.Timeout != 60*time.Second {
						t.Errorf("build timeout %v", s.Timeout)
					}
					want := "GOCACHE,GOENV,GOFLAGS,GOMODCACHE,GOPATH,GOPROXY,GOTOOLCHAIN,GOWORK,HOME,PATH,TMPDIR"
					if race {
						want = "CGO_ENABLED," + want
					}
					if keys(env) != want {
						t.Errorf("build env keys = %s, want %s", keys(env), want)
					}
					if env["GOPROXY"] != "off" || env["GOFLAGS"] != "-mod=mod" || env["GOTOOLCHAIN"] != "local" || env["GOWORK"] != "off" {
						t.Errorf("build env = %v", env)
					}
					if race && env["CGO_ENABLED"] != "1" {
						t.Errorf("race build without CGO_ENABLED=1")
					}
					if hasArg(ctr.Args, "-race") != race {
						t.Errorf("build args %q, race %v", ctr.Args, race)
					}
					for _, a := range []string{"test", "-c", "-o", "/out/poc.test", "-cover", "-coverpkg=example.com/m/vuln", "./vuln"} {
						if !hasArg(ctr.Args, a) {
							t.Errorf("build args %q lack %q", ctr.Args, a)
						}
					}
					if mountOf(t, s, ctrModCache).Writable {
						t.Error("module cache writable in build")
					}
					src := mountOf(t, s, ctrSrc)
					if !src.Writable || src.Source == fetchSrc[c.who] {
						t.Errorf("build must use a writable copy of the tree: %+v (fetch tree %s)", src, fetchSrc[c.who])
					}
					if !hasArg(c.srcFiles, "vuln/poc_test.go") {
						t.Errorf("PoC not placed in the build tree: %v", c.srcFiles)
					}
				case PhaseRun:
					if s.Timeout != 30*time.Second {
						t.Errorf("run timeout %v", s.Timeout)
					}
					if keys(env) != "HOME,PATH,TMPDIR" {
						t.Errorf("run env keys = %s", keys(env))
					}
					for _, d := range []string{ctrSrc, ctrModCache, ctrBin} {
						if mountOf(t, s, d).Writable {
							t.Errorf("run: %s is writable", d)
						}
					}
					if !mountOf(t, s, ctrOut).Writable || !mountOf(t, s, ctrTmp).Tmpfs {
						t.Errorf("run mounts %+v", ctr.Mounts)
					}
					want := []string{"/poc/poc.test", "-test.run=^TestPoC$", "-test.v", "-test.count=1", "-test.timeout=27s", "-test.coverprofile=/out/cover.out"}
					if strings.Join(ctr.Args, " ") != strings.Join(want, " ") || ctr.Cwd != "/src/vuln" {
						t.Errorf("run args %q cwd %q", ctr.Args, ctr.Cwd)
					}
				}
			}
			if fetchSrc["ref"] == "" || fetchSrc["head"] == "" || filepath.Dir(fetchSrc["ref"]) == filepath.Dir(fetchSrc["head"]) {
				t.Errorf("control must use a fresh scratch dir: %v", fetchSrc)
			}
		})
	}
}

func TestRunnerFuzzShape(t *testing.T) {
	fx := newFixture(t, map[string]step{"ref/run": stepPass})
	fx.drv.pocName = "seed.1"
	poc := []report.Artifact{{Name: "testdata/fuzz/FuzzParse/seed.1", Content: []byte("go test fuzz v1\n[]byte(\"\")\n")}}
	res := fx.run(t, Request{Report: report.Report{PoC: poc}, PoCDirHint: "vuln"})
	if !res.Passed || res.Repro.Shape != string(ShapeFuzz) {
		t.Fatalf("result %+v", res)
	}
	run := fx.drv.calls[2]
	if !hasArg(run.spec.Container.Args, `-test.run=^FuzzParse$/^seed\.1$`) {
		t.Fatalf("run args %q: want every -test.run component quoted and anchored", run.spec.Container.Args)
	}
	if !hasArg(run.srcFiles, "vuln/testdata/fuzz/FuzzParse/seed.1") {
		t.Fatalf("seed not in the run's source tree: %v", run.srcFiles)
	}
	if fx.drv.calls[0].pocInFetch {
		t.Fatal("seed visible during fetch")
	}
}

func TestRunnerProgramShape(t *testing.T) {
	fx := newFixture(t, map[string]step{"ref/run": {out: RunOutput{Output: []byte("done\n")}}})
	fx.drv.pocName = "main.go"
	poc := []report.Artifact{{Name: "main.go", Content: []byte("package main\n\nimport \"example.com/m/vuln\"\n\nfunc main() { vuln.Parse(nil) }\n")}}
	res := fx.run(t, Request{Report: report.Report{PoC: poc}})
	if !res.Passed || res.Repro.Shape != string(ShapeProgram) {
		t.Fatalf("result %+v", res)
	}
	build, run := fx.drv.calls[1], fx.drv.calls[2]
	if got := strings.Join(build.spec.Container.Args, " "); got != "go build -o /out/poc ./cmd/kritolith-poc" {
		t.Fatalf("build args %q", got)
	}
	if !hasArg(build.srcFiles, "cmd/kritolith-poc/main.go") {
		t.Fatalf("program not placed: %v", build.srcFiles)
	}
	if got := strings.Join(run.spec.Container.Args, " "); got != "/poc/poc" {
		t.Fatalf("run args %q", got)
	}
}

// A PoC in a nested module: every phase works from that module's root,
// and claims are matched relative to it.
func TestRunnerNestedModule(t *testing.T) {
	fx := newFixture(t, nil)
	nested := map[string]string{
		"go.mod":         "module example.com/root\n",
		"sub/go.mod":     "module example.com/sub\n",
		"sub/pkg/p.go":   "package pkg\n\nfunc Bad() {\n\tpanic(1)\n}\n",
		"other/other.go": "package other\n",
	}
	fx.src.trees[refSHA] = nested
	fx.src.trees[headSHA] = nested
	out := "=== RUN   TestPoC\n--- FAIL: TestPoC (0.00s)\npanic: 1 [recovered]\n\ngoroutine 4 [running]:\npanic({0x1, 0x2})\n\t/usr/local/go/src/runtime/panic.go:860 +0x12c\nexample.com/sub/pkg.Bad(...)\n\t/src/sub/pkg/p.go:4\nexample.com/sub/pkg.TestPoC(0x1)\n\t/src/sub/pkg/poc_test.go:5 +0x20\n"
	fx.drv.script = map[string]step{"ref/run": {out: RunOutput{ExitCode: 2, Output: []byte(out)}}, "head/run": stepPass}
	poc := []report.Artifact{{Name: "poc_test.go", Content: []byte("package pkg\n\nimport \"testing\"\n\nfunc TestPoC(t *testing.T) { Bad() }\n")}}
	claims := []report.Claim{{Kind: report.ClaimFunction, Value: "pkg.Bad", Verified: report.TriYes, DeclPkgDir: "sub/pkg", DeclName: "Bad"}}
	res := fx.run(t, Request{Report: report.Report{PoC: poc}, Claims: claims})
	if !res.Repro.Reproduced || res.Repro.ControlState != ControlFixed {
		t.Fatalf("result %+v %+v", res, res.Repro)
	}
	fetch, build := fx.drv.calls[0], fx.drv.calls[1]
	if fetch.spec.Container.Cwd != "/src/sub" || build.spec.Container.Cwd != "/src/sub" {
		t.Fatalf("cwd fetch %q build %q, want the nested module root", fetch.spec.Container.Cwd, build.spec.Container.Cwd)
	}
	if !hasArg(build.spec.Container.Args, "./pkg") || !hasArg(build.spec.Container.Args, "-coverpkg=example.com/sub/pkg") {
		t.Fatalf("build args %q", build.spec.Container.Args)
	}
}

func TestRunnerCancelled(t *testing.T) {
	fx := newFixture(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := fx.runner.Run(ctx, Request{Report: report.Report{PoC: testPoC}, ResolvedRef: refSHA, Claims: []report.Claim{parseClaim}})
	assertScratchEmpty(t, fx.scratch)
	if !strings.Contains(res.Inconclusive, "cancelled") || res.Passed || res.Repro.Reproduced {
		t.Fatalf("result %+v", res)
	}
}

func TestRunnerCgroupNote(t *testing.T) {
	fx := newFixture(t, map[string]step{"ref/run": stepPass})
	fx.runner.ignoreCgroups = true
	res := fx.run(t, Request{})
	if !strings.Contains(strings.Join(res.Repro.Notes, "\n"), "cgroup limits") {
		t.Fatalf("notes %q", res.Repro.Notes)
	}
}

func TestAvailableAndNew(t *testing.T) {
	rootfs := t.TempDir()
	runtimeBin := filepath.Join(t.TempDir(), "fake-runsc")
	if err := os.WriteFile(runtimeBin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	notDir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	good := config.Sandbox{Rootfs: rootfs, Runtime: runtimeBin}
	tests := []struct {
		name string
		os   string
		cfg  config.Sandbox
		want string
	}{
		{"not enabled", "linux", config.Sandbox{Runtime: runtimeBin}, "no sandbox rootfs"},
		{"not linux", "darwin", good, "Linux host"},
		{"rootfs missing", "linux", config.Sandbox{Rootfs: filepath.Join(rootfs, "nope"), Runtime: runtimeBin}, "not a directory"},
		{"rootfs is a file", "linux", config.Sandbox{Rootfs: notDir, Runtime: runtimeBin}, "not a directory"},
		{"runtime missing", "linux", config.Sandbox{Rootfs: rootfs, Runtime: filepath.Join(rootfs, "no-runsc")}, "not found"},
		{"bad config", "linux", config.Sandbox{Rootfs: rootfs, Runtime: runtimeBin, MemoryMB: -1}, "memory_mb"},
		{"ok", "linux", good, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := hostOS
			hostOS = tt.os
			defer func() { hostOS = old }()
			err := Available(tt.cfg)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("Available = %v", err)
				}
				return
			}
			var u *Unavailable
			if !errors.As(err, &u) || !strings.Contains(u.Reason, tt.want) {
				t.Fatalf("Available = %v, want *Unavailable containing %q", err, tt.want)
			}
			if r, err := New(tt.cfg, &fakeSource{}, filepath.Join(t.TempDir(), "work"), false); r != nil || !errors.As(err, &u) {
				t.Fatalf("New = %v, %v; want *Unavailable", r, err)
			}
		})
	}

	old := hostOS
	hostOS = "linux"
	defer func() { hostOS = old }()
	work := filepath.Join(t.TempDir(), "work")
	r, err := New(good, &fakeSource{}, work, true)
	if err != nil {
		t.Fatal(err)
	}
	if !r.ignoreCgroups || r.scratchRoot != work && r.scratchRoot != mustEval(t, work) {
		t.Fatalf("runner %+v", r)
	}
	var u *Unavailable
	if r2, err := New(good, &fakeSource{}, work, false); r2 != nil || !errors.As(err, &u) {
		t.Fatalf("second New on a locked work dir = %v, %v; want *Unavailable", r2, err)
	}
	if _, err := New(good, nil, filepath.Join(t.TempDir(), "w2"), false); !errors.As(err, &u) {
		t.Fatalf("New without a source = %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if r2, err := New(good, &fakeSource{}, work, false); err != nil {
		t.Fatalf("New after Close = %v", err)
	} else {
		r2.Close()
	}
}

func mustEval(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
