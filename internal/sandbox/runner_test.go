package sandbox

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/config"
	"github.com/ergasterion-dev/kritolith/internal/report"
)

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
		poc          []report.Artifact
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
			phase: PhaseRun, inconclusive: "did not pass", signal: ReasonNoTestsRan},
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
		{name: "all tests skipped at ref", script: map[string]step{"ref/run": {out: RunOutput{Output: []byte(skipOut)}}},
			phase: PhaseRun, inconclusive: "skipped", signal: ReasonSkipped},
		{name: "PoC prints a PASS line but skips", script: map[string]step{"ref/run": {out: RunOutput{Output: []byte("--- PASS: TestPoC (0.00s)\n" + skipOut)}}},
			phase: PhaseRun, inconclusive: "skipped", signal: ReasonSkipped},
		{name: "a PASS line for another name only", script: map[string]step{"ref/run": {out: RunOutput{Output: []byte("--- PASS: TestPoCx (0.00s)\nPASS\n")}}},
			phase: PhaseRun, inconclusive: "did not pass", signal: ReasonNoTestsRan},
		{name: "a subtest of the PoC skipped", script: map[string]step{"ref/run": {out: RunOutput{Output: []byte("    --- SKIP: TestPoC/sub (0.00s)\n--- PASS: TestPoC (0.00s)\nPASS\n")}}},
			phase: PhaseRun, inconclusive: "skipped", signal: ReasonSkipped},
		{name: "panic at ref, all skipped at HEAD", script: map[string]step{"ref/run": stepPanic, "head/run": {out: RunOutput{Output: []byte(skipOut)}}},
			reproduced: true, control: ControlUnavailable, phase: PhaseControl},
		{name: "assertion at ref, all skipped at HEAD", script: map[string]step{"ref/run": stepAssert, "head/run": {out: RunOutput{Output: []byte(skipOut)}}},
			weak: true, control: ControlUnavailable, inconclusive: "could not be re-run at HEAD"},
		{name: "one test passes, one skips", poc: twoTestPoC, script: map[string]step{"ref/run": {out: RunOutput{Output: []byte("--- PASS: TestA (0.00s)\n--- SKIP: TestB (0.00s)\nPASS\n")}}},
			phase: PhaseRun, inconclusive: "skipped"},
		{name: "one of two tests never ran", poc: twoTestPoC, script: map[string]step{"ref/run": {out: RunOutput{Output: []byte("--- PASS: TestA (0.00s)\nPASS\n")}}},
			phase: PhaseRun, inconclusive: "did not pass"},
		{name: "both tests pass", poc: twoTestPoC, script: map[string]step{"ref/run": {out: RunOutput{Output: []byte("--- PASS: TestA (0.00s)\n--- PASS: TestB (0.00s)\nPASS\n")}}},
			passed: true, phase: PhaseRun},
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
			res := fx.run(t, Request{Claims: tt.claims, ViaFallback: tt.viaFallback, Report: report.Report{PoC: tt.poc}})
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
			fx.runner.bridge = fx.bridges
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

const skipOut = "=== RUN   TestPoC\n    poc_test.go:5: not today\n--- SKIP: TestPoC (0.00s)\nPASS\n"

var twoTestPoC = []report.Artifact{{Name: "poc_test.go", Content: []byte("package vuln\n\nimport \"testing\"\n\nfunc TestA(t *testing.T) {}\n\nfunc TestB(t *testing.T) {}\n")}}

// TestRunnerNoRaceDetectorIsInconclusive: a rootfs without a C
// compiler builds the PoC without -race, so a clean run (at the ref or
// as the control) says nothing about a data race. It must never read
// as NOT_REPRODUCED or as fixed at HEAD.
func TestRunnerNoRaceDetectorIsInconclusive(t *testing.T) {
	t.Run("clean run at the ref", func(t *testing.T) {
		fx := newFixture(t, map[string]step{"ref/run": stepPass})
		fx.noCompiler(t)
		res := fx.run(t, Request{})
		if res.Passed {
			t.Fatalf("Passed = true without the race detector: %+v", res)
		}
		if !strings.Contains(res.Inconclusive, "without -race") {
			t.Fatalf("Inconclusive = %q, want the missing race detector named", res.Inconclusive)
		}
		if res.Repro == nil || !strings.Contains(strings.Join(res.Repro.Notes, "\n"), "race detector unavailable") {
			t.Fatalf("Repro notes miss the race caveat: %+v", res.Repro)
		}
	})
	t.Run("clean control", func(t *testing.T) {
		fx := newFixture(t, map[string]step{"ref/run": stepAssert, "head/run": stepPass})
		fx.noCompiler(t)
		res := fx.run(t, Request{})
		if res.Repro.ControlState == ControlFixed || res.Repro.Reproduced {
			t.Fatalf("a clean control without -race counted as fixed: %+v", res.Repro)
		}
		if res.Inconclusive == "" {
			t.Fatalf("weak signal with an unusable control must be inconclusive: %+v", res)
		}
	})
	t.Run("with a compiler a clean run passes", func(t *testing.T) {
		fx := newFixture(t, map[string]step{"ref/run": stepPass})
		if res := fx.run(t, Request{}); !res.Passed || res.Inconclusive != "" {
			t.Fatalf("want Passed: %+v", res)
		}
	})
}
