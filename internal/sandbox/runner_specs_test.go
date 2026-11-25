package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/config"
	"github.com/ergasterion-dev/kritolith/internal/report"
)

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
			if !race {
				fx.noCompiler(t)
			}
			res := fx.run(t, Request{})
			// Without -race a clean control says nothing about a race,
			// so it cannot count as fixed.
			wantControl := ControlFixed
			if !race {
				wantControl = ControlUnavailable
			}
			if !res.Repro.Reproduced || res.Repro.ControlState != wantControl {
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
					if env["GOPROXY"] != fakeBridgeURL || env["GOFLAGS"] != "-mod=mod -modcacherw" || env["GOTOOLCHAIN"] != "local" || env["GOWORK"] != "off" {
						t.Errorf("fetch env = %v", env)
					}
					if ctr.NetnsPath != fakeBridgeNetns {
						t.Errorf("fetch netns %q, want the bridge's %q", ctr.NetnsPath, fakeBridgeNetns)
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
	fuzzPass := "=== RUN   FuzzParse\n=== RUN   FuzzParse/seed.1\n--- PASS: FuzzParse (0.00s)\n    --- PASS: FuzzParse/seed.1 (0.00s)\nPASS\n"
	fx := newFixture(t, map[string]step{"ref/run": {out: RunOutput{Output: []byte(fuzzPass)}}})
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
	if got := strings.Join(build.spec.Container.Args, " "); got != "go build -o /out/poc -race ./cmd/kritolith-poc" {
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
