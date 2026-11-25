package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/config"
	"github.com/ergasterion-dev/kritolith/internal/report"
)

// Every container the Runner builds, at the ref and in the control,
// carries the data dir (and every other forbidden path) in Forbidden.
func TestRunnerForbiddenInEverySpec(t *testing.T) {
	data := filepath.Join(t.TempDir(), "data")
	keys := filepath.Join(t.TempDir(), "keys")
	fx := newFixture(t, map[string]step{"ref/run": stepPanic, "head/run": stepPass})
	if got := fx.runner.WithForbidden(data, keys); got != fx.runner {
		t.Fatal("WithForbidden must return the runner it was called on")
	}
	res := fx.run(t, Request{})
	if res.Repro == nil || res.Repro.Control == nil {
		t.Fatalf("want a reproduction with a control, got %+v", res)
	}
	phases := map[string]bool{}
	for _, c := range fx.drv.calls {
		phases[c.who+"/"+c.phase] = true
		for _, want := range []string{data, keys} {
			if !slices.Contains(c.spec.Container.Forbidden, want) {
				t.Errorf("%s/%s: Forbidden = %v, missing %s", c.who, c.phase, c.spec.Container.Forbidden, want)
			}
		}
	}
	for _, want := range []string{"ref/fetch", "ref/build", "ref/run", "head/fetch", "head/build", "head/run"} {
		if !phases[want] {
			t.Errorf("phase %s never ran; calls cover %v", want, phases)
		}
	}
}

// A specs' Forbidden list is the Runner's own copy: one run cannot
// change what the next run forbids.
func TestRunnerForbiddenIsCopied(t *testing.T) {
	data := filepath.Join(t.TempDir(), "data")
	fx := newFixture(t, map[string]step{"ref/run": stepPass})
	fx.runner.WithForbidden(data)
	spec := fx.runner.runSpec([]string{"true"}, nil, "/src", nil, false, 1, 1)
	spec.Container.Forbidden[0] = "/elsewhere"
	if again := fx.runner.runSpec([]string{"true"}, nil, "/src", nil, false, 1, 1); again.Container.Forbidden[0] != data {
		t.Fatalf("Forbidden after a caller edit = %v", again.Container.Forbidden)
	}
}

// An operator hint that leaves the tree ends NEEDS_INFO before any
// container runs; nothing is placed outside the source tree.
func TestRunnerHostilePoCDirHint(t *testing.T) {
	for _, hint := range []string{"../x", "/abs", "vuln/../../x", "..", "a\x00b"} {
		t.Run(hint, func(t *testing.T) {
			fx := newFixture(t, map[string]step{"ref/run": stepPanic})
			res := fx.run(t, Request{PoCDirHint: hint})
			if res.NeedsInfo == "" || !strings.Contains(res.NeedsInfo, "not a path inside the repository") {
				t.Fatalf("hint %q: result %+v, want NeedsInfo", hint, res)
			}
			if len(fx.drv.calls) != 0 {
				t.Fatalf("hint %q: %d containers ran", hint, len(fx.drv.calls))
			}
		})
	}
}

// A resolver picks the source per report repository.
func TestRunnerSourceResolver(t *testing.T) {
	fx := newFixture(t, map[string]step{"ref/run": stepPanic, "head/run": stepPass})
	var asked []string
	fx.runner.src = nil
	fx.runner.resolve = func(repo string) (Source, error) {
		asked = append(asked, repo)
		return fx.src, nil
	}
	res := fx.run(t, Request{Report: report.Report{Repo: "owner/name"}})
	if res.Repro == nil || !res.Repro.Reproduced {
		t.Fatalf("result %+v", res)
	}
	if !slices.Equal(asked, []string{"owner/name"}) {
		t.Fatalf("resolver asked for %v", asked)
	}

	for name, resolve := range map[string]SourceResolver{
		"error": func(string) (Source, error) { return nil, errors.New("no mirror") },
		"nil":   func(string) (Source, error) { return nil, nil },
	} {
		t.Run(name, func(t *testing.T) {
			fx := newFixture(t, map[string]step{"ref/run": stepPanic})
			fx.runner.src = nil
			fx.runner.resolve = resolve
			res := fx.run(t, Request{Report: report.Report{Repo: "owner/name"}})
			if res.Skipped == "" || res.Repro != nil || len(fx.drv.calls) != 0 {
				t.Fatalf("result %+v, calls %d; want Skipped and nothing run", res, len(fx.drv.calls))
			}
		})
	}
}

func TestNewWithResolver(t *testing.T) {
	rootfs := t.TempDir()
	runtimeBin := filepath.Join(t.TempDir(), "fake-runsc")
	if err := os.WriteFile(runtimeBin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	good := config.Sandbox{Rootfs: rootfs, Runtime: runtimeBin}
	resolve := func(string) (Source, error) { return &fakeSource{}, nil }
	old := hostOS
	defer func() { hostOS = old }()

	var u *Unavailable
	hostOS = "darwin"
	if r, err := NewWithResolver(good, resolve, filepath.Join(t.TempDir(), "w"), false); r != nil || !errors.As(err, &u) {
		t.Fatalf("non-Linux NewWithResolver = %v, %v; want *Unavailable", r, err)
	}
	hostOS = "linux"
	if r, err := NewWithResolver(good, nil, filepath.Join(t.TempDir(), "w"), false); r != nil || !errors.As(err, &u) {
		t.Fatalf("nil resolver = %v, %v; want *Unavailable", r, err)
	}
	r, err := NewWithResolver(good, resolve, filepath.Join(t.TempDir(), "w"), false)
	if err != nil {
		t.Fatal(err)
	}
	if r.resolve == nil || r.src != nil {
		t.Fatalf("runner %+v", r)
	}
	for i := 0; i < 2; i++ {
		if err := r.Close(); err != nil {
			t.Fatalf("Close #%d = %v", i+1, err)
		}
	}
}
