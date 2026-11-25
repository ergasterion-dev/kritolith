package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// readOnlyTree makes dir/locked (0500) holding a 0400 file and a
// nested 0500 dir, plus dir/escape, a symlink to outside. It is what
// `go mod download` (0555 module dirs) or a hostile PoC leaves behind.
func readOnlyTree(t *testing.T, dir, outside string) {
	t.Helper()
	locked := filepath.Join(dir, "locked")
	if err := os.MkdirAll(filepath.Join(locked, "deeper"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "deeper", "f"), []byte("x"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "f"), []byte("x"), 0o400); err != nil {
		t.Fatal(err)
	}
	if outside != "" {
		if err := os.Symlink(outside, filepath.Join(locked, "escape")); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{filepath.Join(locked, "deeper"), locked} {
		if err := os.Chmod(d, 0o500); err != nil {
			t.Fatal(err)
		}
	}
}

// outsideDir is a read-only directory the cleanup must not touch.
func outsideDir(t *testing.T) string {
	t.Helper()
	o := filepath.Join(realTempDir(t), "outside")
	if err := os.Mkdir(o, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(o, "keep"), []byte("k"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(o, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(o, 0o700) })
	return o
}

func assertOutsideUntouched(t *testing.T, o string) {
	t.Helper()
	fi, err := os.Lstat(o)
	if err != nil || fi.Mode().Perm() != 0o500 {
		t.Fatalf("outside dir changed: %v %v", fi, err)
	}
	if _, err := os.Stat(filepath.Join(o, "keep")); err != nil {
		t.Fatalf("outside file removed: %v", err)
	}
}

func TestRemoveAllForce(t *testing.T) {
	outside := outsideDir(t)
	root := filepath.Join(realTempDir(t), "kritolith-run-x")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	readOnlyTree(t, root, outside)
	if err := os.Chmod(root, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := removeAllForce(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("root still there: %v", err)
	}
	assertOutsideUntouched(t, outside)

	// A root that is itself a symlink is removed as a link, never
	// followed.
	link := filepath.Join(realTempDir(t), "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := removeAllForce(link); err != nil {
		t.Fatal(err)
	}
	assertOutsideUntouched(t, outside)
	if err := removeAllForce(filepath.Join(realTempDir(t), "missing")); err != nil {
		t.Fatalf("missing path: %v", err)
	}
}

// The fake driver leaves read-only trees in every writable scratch
// mount (module cache in fetch, /out in run); the scratch root must
// still end up empty, and a link out of the tree is never followed.
func TestRunnerRemovesReadOnlyScratch(t *testing.T) {
	fx := newFixture(t, map[string]step{
		"ref/fetch": {lock: true},
		"ref/run":   {out: RunOutput{Output: []byte(passOut)}, lock: true},
	})
	fx.drv.outside = outsideDir(t)
	res := fx.run(t, Request{}) // asserts the scratch root is empty
	if !res.Passed {
		t.Fatalf("result %+v", res)
	}
	assertOutsideUntouched(t, fx.drv.outside)
}

func TestRunnerFetchMakesModuleCacheWritable(t *testing.T) {
	fx := newFixture(t, map[string]step{"ref/run": stepPass})
	fx.run(t, Request{})
	env := envMap(t, fx.drv.calls[0].spec.Container.Env)
	if env["GOFLAGS"] != "-mod=mod -modcacherw" {
		t.Fatalf("fetch GOFLAGS = %q", env["GOFLAGS"])
	}
}

func TestRunnerCleanupFailureNoted(t *testing.T) {
	old := removeScratch
	removeScratch = func(p string) error { _ = os.RemoveAll(p); return errors.New("permission denied") }
	defer func() { removeScratch = old }()
	fx := newFixture(t, map[string]step{"ref/run": stepPass})
	res := fx.run(t, Request{})
	if !strings.Contains(strings.Join(res.Repro.Notes, "\n"), "scratch") {
		t.Fatalf("notes %q, want a cleanup note", res.Repro.Notes)
	}
}

func TestSweepOrphansRemovesReadOnlyTrees(t *testing.T) {
	outside := outsideDir(t)
	workDir := claimedWorkDir(t)
	p := filepath.Join(workDir, "kritolith-run-7007")
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	readOnlyTree(t, p, outside)
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	if err := sweepOrphans(filepath.Join(realTempDir(t), "no-runsc"), workDir, time.Now()); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Fatalf("read-only orphan kept: %v", err)
	}
	assertOutsideUntouched(t, outside)
}

func TestRunnerRefusesProxyList(t *testing.T) {
	for _, p := range []string{"https://p.org/x,direct", "direct", "off", "file:///x", "https://p.org|https://q.org", "https://u:p@h"} {
		fx := newFixture(t, nil)
		cfg := testCfg(fx.rootfs)
		cfg.GoProxy = p
		fx.runner = NewRunner(cfg, fx.src, fx.drv, fx.scratch)
		fx.runner.bridge = fx.bridges
		res := fx.runner.Run(context.Background(), Request{Report: report.Report{PoC: testPoC}, ResolvedRef: refSHA})
		if !strings.Contains(res.Skipped, "goproxy") || len(fx.drv.calls) != 0 {
			t.Errorf("%s: Skipped %q, %d containers", p, res.Skipped, len(fx.drv.calls))
		}
		if err := checkProxy(p); err == nil {
			t.Errorf("checkProxy(%q) = nil", p)
		}
	}
	if err := checkProxy("https://proxy.golang.org"); err != nil {
		t.Fatal(err)
	}
}
