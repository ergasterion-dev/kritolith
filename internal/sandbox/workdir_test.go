package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// realTempDir is t.TempDir with symlinks resolved: on macOS the temp
// dir lives under /var, a symlink to /private/var, and the work dir
// checks refuse a symlinked ancestor.
func realTempDir(t *testing.T) string {
	t.Helper()
	p, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// claimedWorkDir is a fresh work dir that already carries the marker.
func claimedWorkDir(t *testing.T) string {
	t.Helper()
	p := realTempDir(t)
	if err := claimWorkDir(p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIsOrphanName(t *testing.T) {
	for n, want := range map[string]bool{
		"kritolith-1234567":     true,
		"kritolith-run-1234567": true,
		"kritolith-":            false,
		"kritolith-run-":        false,
		"kritolith-rootfs":      false,
		"kritolith-backup":      false,
		"kritolith-dev":         false,
		"kritolith-12a":         false,
		"kritolith-run-12a":     false,
		"kritolith-run-1/2":     false,
		"kritolith-1\x00":       false,
		"xkritolith-1":          false,
		"kritolith-eval-123":    false,
	} {
		if got := isOrphanName(n); got != want {
			t.Errorf("isOrphanName(%q) = %v, want %v", n, got, want)
		}
	}
	// The names the driver and the Runner actually create match.
	dir := t.TempDir()
	for _, pat := range []string{orphanPrefix + "*", orphanPrefix + "run-*"} {
		p, err := os.MkdirTemp(dir, pat)
		if err != nil {
			t.Fatal(err)
		}
		if !isOrphanName(filepath.Base(p)) {
			t.Errorf("MkdirTemp(%q) made %q, which isOrphanName refuses", pat, filepath.Base(p))
		}
	}
}

func TestClaimWorkDir(t *testing.T) {
	t.Run("empty dir gets a private marker", func(t *testing.T) {
		p := realTempDir(t)
		if err := claimWorkDir(p); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Lstat(filepath.Join(p, workDirMarker))
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
			t.Fatalf("marker %v %v", fi, err)
		}
		if err := claimWorkDir(p); err != nil {
			t.Fatalf("second claim: %v", err)
		}
	})
	t.Run("non-empty dir without a marker is refused", func(t *testing.T) {
		p := realTempDir(t)
		if err := os.WriteFile(filepath.Join(p, "something"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := claimWorkDir(p); err == nil || !strings.Contains(err.Error(), "dedicated") {
			t.Fatalf("err = %v", err)
		}
		if _, err := os.Lstat(filepath.Join(p, workDirMarker)); err == nil {
			t.Fatal("marker created in a shared dir")
		}
	})
	t.Run("symlinked marker is refused", func(t *testing.T) {
		p := realTempDir(t)
		target := filepath.Join(realTempDir(t), "f")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(p, workDirMarker)); err != nil {
			t.Fatal(err)
		}
		if err := claimWorkDir(p); err == nil {
			t.Fatal("accepted a symlinked marker")
		}
	})
	t.Run("readable marker is refused", func(t *testing.T) {
		p := realTempDir(t)
		if err := os.WriteFile(filepath.Join(p, workDirMarker), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := claimWorkDir(p); err == nil {
			t.Fatal("accepted a 0644 marker")
		}
	})
}

func TestCheckAncestors(t *testing.T) {
	base := realTempDir(t)
	if err := checkAncestors(filepath.Join(base, "a", "work")); err != nil {
		t.Fatalf("private ancestors refused: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(realTempDir(t), link); err != nil {
		t.Fatal(err)
	}
	if err := checkAncestors(filepath.Join(link, "work")); err == nil {
		t.Fatal("symlinked ancestor accepted")
	}
	open := filepath.Join(base, "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := checkAncestors(filepath.Join(open, "work")); err == nil {
		t.Fatal("world-writable ancestor without the sticky bit accepted")
	}
	if err := os.Chmod(open, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	if err := checkAncestors(filepath.Join(open, "work")); err != nil {
		t.Fatalf("sticky ancestor (like /tmp) refused: %v", err)
	}
}

func TestCheckWorkDirOverlap(t *testing.T) {
	base := realTempDir(t)
	work := filepath.Join(base, "work")
	for _, tt := range []struct {
		name      string
		rootfs    string
		forbidden []string
		bad       bool
	}{
		{"separate", filepath.Join(base, "rootfs"), []string{filepath.Join(base, "data")}, false},
		{"rootfs inside the work dir", filepath.Join(work, "kritolith-rootfs", "go1.26.0"), nil, true},
		{"rootfs is the work dir", work, nil, true},
		{"rootfs contains the work dir", base, nil, true},
		{"forbidden inside the work dir", filepath.Join(base, "rootfs"), []string{filepath.Join(work, "key")}, true},
		{"forbidden contains the work dir", filepath.Join(base, "rootfs"), []string{base}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := checkWorkDirOverlap(work, tt.rootfs, tt.forbidden)
			if (err != nil) != tt.bad {
				t.Fatalf("err = %v, want error %v", err, tt.bad)
			}
		})
	}
}

// The reviewer's scenario: work_dir is a shared parent (like /var/lib)
// that also holds the rootfs. The sweep must delete nothing and the
// driver must refuse the dir.
func TestSharedParentWorkDirIsRefused(t *testing.T) {
	parent := realTempDir(t)
	rootfs := filepath.Join(parent, "kritolith-rootfs", "go1.26.0")
	gcc := filepath.Join(rootfs, "usr", "bin", "gcc")
	if err := os.MkdirAll(filepath.Dir(gcc), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gcc, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	siblings := []string{"kritolith-backup", "kritolith-dev", "kritolith-123"}
	old := time.Now().Add(-2 * time.Hour)
	for _, s := range append(siblings, "kritolith-rootfs") {
		p := filepath.Join(parent, s)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	f := newFakeRunsc(t, `:`, ``)
	if err := sweepOrphans(f.path, parent, time.Now()); err == nil {
		t.Fatal("sweep of a shared, unmarked parent returned no error")
	}
	for _, s := range append(siblings, "kritolith-rootfs") {
		if _, err := os.Lstat(filepath.Join(parent, s)); err != nil {
			t.Fatalf("sweep deleted %s: %v", s, err)
		}
	}
	if _, err := os.Lstat(gcc); err != nil {
		t.Fatalf("rootfs touched: %v", err)
	}
	if len(f.calls(t)) != 0 {
		t.Fatalf("sweep called runsc on an unmarked dir: %q", f.calls(t))
	}
	if d, err := newRunscDriver(f.path, parent); err == nil {
		d.Close()
		t.Fatal("driver accepted a shared parent as its work dir")
	}
	if _, err := os.Lstat(filepath.Join(parent, workDirMarker)); err == nil {
		t.Fatal("marker written into a shared parent")
	}
	// Even a marked work dir is refused when the rootfs lies inside it.
	if err := checkWorkDirOverlap(parent, rootfs, nil); err == nil {
		t.Fatal("rootfs inside the work dir accepted")
	}
}

// An empty, unmarked dir has nothing to sweep: no error, no marker.
func TestSweepEmptyUnmarkedWorkDir(t *testing.T) {
	p := realTempDir(t)
	f := newFakeRunsc(t, `:`, ``)
	if err := sweepOrphans(f.path, p, time.Now()); err != nil {
		t.Fatal(err)
	}
}

// The Runner refuses to run when the rootfs or a forbidden path
// overlaps its scratch root: nothing runs, nothing is created.
func TestRunnerRefusesOverlappingScratchRoot(t *testing.T) {
	for _, tt := range []struct {
		name      string
		rootfsIn  bool
		forbidden bool
	}{{"rootfs inside scratch", true, false}, {"forbidden inside scratch", false, true}} {
		t.Run(tt.name, func(t *testing.T) {
			fx := newFixture(t, nil)
			cfg := testCfg(fx.rootfs)
			if tt.rootfsIn {
				cfg.Rootfs = filepath.Join(fx.scratch, "rootfs")
			}
			fx.runner = NewRunner(cfg, fx.src, fx.drv, fx.scratch)
			fx.runner.bridge = fx.bridges
			if tt.forbidden {
				fx.runner.WithForbidden(filepath.Join(fx.scratch, "data"))
			}
			res := fx.run(t, Request{})
			if !strings.Contains(res.Skipped, "scratch directory is misconfigured") || len(fx.drv.calls) != 0 {
				t.Fatalf("Skipped %q, %d containers", res.Skipped, len(fx.drv.calls))
			}
		})
	}
}
