package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/config"
	"github.com/ergasterion-dev/kritolith/internal/sandbox"
)

// pruneClock is a settable clock for the log pruner.
type pruneClock struct{ t time.Time }

func (c *pruneClock) now() time.Time { return c.t }

// mkLogDir creates <data>/sandbox-logs/<id>/ with the given files, and
// sets the files' and then the directory's modification time to mtime.
func mkLogDir(t *testing.T, data, id string, mtime time.Time, files ...string) string {
	t.Helper()
	root := filepath.Join(data, sandboxLogsDir)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, id)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		p := filepath.Join(dir, f)
		if err := os.WriteFile(p, []byte("log"), 0o600); err != nil {
			t.Fatal(err)
		}
		setMtime(t, p, mtime)
	}
	setMtime(t, dir, mtime)
	return dir
}

func setMtime(t *testing.T, p string, mtime time.Time) {
	t.Helper()
	if err := os.Chtimes(p, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func TestSandboxLogPrune(t *testing.T) {
	const days = 30
	now := time.Now()
	old := now.Add(-(days*24 + 1) * time.Hour)
	fresh := now.Add(-(days*24 - 1) * time.Hour)

	tests := []struct {
		name string
		days int
		// setup builds the case under data and returns the paths that
		// must be gone and the paths that must still exist afterwards.
		setup func(t *testing.T, data string) (gone, kept []string)
	}{
		{"old dir removed", days, func(t *testing.T, data string) ([]string, []string) {
			return []string{mkLogDir(t, data, "OLD", old, "run.log", "build.log")}, []string{filepath.Join(data, sandboxLogsDir)}
		}},
		{"old empty dir removed", days, func(t *testing.T, data string) ([]string, []string) {
			return []string{mkLogDir(t, data, "OLDEMPTY", old)}, nil
		}},
		{"fresh dir kept", days, func(t *testing.T, data string) ([]string, []string) {
			d := mkLogDir(t, data, "FRESH", fresh, "run.log")
			return nil, []string{d, filepath.Join(d, "run.log")}
		}},
		{"old dir with a fresh file kept", days, func(t *testing.T, data string) ([]string, []string) {
			d := mkLogDir(t, data, "MIXED", old, "run.log", "build.log")
			setMtime(t, filepath.Join(d, "run.log"), fresh)
			return nil, []string{d, filepath.Join(d, "run.log"), filepath.Join(d, "build.log")}
		}},
		{"fresh dir with old files kept", days, func(t *testing.T, data string) ([]string, []string) {
			d := mkLogDir(t, data, "TOUCHED", old, "run.log")
			setMtime(t, d, fresh)
			return nil, []string{d, filepath.Join(d, "run.log")}
		}},
		{"zero keeps everything", 0, func(t *testing.T, data string) ([]string, []string) {
			d := mkLogDir(t, data, "OLD", old, "run.log")
			return nil, []string{d, filepath.Join(d, "run.log")}
		}},
		{"symlink entry and its target untouched", days, func(t *testing.T, data string) ([]string, []string) {
			elsewhere := t.TempDir()
			target := mkLogDir(t, elsewhere, "TARGET", old, "run.log")
			if err := os.MkdirAll(filepath.Join(data, sandboxLogsDir), 0o700); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(data, sandboxLogsDir, "LINK")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			return nil, []string{link, target, filepath.Join(target, "run.log")}
		}},
		{"odd names untouched", days, func(t *testing.T, data string) ([]string, []string) {
			var kept []string
			for _, id := range []string{"has space", ".hidden", "dot.ted", "é"} {
				d := mkLogDir(t, data, id, old, "run.log")
				kept = append(kept, d, filepath.Join(d, "run.log"))
			}
			// A regular file whose name looks like a report id.
			f := filepath.Join(data, sandboxLogsDir, "FILEID")
			if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			setMtime(t, f, old)
			return nil, append(kept, f)
		}},
		{"dir holding a subdirectory left alone", days, func(t *testing.T, data string) ([]string, []string) {
			d := mkLogDir(t, data, "HASDIR", old, "run.log")
			sub := filepath.Join(d, "sub")
			if err := os.Mkdir(sub, 0o700); err != nil {
				t.Fatal(err)
			}
			setMtime(t, sub, old)
			setMtime(t, d, old)
			return nil, []string{d, sub, filepath.Join(d, "run.log")}
		}},
		{"dir holding a symlink left alone", days, func(t *testing.T, data string) ([]string, []string) {
			victim := filepath.Join(t.TempDir(), "victim")
			if err := os.WriteFile(victim, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			setMtime(t, victim, old)
			d := mkLogDir(t, data, "HASLINK", old, "run.log")
			link := filepath.Join(d, "build.log")
			if err := os.Symlink(victim, link); err != nil {
				t.Fatal(err)
			}
			setMtime(t, d, old)
			return nil, []string{d, link, victim, filepath.Join(d, "run.log")}
		}},
		{"symlinked logs dir untouched", days, func(t *testing.T, data string) ([]string, []string) {
			elsewhere := t.TempDir()
			target := mkLogDir(t, elsewhere, "OLD", old, "run.log")
			if err := os.Symlink(filepath.Join(elsewhere, sandboxLogsDir), filepath.Join(data, sandboxLogsDir)); err != nil {
				t.Fatal(err)
			}
			return nil, []string{target, filepath.Join(target, "run.log")}
		}},
		{"rest of the data dir untouched", days, func(t *testing.T, data string) ([]string, []string) {
			gone := mkLogDir(t, data, "OLD", old, "run.log")
			// An old directory beside sandbox-logs that looks like a
			// report's log directory, and an old file.
			sibling := filepath.Join(data, "SIBLING")
			if err := os.Mkdir(sibling, 0o700); err != nil {
				t.Fatal(err)
			}
			db := filepath.Join(data, "kritolith.db")
			for _, p := range []string{filepath.Join(sibling, "run.log"), db} {
				if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				setMtime(t, p, old)
			}
			setMtime(t, sibling, old)
			return []string{gone}, []string{sibling, filepath.Join(sibling, "run.log"), db}
		}},
		{"no logs dir", days, func(t *testing.T, data string) ([]string, []string) {
			return []string{filepath.Join(data, sandboxLogsDir)}, []string{data}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := t.TempDir()
			gone, kept := tt.setup(t, data)
			// Creating the sink prunes once.
			newSandboxLogSink(data, tt.days, func() time.Time { return now })
			for _, p := range gone {
				if exists(p) {
					t.Errorf("%s still exists", p)
				}
			}
			for _, p := range kept {
				if !exists(p) {
					t.Errorf("%s was removed", p)
				}
			}
		})
	}
}

// A directory owned by another user is left alone.
func TestSandboxLogPruneOtherOwner(t *testing.T) {
	data := t.TempDir()
	now := time.Now()
	d := mkLogDir(t, data, "OLD", now.Add(-48*time.Hour), "run.log")
	p := newLogPruner(data, 1, func() time.Time { return now })
	p.uid++ // nothing under data belongs to this uid
	p.prune()
	if !exists(d) || !exists(filepath.Join(d, "run.log")) {
		t.Fatal("removed a directory owned by another user")
	}
	p.uid--
	p.prune()
	if exists(d) {
		t.Fatal("did not remove the user's own old directory")
	}
}

// The sink prunes when it is created and then at most once an hour.
func TestSandboxLogPruneOncePerHour(t *testing.T) {
	data := t.TempDir()
	clock := &pruneClock{t: time.Now()}
	old := clock.t.Add(-48 * time.Hour)
	logs := map[string][]byte{"run": []byte("x")}

	first := mkLogDir(t, data, "FIRST", old, "run.log")
	sink := newSandboxLogSink(data, 1, clock.now)
	if exists(first) {
		t.Fatal("creating the sink did not prune")
	}

	second := mkLogDir(t, data, "SECOND", old, "run.log")
	clock.t = clock.t.Add(59 * time.Minute)
	sink("R1", logs)
	if !exists(second) {
		t.Fatal("pruned again within the hour")
	}
	if !exists(filepath.Join(data, sandboxLogsDir, "R1", "run.log")) {
		t.Fatal("the sink did not write its log")
	}

	clock.t = clock.t.Add(2 * time.Minute)
	sink("R2", logs)
	if exists(second) {
		t.Fatal("did not prune after an hour")
	}
	for _, id := range []string{"R1", "R2"} {
		if !exists(filepath.Join(data, sandboxLogsDir, id, "run.log")) {
			t.Fatalf("pruning removed the fresh log of %s", id)
		}
	}

	// The hour counts from the last pruning, not from the creation.
	third := mkLogDir(t, data, "THIRD", old, "run.log")
	clock.t = clock.t.Add(30 * time.Minute)
	sink("R3", logs)
	if !exists(third) {
		t.Fatal("pruned 30 minutes after the last pruning")
	}
}

// With no retention bound the sink never prunes, however much time
// passes.
func TestSandboxLogSinkNoRetentionNeverPrunes(t *testing.T) {
	data := t.TempDir()
	clock := &pruneClock{t: time.Now()}
	d := mkLogDir(t, data, "OLD", clock.t.Add(-100*365*24*time.Hour), "run.log")
	sink := newSandboxLogSink(data, 0, clock.now)
	clock.t = clock.t.Add(48 * time.Hour)
	sink("R1", map[string][]byte{"run": []byte("x")})
	if !exists(d) || !exists(filepath.Join(d, "run.log")) {
		t.Fatal("pruned with log_retention_days 0")
	}
	if newLogPruner(data, 0, clock.now) != nil {
		t.Fatal("want no pruner for 0 days")
	}
}

// newProcessor passes sandbox.log_retention_days to the sink, and
// pruning follows the sink: a processor without the sandbox has no sink
// and removes nothing.
func TestNewProcessorLogRetention(t *testing.T) {
	tests := []struct {
		name     string
		days     int
		opts     []processorOption
		wantGone bool
	}{
		{"sandbox built, bound set", 1, nil, true},
		{"sandbox built, no bound", 0, nil, false},
		{"without sandbox, bound set", 1, []processorOption{withoutSandbox()}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubSandbox(t,
				func(string, string) error { return nil },
				func(config.Sandbox, sandbox.SourceResolver, string, string) (sandboxRunner, error) {
					return &fakeSandbox{}, nil
				})
			data := filepath.Join(t.TempDir(), "data")
			old := mkLogDir(t, data, "OLD", time.Now().Add(-48*time.Hour), "run.log")
			cfg := sandboxCfg("/srv/rootfs")
			cfg.Sandbox.LogRetentionDays = tt.days
			var errOut bytes.Buffer
			pr, err := newProcessor(context.Background(), cfg, data, &errOut, tt.opts...)
			if err != nil {
				t.Fatal(err)
			}
			defer pr.close()
			if gone := !exists(old); gone != tt.wantGone {
				t.Fatalf("old log dir gone = %v, want %v", gone, tt.wantGone)
			}
		})
	}
}
