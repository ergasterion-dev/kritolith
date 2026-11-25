package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeRunsc writes a shell script standing in for runsc. Every call
// appends its arguments to calls.log; the "run" subcommand records its
// environment, copies the bundle's config.json, touches started, then
// runs runBody; "list" runs listBody. "kill" hangs while the file
// hang-kill exists in the fake's dir and "delete" fails while
// fail-delete exists. The driver passes no environment,
// so everything the script needs is baked into it.
type fakeRunsc struct {
	dir, path string
}

func newFakeRunsc(t *testing.T, runBody, listBody string) fakeRunsc {
	t.Helper()
	dir := realTempDir(t)
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
	script := `#!/bin/sh
D=` + q(dir) + `
echo "$*" >> "$D/calls.log"
sub=""
bundle=""
for a in "$@"; do
  case "$a" in
    --bundle=*) bundle="${a#--bundle=}" ;;
    -*) ;;
    *) if [ -z "$sub" ]; then sub="$a"; fi ;;
  esac
done
case "$sub" in
  run)
    env > "$D/env"
    cp "$bundle/config.json" "$D/config.json"
    : > "$D/started"
    ` + runBody + `
    ;;
  list)
    ` + listBody + `
    ;;
  kill)
    if [ -e "$D/hang-kill" ]; then sleep 5; fi
    ;;
  delete)
    if [ -e "$D/fail-delete" ]; then echo "delete failed" >&2; exit 1; fi
    ;;
esac
exit 0
`
	path := filepath.Join(dir, "runsc")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return fakeRunsc{dir: dir, path: path}
}

func (f fakeRunsc) calls(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, "calls.log"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

// callsTo returns the calls whose subcommand is sub.
func (f fakeRunsc) callsTo(t *testing.T, sub string) []string {
	var out []string
	for _, c := range f.calls(t) {
		for _, w := range strings.Fields(c) {
			if strings.HasPrefix(w, "-") {
				continue
			}
			if w == sub {
				out = append(out, c)
			}
			break
		}
	}
	return out
}

func testSpec(t *testing.T) RunSpec {
	t.Helper()
	rootfs := filepath.Join(realTempDir(t), "rootfs")
	if err := os.Mkdir(rootfs, 0o700); err != nil {
		t.Fatal(err)
	}
	return RunSpec{
		Container: ContainerSpec{
			Rootfs: rootfs, Args: []string{"/bin/true"}, Cwd: "/",
			Mounts:   []Mount{{Dest: "/tmp", Tmpfs: true, Writable: true, SizeMB: 16}},
			MemoryMB: 256, CPUs: 1, PIDs: 64, CPUSeconds: 30, FileSizeKB: 1024, UID: 1000, GID: 1000,
		},
		Timeout:     10 * time.Second,
		OutputLimit: 1024,
	}
}

func assertNoBundles(t *testing.T, workDir string) {
	t.Helper()
	ents, err := os.ReadDir(workDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "kritolith-") {
			t.Fatalf("bundle dir %s left behind", e.Name())
		}
	}
}

func runID(t *testing.T, f fakeRunsc) string {
	t.Helper()
	runs := f.callsTo(t, "run")
	if len(runs) != 1 {
		t.Fatalf("run calls = %q (all calls %q)", runs, f.calls(t))
	}
	w := strings.Fields(runs[0])
	return w[len(w)-1]
}

func TestRunscArgs(t *testing.T) {
	g := runscGlobals{Root: "/w/runsc-root"}
	tests := []struct {
		name string
		g    runscGlobals
		sub  string
		rest []string
		want []string
	}{
		{"run no network", g, "run", []string{"--bundle=/w/kritolith-1", "kritolith-1"},
			[]string{"--root=/w/runsc-root", "--platform=systrap", "--network=none", "run", "--bundle=/w/kritolith-1", "kritolith-1"}},
		{"run with network", runscGlobals{Root: "/r", Network: true}, "run", []string{"--bundle=/b", "kritolith-x"},
			[]string{"--root=/r", "--platform=systrap", "--network=sandbox", "run", "--bundle=/b", "kritolith-x"}},
		{"ignore cgroups", runscGlobals{Root: "/r", IgnoreCgroups: true}, "run", []string{"--bundle=/b", "kritolith-x"},
			[]string{"--root=/r", "--platform=systrap", "--network=none", "--ignore-cgroups", "run", "--bundle=/b", "kritolith-x"}},
		{"kill", g, "kill", []string{"kritolith-1", "KILL"},
			[]string{"--root=/w/runsc-root", "--platform=systrap", "--network=none", "kill", "kritolith-1", "KILL"}},
		{"delete", g, "delete", []string{"--force", "kritolith-1"},
			[]string{"--root=/w/runsc-root", "--platform=systrap", "--network=none", "delete", "--force", "kritolith-1"}},
		{"list", g, "list", []string{"--quiet"},
			[]string{"--root=/w/runsc-root", "--platform=systrap", "--network=none", "list", "--quiet"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := runscArgs(tt.g, tt.sub, tt.rest...); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("runscArgs = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCapWriter(t *testing.T) {
	tests := []struct {
		name      string
		limit     int
		writes    []string
		want      string
		truncated bool
	}{
		{"under", 10, []string{"abc", "def"}, "abcdef", false},
		{"exact", 6, []string{"abc", "def"}, "abcdef", false},
		{"over in one write", 4, []string{"abcdef"}, "abcd", true},
		{"over across writes", 4, []string{"abc", "def", "ghi"}, "abcd", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &capWriter{limit: tt.limit}
			for _, s := range tt.writes {
				if n, err := w.Write([]byte(s)); n != len(s) || err != nil {
					t.Fatalf("Write = %d, %v; must accept everything so the pipe drains", n, err)
				}
			}
			if string(w.buf) != tt.want || w.truncated != tt.truncated {
				t.Fatalf("got %q truncated=%v", w.buf, w.truncated)
			}
		})
	}
}

func TestRunscDriverRun(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		timeout   time.Duration
		limit     int
		wantExit  int
		wantOut   string
		truncated bool
		timedOut  bool
		wantKill  bool
	}{
		{name: "clean exit", body: `echo hello`, wantOut: "hello\n"},
		{name: "non-zero exit is not a driver error", body: `echo boom >&2; exit 7`, wantExit: 7, wantOut: "boom\n"},
		{name: "output over the cap is truncated", body: `i=0; while [ $i -lt 2000 ]; do echo 0123456789abcdef; i=$((i+1)); done; exit 3`,
			limit: 100, wantExit: 3, wantOut: strings.Repeat("0123456789abcdef\n", 6)[:100], truncated: true},
		{name: "wall clock kills the run", body: `sleep 30 & echo $! > "$D/child"; wait`,
			timeout: 2 * time.Second, wantExit: -1, timedOut: true, wantKill: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunsc(t, tt.body, ``)
			workDir := realTempDir(t)
			d, err := newRunscDriver(f.path, workDir)
			if err != nil {
				t.Fatal(err)
			}
			s := testSpec(t)
			if tt.timeout != 0 {
				s.Timeout = tt.timeout
			}
			if tt.limit != 0 {
				s.OutputLimit = tt.limit
			}
			start := time.Now()
			out, err := d.Run(context.Background(), s)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if time.Since(start) > 8*time.Second {
				t.Fatalf("Run took %v", time.Since(start))
			}
			if out.ExitCode != tt.wantExit || out.TimedOut != tt.timedOut || out.Truncated != tt.truncated || out.OOM {
				t.Fatalf("out = %+v", out)
			}
			if tt.wantOut != "" && string(out.Output) != tt.wantOut {
				t.Fatalf("output = %q, want %q", out.Output, tt.wantOut)
			}
			id := runID(t, f)
			if !strings.HasPrefix(id, "kritolith-") {
				t.Fatalf("container id %q", id)
			}
			dels := f.callsTo(t, "delete")
			if len(dels) == 0 || !strings.HasSuffix(dels[len(dels)-1], "delete --force "+id) {
				t.Fatalf("delete --force %s not invoked: %q", id, f.calls(t))
			}
			if kills := f.callsTo(t, "kill"); tt.wantKill && (len(kills) == 0 || !strings.HasSuffix(kills[0], "kill "+id+" KILL")) {
				t.Fatalf("kill %s KILL not invoked: %q", id, f.calls(t))
			}
			if tt.timedOut {
				assertChildDead(t, f)
			}
			assertNoBundles(t, workDir)
		})
	}
}

// assertChildDead checks that the fake's background sleep, a grandchild
// of the driver, died with the process group.
func assertChildDead(t *testing.T, f fakeRunsc) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, "child"))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if syscall.Kill(pid, 0) != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("child %d survived the wall-clock kill", pid)
}

func TestRunscDriverCancel(t *testing.T) {
	f := newFakeRunsc(t, `sleep 30 & echo $! > "$D/child"; wait`, ``)
	workDir := realTempDir(t)
	d, err := newRunscDriver(f.path, workDir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for i := 0; i < 500; i++ {
			if _, err := os.Stat(filepath.Join(f.dir, "child")); err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
	}()
	start := time.Now()
	_, err = d.Run(ctx, testSpec(t))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if time.Since(start) > 8*time.Second {
		t.Fatalf("cancel took %v", time.Since(start))
	}
	id := runID(t, f)
	if len(f.callsTo(t, "kill")) == 0 || len(f.callsTo(t, "delete")) == 0 {
		t.Fatalf("container %s not killed and deleted: %q", id, f.calls(t))
	}
	assertChildDead(t, f)
	assertNoBundles(t, workDir)
}

func TestRunscDriverEnvironment(t *testing.T) {
	t.Setenv("KRITOLITH_TEST_SECRET", "leak")
	t.Setenv("HOME", "/home/leak")
	f := newFakeRunsc(t, `:`, ``)
	d, err := newRunscDriver(f.path, realTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Run(context.Background(), testSpec(t)); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(f.dir, "env"))
	if err != nil {
		t.Fatal(err)
	}
	// The shell itself adds PWD, SHLVL, _ and OLDPWD; nothing else may
	// appear, and PATH must be the fixed value, not the host's.
	shell := map[string]bool{"PWD": true, "SHLVL": true, "_": true, "OLDPWD": true}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		k, v, _ := strings.Cut(line, "=")
		switch {
		case k == "PATH":
			if v != runscPath {
				t.Fatalf("PATH = %q, want %q", v, runscPath)
			}
		case shell[k]:
		default:
			t.Fatalf("host environment leaked to runsc: %q", line)
		}
	}
}

func TestRunscDriverResolvesSymlinks(t *testing.T) {
	base := realTempDir(t)
	realRoot := filepath.Join(base, "real-rootfs")
	realSrc := filepath.Join(base, "real-src")
	data := filepath.Join(base, "data")
	for _, p := range []string{realRoot, realSrc, filepath.Join(data, "keys")} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, name string) string {
		p := filepath.Join(base, name)
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	rootLink := link(realRoot, "rootfs-link")
	srcLink := link(realSrc, "src-link")
	keysLink := link(filepath.Join(data, "keys"), "innocent")

	resolved := func(p string) string {
		r, err := filepath.EvalSymlinks(p)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	t.Run("links are resolved before BuildOCI", func(t *testing.T) {
		f := newFakeRunsc(t, `:`, ``)
		d, err := newRunscDriver(f.path, realTempDir(t))
		if err != nil {
			t.Fatal(err)
		}
		s := testSpec(t)
		s.Container.Rootfs = rootLink
		s.Container.Mounts = append(s.Container.Mounts, Mount{Source: srcLink, Dest: "/work"})
		s.Container.Forbidden = []string{data}
		if _, err := d.Run(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(f.dir, "config.json"))
		if err != nil {
			t.Fatal(err)
		}
		var o ociConfig
		if err := json.Unmarshal(b, &o); err != nil {
			t.Fatal(err)
		}
		if o.Root.Path != resolved(realRoot) {
			t.Fatalf("root.path = %q, want %q", o.Root.Path, resolved(realRoot))
		}
		var found bool
		for _, m := range o.Mounts {
			if m.Destination == "/work" {
				found = m.Source == resolved(realSrc)
			}
		}
		if !found {
			t.Fatalf("/work source not resolved: %+v", o.Mounts)
		}
	})

	refused := []struct {
		name string
		mod  func(*ContainerSpec)
	}{
		{"mount source linking into a forbidden dir", func(c *ContainerSpec) {
			c.Mounts = append(c.Mounts, Mount{Source: keysLink, Dest: "/work"})
			c.Forbidden = []string{data}
		}},
		{"rootfs linking into a forbidden dir", func(c *ContainerSpec) {
			c.Rootfs = keysLink
			c.Forbidden = []string{data}
		}},
		{"forbidden prefix given through a link", func(c *ContainerSpec) {
			c.Mounts = append(c.Mounts, Mount{Source: filepath.Join(data, "keys"), Dest: "/work"})
			c.Forbidden = []string{link(data, "data-link")}
		}},
		{"missing mount source", func(c *ContainerSpec) {
			c.Mounts = append(c.Mounts, Mount{Source: filepath.Join(base, "nope"), Dest: "/work"})
		}},
	}
	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunsc(t, `:`, ``)
			workDir := realTempDir(t)
			d, err := newRunscDriver(f.path, workDir)
			if err != nil {
				t.Fatal(err)
			}
			s := testSpec(t)
			tt.mod(&s.Container)
			if _, err := d.Run(context.Background(), s); err == nil {
				t.Fatal("Run accepted the spec")
			}
			if c := f.calls(t); len(c) != 0 {
				t.Fatalf("runsc invoked for a refused spec: %q", c)
			}
			assertNoBundles(t, workDir)
		})
	}
}

func TestRunscDriverRejectsBadRunSpec(t *testing.T) {
	f := newFakeRunsc(t, `:`, ``)
	d, err := newRunscDriver(f.path, realTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, mod := range []func(*RunSpec){
		func(s *RunSpec) { s.Timeout = 0 },
		func(s *RunSpec) { s.OutputLimit = 0 },
		func(s *RunSpec) { s.Container.MemoryMB = 0 },
		func(s *RunSpec) { s.OutputLimit = maxOutputLimit + 1 },
	} {
		s := testSpec(t)
		mod(&s)
		if _, err := d.Run(context.Background(), s); err == nil {
			t.Fatalf("accepted %+v", s)
		}
	}
	if c := f.calls(t); len(c) != 0 {
		t.Fatalf("runsc invoked: %q", c)
	}
}

func TestNewRunscDriver(t *testing.T) {
	f := newFakeRunsc(t, `:`, ``)
	t.Run("missing runtime", func(t *testing.T) {
		if _, err := newRunscDriver(filepath.Join(realTempDir(t), "no-runsc"), realTempDir(t)); err == nil {
			t.Fatal("accepted a missing runtime")
		}
	})
	t.Run("relative workDir", func(t *testing.T) {
		if _, err := newRunscDriver(f.path, "relative/dir"); err == nil {
			t.Fatal("accepted a relative workDir")
		}
	})
	t.Run("runtime on PATH, state dir 0700", func(t *testing.T) {
		t.Setenv("PATH", f.dir)
		workDir := filepath.Join(realTempDir(t), "work")
		d, err := newRunscDriver("runsc", workDir)
		if err != nil {
			t.Fatal(err)
		}
		if d.runtime != f.path {
			t.Fatalf("runtime = %q", d.runtime)
		}
		for _, p := range []string{workDir, filepath.Join(workDir, runscStateDir)} {
			fi, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o700 {
				t.Fatalf("%s mode %v", p, fi.Mode())
			}
		}
	})
}

func TestSweepOrphans(t *testing.T) {
	now := time.Now()
	old := now.Add(-2 * time.Hour)
	cutoff := now.Add(-time.Hour)

	// list reports every container not yet deleted.
	f := newFakeRunsc(t, `:`, `for id in kritolith-9001 other-1 kritolith-2002 kritolith-backup; do grep -q -- "delete --force $id\$" "$D/calls.log" || echo "$id"; done`)
	workDir := claimedWorkDir(t)
	outside := realTempDir(t)
	mk := func(name string, mtime time.Time) string {
		p := filepath.Join(workDir, name)
		if err := os.MkdirAll(filepath.Join(p, "inner"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		return p
	}
	mk("kritolith-1001", old)
	mk("kritolith-run-1003", old)
	mk("kritolith-backup", old)
	mk("kritolith-2002", now)
	mk("other-old", old)
	nested := filepath.Join(workDir, "sub", "kritolith-4004")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(nested, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "kritolith-5005"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(outside, "victim")
	if err := os.Mkdir(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(workDir, "kritolith-6006")); err != nil {
		t.Fatal(err)
	}

	// A symlink's own mtime cannot be set with the standard library, so
	// a cutoff in the future makes the link "old" for the second pass.
	if err := sweepOrphans(f.path, workDir, cutoff); err == nil || !strings.Contains(err.Error(), "kept 1 leftover") {
		t.Fatalf("err = %v, want the kept scratch tree reported", err)
	}
	exists := func(p string) bool { _, err := os.Lstat(p); return err == nil }
	for p, want := range map[string]bool{
		filepath.Join(workDir, "kritolith-1001"): false,
		// kritolith-2002 is still listed (its bundle is new), so no
		// scratch tree is removed while it may still use one.
		filepath.Join(workDir, "kritolith-run-1003"): true,
		filepath.Join(workDir, "kritolith-backup"):   true,
		filepath.Join(workDir, "kritolith-2002"):     true,
		filepath.Join(workDir, "other-old"):          true,
		nested:                                       true,
		filepath.Join(workDir, "kritolith-5005"):     true,
		filepath.Join(workDir, "kritolith-6006"):     true,
		victim:                                       true,
	} {
		if exists(p) != want {
			t.Fatalf("%s exists=%v, want %v", p, !want, want)
		}
	}
	dels := strings.Join(f.callsTo(t, "delete"), "\n")
	if !strings.Contains(dels, "delete --force kritolith-9001") {
		t.Fatalf("orphan container not deleted: %q", f.calls(t))
	}
	if strings.Contains(dels, "other-1") || strings.Contains(dels, "kritolith-2002") || strings.Contains(dels, "kritolith-backup") {
		t.Fatalf("deleted a container it does not own or a live one: %q", dels)
	}

	if err := sweepOrphans(f.path, workDir, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !exists(victim) || !exists(filepath.Join(workDir, "kritolith-6006")) {
		t.Fatal("sweep followed or removed a symlink")
	}
	if exists(filepath.Join(workDir, "kritolith-2002")) || exists(filepath.Join(workDir, "kritolith-run-1003")) {
		t.Fatal("stale dir kept after the cutoff passed it and its container was deleted")
	}
}

func TestSweepOrphansToleratesListFailure(t *testing.T) {
	f := newFakeRunsc(t, `:`, `echo nope >&2; exit 1`)
	workDir := claimedWorkDir(t)
	p := filepath.Join(workDir, "kritolith-1001")
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	err := sweepOrphans(f.path, workDir, time.Now())
	if err == nil {
		t.Fatal("list failure not reported")
	}
	// With the container state unknown, a container may still be
	// writing into the tree: it is left for the next start.
	if _, serr := os.Lstat(p); serr != nil {
		t.Fatal("stale dir removed although runsc list failed")
	}
}

// The sweep leaves a bundle or scratch tree alone while a container
// that may use it could still be running: its delete failed, it is
// still listed, or runsc is not there to ask.
func TestSweepOrphansKeepsTreesOfLiveContainers(t *testing.T) {
	old := time.Now().Add(-time.Hour)
	setup := func(t *testing.T) (string, map[string]string) {
		workDir := claimedWorkDir(t)
		ps := map[string]string{}
		for _, n := range []string{"kritolith-1001", "kritolith-run-1002", "kritolith-1003"} {
			p := filepath.Join(workDir, n)
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(p, old, old); err != nil {
				t.Fatal(err)
			}
			ps[n] = p
		}
		return workDir, ps
	}
	exists := func(p string) bool { _, err := os.Lstat(p); return err == nil }
	t.Run("delete fails", func(t *testing.T) {
		f := newFakeRunsc(t, `:`, `echo kritolith-1001`)
		f.toggle(t, "fail-delete", true)
		workDir, ps := setup(t)
		if err := sweepOrphans(f.path, workDir, time.Now()); err == nil {
			t.Fatal("failed delete not reported")
		}
		if !exists(ps["kritolith-1001"]) || !exists(ps["kritolith-run-1002"]) {
			t.Fatal("removed the tree of a container that could not be deleted")
		}
		if exists(ps["kritolith-1003"]) {
			t.Fatal("bundle of no container kept")
		}
	})
	t.Run("still listed after delete", func(t *testing.T) {
		f := newFakeRunsc(t, `:`, `echo kritolith-1001`)
		workDir, ps := setup(t)
		if err := sweepOrphans(f.path, workDir, time.Now()); err == nil {
			t.Fatal("surviving container not reported")
		}
		if !exists(ps["kritolith-1001"]) || !exists(ps["kritolith-run-1002"]) {
			t.Fatal("removed the tree of a container that is still listed")
		}
	})
	t.Run("runtime missing", func(t *testing.T) {
		workDir, ps := setup(t)
		if err := sweepOrphans(filepath.Join(t.TempDir(), "no-runsc"), workDir, time.Now()); err == nil {
			t.Fatal("kept leftovers not reported")
		}
		for n, p := range ps {
			if !exists(p) {
				t.Fatalf("%s removed without asking runsc which containers live", n)
			}
		}
	})
}

func TestSweepOrphansMissingRuntime(t *testing.T) {
	workDir := claimedWorkDir(t)
	if err := SweepOrphans(filepath.Join(realTempDir(t), "no-runsc"), workDir); err != nil {
		t.Fatalf("missing runtime: %v", err)
	}
}

func (f fakeRunsc) toggle(t *testing.T, name string, on bool) {
	t.Helper()
	p := filepath.Join(f.dir, name)
	if on {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
}

func TestNewRunscDriverWorkDirChecks(t *testing.T) {
	f := newFakeRunsc(t, `:`, ``)
	tests := []struct {
		name    string
		setup   func(t *testing.T) string
		wantErr bool
	}{
		{"fresh dir is created 0700", func(t *testing.T) string {
			return filepath.Join(realTempDir(t), "a", "work")
		}, false},
		{"existing private dir is accepted", func(t *testing.T) string {
			return realTempDir(t)
		}, false},
		{"root is refused", func(t *testing.T) string { return "/" }, true},
		{"single component is refused", func(t *testing.T) string { return "/kritolith" }, true},
		{"symlinked work dir is refused", func(t *testing.T) string {
			p := filepath.Join(realTempDir(t), "link")
			if err := os.Symlink(realTempDir(t), p); err != nil {
				t.Fatal(err)
			}
			return p
		}, true},
		{"group or world writable work dir is refused", func(t *testing.T) string {
			p := filepath.Join(realTempDir(t), "open")
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, 0o777); err != nil {
				t.Fatal(err)
			}
			return p
		}, true},
		{"symlinked state dir is refused", func(t *testing.T) string {
			p := realTempDir(t)
			if err := os.Symlink(realTempDir(t), filepath.Join(p, runscStateDir)); err != nil {
				t.Fatal(err)
			}
			return p
		}, true},
		{"writable state dir is refused", func(t *testing.T) string {
			p := realTempDir(t)
			s := filepath.Join(p, runscStateDir)
			if err := os.Mkdir(s, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(s, 0o770); err != nil {
				t.Fatal(err)
			}
			return p
		}, true},
		{"work dir that is a file is refused", func(t *testing.T) string {
			p := filepath.Join(realTempDir(t), "file")
			if err := os.WriteFile(p, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := tt.setup(t)
			var before os.FileMode
			if fi, err := os.Lstat(p); err == nil {
				before = fi.Mode()
			}
			d, err := newRunscDriver(f.path, p)
			if tt.wantErr {
				if err == nil {
					d.Close()
					t.Fatal("accepted an unsafe work dir")
				}
				if fi, lerr := os.Lstat(p); lerr == nil && fi.Mode() != before {
					t.Fatalf("refused dir was changed: %v -> %v", before, fi.Mode())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			// A dir the driver created is 0700; an existing one is left
			// as it was, which the check allowed (no group/other write).
			want := map[string]os.FileMode{p: before.Perm(), filepath.Join(p, runscStateDir): 0o700}
			if before == 0 {
				want[p] = 0o700
			}
			for q, perm := range want {
				fi, err := os.Lstat(q)
				if err != nil {
					t.Fatal(err)
				}
				if !fi.IsDir() || fi.Mode().Perm() != perm {
					t.Fatalf("%s mode %v, want %v", q, fi.Mode(), perm)
				}
			}
		})
	}
}

func TestNewRunscDriverRefusesForeignOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown a dir to another user")
	}
	f := newFakeRunsc(t, `:`, ``)
	p := filepath.Join(realTempDir(t), "foreign")
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(p, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if d, err := newRunscDriver(f.path, p); err == nil {
		d.Close()
		t.Fatal("accepted a work dir owned by another user")
	}
}

func TestRunscDriverLocksWorkDir(t *testing.T) {
	f := newFakeRunsc(t, `:`, ``)
	workDir := realTempDir(t)
	d, err := newRunscDriver(f.path, workDir)
	if err != nil {
		t.Fatal(err)
	}
	if d2, err := newRunscDriver(f.path, workDir); err == nil {
		d2.Close()
		t.Fatal("second driver on the same work dir was allowed")
	} else if !strings.Contains(err.Error(), "in use") {
		t.Fatalf("unclear error: %v", err)
	}
	if err := SweepOrphans(f.path, workDir); err == nil {
		t.Fatal("sweep ran while a live driver holds the work dir")
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d3, err := newRunscDriver(f.path, workDir)
	if err != nil {
		t.Fatalf("work dir not released by Close: %v", err)
	}
	d3.Close()
}

func TestRunscDriverCleanupFailure(t *testing.T) {
	f := newFakeRunsc(t, `echo out`, ``)
	workDir := realTempDir(t)
	d, err := newRunscDriver(f.path, workDir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	// delete --force fails: the run is an error and the id is kept.
	f.toggle(t, "fail-delete", true)
	if _, err := d.Run(context.Background(), testSpec(t)); err == nil {
		t.Fatal("a failed delete --force was reported as a clean run")
	}
	first := runID(t, f)
	if _, ok := d.pending[first]; !ok {
		t.Fatalf("failed container %s not remembered: %v", first, d.pending)
	}
	assertNoBundles(t, workDir)

	// The next Run retries the deletion first.
	f.toggle(t, "fail-delete", false)
	if _, err := os.Stat(filepath.Join(f.dir, "calls.log")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.dir, "calls.log")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Run(context.Background(), testSpec(t)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(f.callsTo(t, "delete"), "\n"), "delete --force "+first) {
		t.Fatalf("pending %s not retried: %q", first, f.calls(t))
	}
	if len(d.pending) != 0 {
		t.Fatalf("pending not cleared: %v", d.pending)
	}

	// Close retries too, and reports what still cannot be deleted.
	f.toggle(t, "fail-delete", true)
	if _, err := d.Run(context.Background(), testSpec(t)); err == nil {
		t.Fatal("a failed delete --force was reported as a clean run")
	}
	if err := d.Close(); err == nil {
		t.Fatal("Close hid a container it could not delete")
	}
	f.toggle(t, "fail-delete", false)
	d2, err := newRunscDriver(f.path, workDir)
	if err != nil {
		t.Fatal(err)
	}
	d2.Close()
}

func TestRunscDriverCloseRetriesPending(t *testing.T) {
	f := newFakeRunsc(t, `:`, ``)
	d, err := newRunscDriver(f.path, realTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	f.toggle(t, "fail-delete", true)
	if _, err := d.Run(context.Background(), testSpec(t)); err == nil {
		t.Fatal("a failed delete --force was reported as a clean run")
	}
	id := runID(t, f)
	f.toggle(t, "fail-delete", false)
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	dels := f.callsTo(t, "delete")
	if !strings.HasSuffix(dels[len(dels)-1], "delete --force "+id) || len(d.pending) != 0 {
		t.Fatalf("Close did not retry %s: %q", id, dels)
	}
}

func TestRunscDriverKillTimeoutIsAnError(t *testing.T) {
	f := newFakeRunsc(t, `sleep 30 & echo $! > "$D/child"; wait`, ``)
	d, err := newRunscDriver(f.path, realTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.cleanupTimeout = 300 * time.Millisecond
	f.toggle(t, "hang-kill", true)
	s := testSpec(t)
	s.Timeout = 2 * time.Second
	out, err := d.Run(context.Background(), s)
	if err == nil {
		t.Fatal("a hung runsc kill was reported as a clean run")
	}
	if !out.TimedOut {
		t.Fatalf("out = %+v", out)
	}
}

func TestRunError(t *testing.T) {
	ioErr := errors.New("copy failed")
	tests := []struct {
		name         string
		waitErr, ctx error
		wantNil      bool
		wantIs       []error
	}{
		{"clean", nil, nil, true, nil},
		{"container exit status is not an error", &exec.ExitError{}, nil, true, nil},
		{"wait delay is not an error", exec.ErrWaitDelay, nil, true, nil},
		{"wait failure", ioErr, nil, false, []error{ioErr}},
		{"cancelled", &exec.ExitError{}, context.Canceled, false, []error{context.Canceled}},
		{"cancelled and wait failure", ioErr, context.Canceled, false, []error{context.Canceled, ioErr}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runError(tt.waitErr, tt.ctx)
			if (err == nil) != tt.wantNil {
				t.Fatalf("err = %v", err)
			}
			for _, want := range tt.wantIs {
				if !errors.Is(err, want) {
					t.Fatalf("errors.Is(%v, %v) = false", err, want)
				}
			}
		})
	}
}
