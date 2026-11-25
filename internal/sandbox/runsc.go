package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// TODO(task10): verify against a real runsc (these are tracked checks,
// not open design questions):
//   - linux.devices: runsc honours the list (null, zero, urandom, tty)
//     and adds nothing else; check `ls -la /dev` inside a container.
//   - /dev contents: only null, zero, urandom, tty (+ runsc's own
//     fd/stdin/stdout/stderr/pts links); nothing from the host.
//   - linux.resources: memory.limit, cpu.quota/period and pids.limit are
//     applied, or knowingly not applied under --ignore-cgroups.
//   - rlimit names: RLIMIT_CPU, RLIMIT_FSIZE, RLIMIT_NOFILE, RLIMIT_NPROC
//     are accepted and enforced inside the sandbox.
//   - --ignore-cgroups: confirm no cgroup is created and that rlimits and
//     the host wall clock still bound the run; record that in Limits.
//   - --root=<workDir>/runsc-state: long workDir paths stay within the
//     unix socket path limit for anything runsc puts there.
//   - exit status: runsc exits 128 when it fails to run the container
//     itself, which a contained `exit 128` cannot be told from.
//   - OOM: find whether runsc (`runsc events`, state, or wait status)
//     says a container was OOM-killed; until then OOM is never set.
//   - kill/delete flags marked UNVERIFIED below.

// processStart is when this process started; SweepOrphans removes
// only what is older. It is written once, at init, and never changed.
var processStart = time.Now()

const (
	// runscPath is the only environment runsc receives: a fixed PATH,
	// never the host's, so no host variable reaches the runtime.
	runscPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	// runscStateDir, under workDir, is runsc's --root (container state).
	runscStateDir = "runsc-state"
	// orphanPrefix names every container and bundle dir this tool owns.
	orphanPrefix = "kritolith-"

	cleanupTimeout = 30 * time.Second
	// waitDelay bounds how long Wait keeps the output pipes open after
	// runsc exits, in case a process outside its group still holds them.
	waitDelay      = 5 * time.Second
	controlOutCap  = 1 << 20
	maxRunsTimeout = 24 * time.Hour
)

// runscGlobals are the global flags given to every runsc invocation.
type runscGlobals struct {
	Root          string
	Network       bool
	IgnoreCgroups bool
}

// runscArgs builds a runsc command line. It is pure.
//
// Verified flags (gVisor docs and source, read 2026-11-25):
//   - --root=<dir>: state directory; default $XDG_RUNTIME_DIR/runsc or
//     /var/run/runsc, so it is always given explicitly.
//     https://github.com/google/gvisor/blob/master/runsc/config/flags.go
//   - --network=none|sandbox|host (default sandbox). We use none, or
//     sandbox (gVisor's own netstack) for the fetch phase; never host.
//     Also verified on a real host: --network=none (release-20261102.0).
//     https://github.com/google/gvisor/blob/master/runsc/config/flags.go
//   - --platform=systrap (default systrap; also ptrace, kvm, auto).
//     Verified on a real host (release-20261102.0).
//     https://github.com/google/gvisor/blob/master/runsc/config/flags.go
//   - --ignore-cgroups ("don't configure cgroups"), only when the
//     operator's setup cannot use cgroups (driver.ignoreCgroups).
//     Verified on a real host (release-20261102.0).
//   - run [--bundle=<dir>] <id>: --bundle comes from create's flags,
//     default the current directory, so it is always given. runsc exits
//     with the container's status, or 128+signal if it was signalled,
//     or 128 if runsc itself failed.
//     https://github.com/google/gvisor/blob/master/runsc/cmd/run.go
//     https://github.com/google/gvisor/blob/master/runsc/cmd/create.go
//     https://github.com/google/gvisor/blob/master/runsc/cli/cli.go
//   - kill <id> [signal]: signal by name (KILL) or number; default TERM.
//     https://github.com/google/gvisor/blob/master/runsc/cmd/kill.go
//   - delete --force <ids...>: terminates a running container; a missing
//     id is a warning, not a failure.
//     https://github.com/google/gvisor/blob/master/runsc/cmd/delete.go
//   - list --quiet: container ids only, one per line.
//     https://github.com/google/gvisor/blob/master/runsc/cmd/list.go
//
// Global flags are given to every subcommand, as containerd and Docker
// do with runtime args, so kill/delete/list see the same state root.
// UNVERIFIED: confirm in Task 10 against real runsc that kill, delete
// and list accept --network/--platform/--ignore-cgroups without error.
// --rootless is not used: the gVisor rootless guide says it does not
// support create (which run uses) nor netstack.
// https://gvisor.dev/docs/user_guide/rootless/
func runscArgs(g runscGlobals, sub string, rest ...string) []string {
	args := []string{"--root=" + g.Root, "--platform=systrap"}
	if g.Network {
		args = append(args, "--network=sandbox")
	} else {
		args = append(args, "--network=none")
	}
	if g.IgnoreCgroups {
		args = append(args, "--ignore-cgroups")
	}
	args = append(args, sub)
	return append(args, rest...)
}

// capWriter keeps the first limit bytes written and discards the rest,
// always reporting success so the writer behind it never blocks on a
// full pipe.
type capWriter struct {
	mu        sync.Mutex
	limit     int
	buf       []byte
	truncated bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	room := w.limit - len(w.buf)
	if room < 0 {
		room = 0
	}
	if len(p) > room {
		w.buf = append(w.buf, p[:room]...)
		w.truncated = true
	} else {
		w.buf = append(w.buf, p...)
	}
	return len(p), nil
}

func (w *capWriter) result() ([]byte, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf...), w.truncated
}

// runscDriver runs containers with gVisor's runsc.
type runscDriver struct {
	runtime string // absolute path
	workDir string // absolute; holds bundles and the state root
	// ignoreCgroups passes --ignore-cgroups, for hosts where runsc
	// cannot configure cgroups. Set by the runner from its config.
	ignoreCgroups bool
}

// newRunscDriver resolves runtime on PATH and prepares workDir (0700)
// with runsc's state root inside it.
func newRunscDriver(runtime, workDir string) (*runscDriver, error) {
	rt, err := exec.LookPath(runtime)
	if err != nil {
		return nil, fmt.Errorf("sandbox: find runtime %q: %w", runtime, err)
	}
	if rt, err = filepath.Abs(rt); err != nil {
		return nil, fmt.Errorf("sandbox: runtime path: %w", err)
	}
	if !filepath.IsAbs(workDir) || hasDotDot(workDir) {
		return nil, fmt.Errorf("sandbox: work dir %q must be absolute without ..", workDir)
	}
	workDir = filepath.Clean(workDir)
	for _, p := range []string{workDir, filepath.Join(workDir, runscStateDir)} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			return nil, fmt.Errorf("sandbox: create %s: %w", p, err)
		}
		if err := os.Chmod(p, 0o700); err != nil {
			return nil, fmt.Errorf("sandbox: chmod %s: %w", p, err)
		}
	}
	return &runscDriver{runtime: rt, workDir: workDir}, nil
}

func (d *runscDriver) globals(network bool) runscGlobals {
	return runscGlobals{Root: filepath.Join(d.workDir, runscStateDir), Network: network, IgnoreCgroups: d.ignoreCgroups}
}

// Run implements driver.
func (d *runscDriver) Run(ctx context.Context, s RunSpec) (out RunOutput, err error) {
	if s.Timeout <= 0 || s.Timeout > maxRunsTimeout {
		return RunOutput{}, fmt.Errorf("sandbox: timeout %v out of range", s.Timeout)
	}
	if s.OutputLimit <= 0 {
		return RunOutput{}, errors.New("sandbox: output limit must be positive")
	}
	spec, err := resolveSpec(s.Container)
	if err != nil {
		return RunOutput{}, fmt.Errorf("sandbox: %w", err)
	}
	cfg, err := BuildOCI(spec)
	if err != nil {
		return RunOutput{}, fmt.Errorf("sandbox: oci config: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return RunOutput{}, fmt.Errorf("sandbox: %w", err)
	}

	// MkdirTemp creates the dir 0700 with a random suffix; its name is
	// also the container id, which ties a container to its bundle for
	// the orphan sweep.
	bundle, err := os.MkdirTemp(d.workDir, orphanPrefix+"*")
	if err != nil {
		return RunOutput{}, fmt.Errorf("sandbox: create bundle: %w", err)
	}
	defer func() {
		if rerr := os.RemoveAll(bundle); rerr != nil && err == nil {
			err = fmt.Errorf("sandbox: remove bundle: %w", rerr)
		}
	}()
	id := filepath.Base(bundle)
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), cfg, 0o600); err != nil {
		return RunOutput{}, fmt.Errorf("sandbox: write config: %w", err)
	}

	g := d.globals(spec.Network)
	w := &capWriter{limit: s.OutputLimit}
	cmd := runscCommand(d.runtime, runscArgs(g, "run", "--bundle="+bundle, id), bundle)
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Start(); err != nil {
		return RunOutput{}, fmt.Errorf("sandbox: start runsc: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	finished := false
	// On every exit path after Start, including a panic: kill the runsc
	// process group if it is still running, wait for it, then remove the
	// container. Deferred calls run in reverse, so this runs before the
	// bundle is removed.
	defer func() {
		if !finished {
			killGroup(cmd)
			d.kill(g, id)
			<-done
		}
		d.remove(g, id)
	}()

	timer := time.NewTimer(s.Timeout)
	defer timer.Stop()
	var waitErr, ctxErr error
	select {
	case waitErr = <-done:
	case <-timer.C:
		out.TimedOut = true
	case <-ctx.Done():
		ctxErr = ctx.Err()
	}
	if out.TimedOut || ctxErr != nil {
		killGroup(cmd)
		d.kill(g, id)
		waitErr = <-done
	}
	finished = true

	out.Output, out.Truncated = w.result()
	// ExitCode is -1 when runsc was killed by a signal (our wall-clock
	// or cancel kill); otherwise it is runsc's exit status, which is the
	// container's (or 128+signal). OOM is left false: runsc's exit status
	// does not say why a container was SIGKILLed (137 is any SIGKILL),
	// and guessing would turn a hostile `kill -9 $$` into a resource
	// fact. TODO(task10) above tracks finding a real OOM signal.
	out.ExitCode = cmd.ProcessState.ExitCode()
	var ee *exec.ExitError
	if waitErr != nil && !errors.As(waitErr, &ee) && !errors.Is(waitErr, exec.ErrWaitDelay) {
		return out, fmt.Errorf("sandbox: wait for runsc: %w", waitErr)
	}
	if ctxErr != nil {
		return out, fmt.Errorf("sandbox: run cancelled: %w", ctxErr)
	}
	return out, nil
}

// runscCommand builds a runsc invocation with no host environment
// beyond a fixed PATH, in its own process group so a kill reaches all
// of it.
func runscCommand(runtime string, args []string, dir string) *exec.Cmd {
	cmd := exec.Command(runtime, args...)
	cmd.Env = []string{"PATH=" + runscPath}
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = waitDelay
	return cmd
}

func killGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	// The group id is runsc's pid (Setpgid with Pgid 0). Errors mean the
	// group is already gone.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

// control runs a short runsc management command (kill, delete, list)
// with its own timeout, independent of the caller's possibly cancelled
// context, and returns its capped combined output.
func control(runtime, dir string, args []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	cmd := runscCommand(runtime, args, dir)
	w := &capWriter{limit: controlOutCap}
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		killGroup(cmd)
		<-done
		err = ctx.Err()
	}
	b, _ := w.result()
	return b, err
}

// kill sends SIGKILL to the container. Failure is expected when the
// container already exited or was never created; remove follows anyway.
func (d *runscDriver) kill(g runscGlobals, id string) {
	_, _ = control(d.runtime, d.workDir, runscArgs(g, "kill", id, "KILL"))
}

// remove force-deletes the container. delete --force treats a missing
// container as a warning, so this is safe after runsc run cleaned up.
// A failure here leaves an orphan that SweepOrphans removes on the next
// start; it does not change the run's result.
func (d *runscDriver) remove(g runscGlobals, id string) {
	_, _ = control(d.runtime, d.workDir, runscArgs(g, "delete", "--force", id))
}

// resolveSpec returns a copy of c with the rootfs and every bind source
// resolved through symlinks, and the forbidden list extended with the
// resolved form of each forbidden and built-in denied prefix, so that
// BuildOCI's checks see real paths: a link into the data directory is
// refused, and so is a source reached through a linked prefix.
func resolveSpec(c ContainerSpec) (ContainerSpec, error) {
	out := c
	var err error
	if out.Rootfs, err = evalExisting(c.Rootfs); err != nil {
		return ContainerSpec{}, fmt.Errorf("rootfs: %w", err)
	}
	out.Mounts = make([]Mount, len(c.Mounts))
	for i, m := range c.Mounts {
		out.Mounts[i] = m
		if m.Tmpfs {
			continue
		}
		if out.Mounts[i].Source, err = evalExisting(m.Source); err != nil {
			return ContainerSpec{}, fmt.Errorf("mount %s: %w", m.Dest, err)
		}
	}
	forbidden := append([]string{}, c.Forbidden...)
	for _, list := range [][]string{c.Forbidden, builtinDeny} {
		for _, p := range list {
			if r := evalBestEffort(p); r != "" && r != filepath.Clean(p) {
				forbidden = append(forbidden, r)
			}
		}
	}
	out.Forbidden = forbidden
	return out, nil
}

// evalExisting resolves an absolute host path that must exist.
func evalExisting(p string) (string, error) {
	if !filepath.IsAbs(p) || strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("host path %q is not absolute", p)
	}
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", fmt.Errorf("resolve %q: %w", p, err)
	}
	return r, nil
}

// evalBestEffort resolves p through its longest existing ancestor, so a
// forbidden prefix that does not exist yet still has its linked parent
// resolved. It returns "" for paths it cannot use.
func evalBestEffort(p string) string {
	if !filepath.IsAbs(p) || hasDotDot(p) || strings.ContainsRune(p, 0) {
		return ""
	}
	p = filepath.Clean(p)
	rest := ""
	for cur := p; ; cur = filepath.Dir(cur) {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(r, rest)
		}
		if cur == "/" {
			return ""
		}
		rest = filepath.Join(filepath.Base(cur), rest)
	}
}

// SweepOrphans removes what a crashed or interrupted earlier run left
// behind in workDir: runsc containers named kritolith-* whose bundle
// dir is gone or older than this process, and kritolith-* directories
// directly in workDir older than this process. It never follows a
// symlink and touches nothing else. It keeps going past failures and
// returns them joined; the caller should log the error, not abort. A
// runtime that cannot be found means there are no containers to sweep.
func SweepOrphans(runtime, workDir string) error {
	return sweepOrphans(runtime, workDir, processStart)
}

func sweepOrphans(runtime, workDir string, before time.Time) error {
	if !filepath.IsAbs(workDir) {
		return fmt.Errorf("sandbox: sweep: work dir %q is not absolute", workDir)
	}
	workDir = filepath.Clean(workDir)
	var errs []error
	if rt, err := exec.LookPath(runtime); err == nil {
		if err := sweepContainers(rt, workDir, before); err != nil {
			errs = append(errs, err)
		}
	}
	ents, err := os.ReadDir(workDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.Join(errs...)
		}
		return errors.Join(append(errs, fmt.Errorf("sandbox: sweep: read %s: %w", workDir, err))...)
	}
	for _, e := range ents {
		if !isOrphanName(e.Name()) {
			continue
		}
		p := filepath.Join(workDir, e.Name())
		fi, err := os.Lstat(p)
		if err != nil {
			errs = append(errs, fmt.Errorf("sandbox: sweep: %w", err))
			continue
		}
		// Only real directories: a symlink is never followed or removed.
		if !fi.IsDir() || !fi.ModTime().Before(before) {
			continue
		}
		if err := os.RemoveAll(p); err != nil {
			errs = append(errs, fmt.Errorf("sandbox: sweep: remove %s: %w", p, err))
		}
	}
	return errors.Join(errs...)
}

func isOrphanName(n string) bool {
	return strings.HasPrefix(n, orphanPrefix) && len(n) > len(orphanPrefix) && !strings.ContainsAny(n, "/\x00")
}

// sweepContainers force-deletes kritolith-* containers in the state
// root unless their bundle dir exists and is newer than before (a run
// of this process still using it).
func sweepContainers(runtime, workDir string, before time.Time) error {
	g := runscGlobals{Root: filepath.Join(workDir, runscStateDir)}
	b, err := control(runtime, workDir, runscArgs(g, "list", "--quiet"))
	if err != nil {
		return fmt.Errorf("sandbox: sweep: runsc list: %w", err)
	}
	var errs []error
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		id := strings.TrimSpace(sc.Text())
		if !isOrphanName(id) {
			continue
		}
		if fi, err := os.Lstat(filepath.Join(workDir, id)); err == nil && fi.IsDir() && !fi.ModTime().Before(before) {
			continue
		}
		_, _ = control(runtime, workDir, runscArgs(g, "kill", id, "KILL"))
		if _, err := control(runtime, workDir, runscArgs(g, "delete", "--force", id)); err != nil {
			errs = append(errs, fmt.Errorf("sandbox: sweep: delete %s: %w", id, err))
		}
	}
	return errors.Join(errs...)
}
