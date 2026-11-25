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
//   - sandbox and gofer processes are gone after a wall-clock kill (they
//     run in their own session, so the process-group kill misses them;
//     `runsc kill` and `delete --force` must reach them).
//   - delete --force on a running container removes its sandbox and
//     gofer processes and its state under --root.
//   - kill/delete/list flags marked UNVERIFIED below.

// processStart is when this process started; SweepOrphans removes
// only what is older. It is written once, at init, and never changed.
var processStart = time.Now()

const (
	// runscPath is the only environment runsc receives: a fixed PATH,
	// never the host's, so no host variable reaches the runtime.
	runscPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	// runscStateDir, under workDir, is runsc's --root (container state).
	runscStateDir = "runsc-state"
	// lockFile, under workDir, is flocked by the live driver.
	lockFile = ".lock"
	// orphanPrefix names every container and bundle dir this tool owns.
	orphanPrefix = "kritolith-"

	// defaultCleanupTimeout bounds each runsc kill/delete/list call.
	defaultCleanupTimeout = 30 * time.Second
	// waitDelay bounds how long Wait keeps the output pipes open after
	// runsc exits, in case a process outside its group still holds them.
	waitDelay      = 5 * time.Second
	controlOutCap  = 1 << 20
	maxRunsTimeout = 24 * time.Hour
	// maxOutputLimit is the largest OutputLimit a RunSpec may ask for.
	maxOutputLimit = 64 << 20
)

// runscGlobals are the global flags given to every runsc invocation.
type runscGlobals struct {
	Root          string
	Network       bool
	IgnoreCgroups bool
}

// runscArgs builds a runsc command line. It is pure.
//
// Flags, checked against the gVisor source and docs read 2026-11-25:
//   - --root=<dir>: state directory; default $XDG_RUNTIME_DIR/runsc or
//     /var/run/runsc, so it is always given explicitly.
//     https://github.com/google/gvisor/blob/master/runsc/config/flags.go
//   - --network=none|sandbox|host (default sandbox). We use none, or
//     sandbox (gVisor's own netstack) for the fetch phase; never host.
//     https://github.com/google/gvisor/blob/master/runsc/config/flags.go
//   - --platform=systrap (default systrap; also ptrace, kvm, auto).
//     https://github.com/google/gvisor/blob/master/runsc/config/flags.go
//   - --ignore-cgroups ("don't configure cgroups"), only when the
//     operator's setup cannot use cgroups (driver.ignoreCgroups).
//     https://github.com/google/gvisor/blob/master/runsc/config/flags.go
//   - --network=none, --platform=systrap and --ignore-cgroups were run on
//     a real host on 2026-11-11 (gVisor release-20261102.0, privileged
//     container on Docker Desktop), per the handoff; not re-verified in
//     this session (runsc is not installed here).
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

// runscDriver runs containers with gVisor's runsc. It holds an
// exclusive lock on its work dir until Close.
//
// For the wiring in Tasks 7 and 9: ContainerSpec.Network must be set
// only by the fetch phase, and workDir must neither equal nor contain
// the data directory (database, keys).
type runscDriver struct {
	runtime string // absolute path
	workDir string // absolute; holds bundles, the state root and the lock
	// ignoreCgroups passes --ignore-cgroups, for hosts where runsc
	// cannot configure cgroups. Set by the runner from its config.
	ignoreCgroups bool
	// cleanupTimeout bounds each kill/delete call.
	cleanupTimeout time.Duration

	mu   sync.Mutex
	lock *os.File
	// pending holds containers whose delete --force failed; they are
	// retried at the start of each Run and by Close.
	pending map[string]runscGlobals
}

// newRunscDriver resolves runtime on PATH, prepares workDir and runsc's
// state root inside it (both 0700, owned by this user, never a
// symlink), and locks workDir against a second live driver. Call Close
// when done.
func newRunscDriver(runtime, workDir string) (*runscDriver, error) {
	rt, err := exec.LookPath(runtime)
	if err != nil {
		return nil, fmt.Errorf("sandbox: find runtime %q: %w", runtime, err)
	}
	if rt, err = filepath.Abs(rt); err != nil {
		return nil, fmt.Errorf("sandbox: runtime path: %w", err)
	}
	workDir, err = cleanWorkDir(workDir)
	if err != nil {
		return nil, err
	}
	for _, p := range []string{workDir, filepath.Join(workDir, runscStateDir)} {
		if err := ensurePrivateDir(p); err != nil {
			return nil, err
		}
	}
	lock, err := lockWorkDir(workDir)
	if err != nil {
		return nil, err
	}
	return &runscDriver{runtime: rt, workDir: workDir, cleanupTimeout: defaultCleanupTimeout,
		lock: lock, pending: map[string]runscGlobals{}}, nil
}

// cleanWorkDir requires an absolute path without .. and at least two
// components, so "/" or "/tmp" is never used as the work dir.
func cleanWorkDir(workDir string) (string, error) {
	if !filepath.IsAbs(workDir) || hasDotDot(workDir) || strings.ContainsRune(workDir, 0) {
		return "", fmt.Errorf("sandbox: work dir %q must be absolute without ..", workDir)
	}
	c := filepath.Clean(workDir)
	if strings.Count(c, "/") < 2 {
		return "", fmt.Errorf("sandbox: work dir %q is too close to /", workDir)
	}
	return c, nil
}

// ensurePrivateDir creates p 0700 if it is missing, then checks it.
func ensurePrivateDir(p string) error {
	if _, err := os.Lstat(p); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(p, 0o700); err != nil {
			return fmt.Errorf("sandbox: create %s: %w", p, err)
		}
	}
	return checkPrivateDir(p)
}

// checkPrivateDir refuses a path that is a symlink or not a directory,
// is owned by another user, or is group or world writable: anyone who
// can write there could rewrite a bundle's config.json before runsc
// reads it. It never changes the directory.
func checkPrivateDir(p string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return fmt.Errorf("sandbox: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("sandbox: %s is a symlink", p)
	}
	if !fi.IsDir() {
		return fmt.Errorf("sandbox: %s is not a directory", p)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("sandbox: %s is not owned by this user", p)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("sandbox: %s is group or world writable (%v)", p, fi.Mode().Perm())
	}
	return nil
}

// lockWorkDir takes an exclusive, non-blocking flock on workDir/.lock.
func lockWorkDir(workDir string) (*os.File, error) {
	p := filepath.Join(workDir, lockFile)
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("sandbox: open %s: %w", p, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("sandbox: work dir %s is in use by another kritolith sandbox driver", workDir)
		}
		return nil, fmt.Errorf("sandbox: lock %s: %w", p, err)
	}
	return f, nil
}

func unlockWorkDir(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	f.Close()
}

// Close retries the deletion of containers whose delete --force failed,
// then releases the work dir lock. It returns the containers it still
// could not delete; those are left for SweepOrphans at the next start.
func (d *runscDriver) Close() error {
	err := d.retryPending()
	// runsc leaves its null-netns mount behind; without this the work
	// dir cannot be deleted.
	if uerr := unmountNullNetns(filepath.Join(d.workDir, runscStateDir)); uerr != nil {
		err = errors.Join(err, uerr)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.lock != nil {
		unlockWorkDir(d.lock)
		d.lock = nil
	}
	return err
}

func (d *runscDriver) globals(network bool) runscGlobals {
	return runscGlobals{Root: filepath.Join(d.workDir, runscStateDir), Network: network, IgnoreCgroups: d.ignoreCgroups}
}

// Run implements driver.
func (d *runscDriver) Run(ctx context.Context, s RunSpec) (out RunOutput, err error) {
	if s.Timeout <= 0 || s.Timeout > maxRunsTimeout {
		return RunOutput{}, fmt.Errorf("sandbox: timeout %v out of range", s.Timeout)
	}
	if s.OutputLimit <= 0 || s.OutputLimit > maxOutputLimit {
		return RunOutput{}, fmt.Errorf("sandbox: output limit must be in 1..%d", maxOutputLimit)
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
	// Containers an earlier run could not delete are retried first;
	// whatever still fails stays pending and is reported by Close.
	_ = d.retryPending()

	// MkdirTemp creates the dir 0700 with a random suffix; its name is
	// also the container id, which ties a container to its bundle for
	// the orphan sweep.
	bundle, err := os.MkdirTemp(d.workDir, orphanPrefix+"*")
	if err != nil {
		return RunOutput{}, fmt.Errorf("sandbox: create bundle: %w", err)
	}
	defer func() {
		if rerr := os.RemoveAll(bundle); rerr != nil {
			err = errors.Join(err, fmt.Errorf("sandbox: remove bundle: %w", rerr))
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

	var killErr error
	stop := func() {
		killGroup(cmd)
		killErr = d.killContainer(g, id)
	}
	finished := false
	// On every exit path after Start, including a panic: stop runsc if
	// it is still running and wait for it, then force-delete the
	// container. A failed cleanup is an error: the container may still be
	// running hostile code. Deferred calls run in reverse, so this runs
	// before the bundle is removed.
	defer func() {
		if !finished {
			stop()
			<-done
		}
		if cerr := d.removeContainer(g, id, killErr); cerr != nil {
			err = errors.Join(err, cerr)
		}
	}()

	timer := time.NewTimer(s.Timeout)
	defer timer.Stop()
	var waitErr, ctxErr error
	exited := false
	select {
	case waitErr = <-done:
		exited = true
	case <-timer.C:
		out.TimedOut = true
	case <-ctx.Done():
		ctxErr = ctx.Err()
	}
	if !exited {
		// A run that finished as the clock fired is not a timeout, and its
		// reaped pid must not be signalled.
		select {
		case waitErr = <-done:
			out.TimedOut, ctxErr = false, nil
		default:
			stop()
			waitErr = <-done
		}
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
	return out, runError(waitErr, ctxErr)
}

// runError turns how a run ended into the driver's error: a container
// exit status (or pipes closed late after a clean exit) is a result,
// not an error; a cancelled ctx always is, joined with any wait failure
// so errors.Is still finds context.Canceled.
func runError(waitErr, ctxErr error) error {
	var ee *exec.ExitError
	if errors.As(waitErr, &ee) || errors.Is(waitErr, exec.ErrWaitDelay) {
		waitErr = nil
	}
	switch {
	case ctxErr != nil && waitErr != nil:
		return fmt.Errorf("sandbox: run cancelled: %w", errors.Join(ctxErr, waitErr))
	case ctxErr != nil:
		return fmt.Errorf("sandbox: run cancelled: %w", ctxErr)
	case waitErr != nil:
		return fmt.Errorf("sandbox: wait for runsc: %w", waitErr)
	}
	return nil
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
// context, and returns its capped combined output. A timeout returns
// context.DeadlineExceeded.
func control(runtime, dir string, timeout time.Duration, args []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
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

// killContainer sends SIGKILL to the container.
func (d *runscDriver) killContainer(g runscGlobals, id string) error {
	if _, err := control(d.runtime, d.workDir, d.cleanupTimeout, runscArgs(g, "kill", id, "KILL")); err != nil {
		return fmt.Errorf("sandbox: runsc kill %s: %w", id, err)
	}
	return nil
}

// removeContainer force-deletes the container and decides whether
// cleanup failed. delete --force terminates a running container and
// treats a missing one as a warning, so its success means the container
// is gone. A failed kill is then only an error if it timed out (runsc
// hung, so nothing it did can be trusted); otherwise it just means the
// container had already exited. A failed delete is always an error and
// the id is kept for retry.
func (d *runscDriver) removeContainer(g runscGlobals, id string, killErr error) error {
	_, err := control(d.runtime, d.workDir, d.cleanupTimeout, runscArgs(g, "delete", "--force", id))
	if err != nil {
		d.mu.Lock()
		d.pending[id] = g
		d.mu.Unlock()
		return errors.Join(fmt.Errorf("sandbox: runsc delete --force %s: %w", id, err), killErr)
	}
	if errors.Is(killErr, context.DeadlineExceeded) {
		return killErr
	}
	return nil
}

// retryPending retries delete --force for containers an earlier run
// could not delete and returns those that still fail.
func (d *runscDriver) retryPending() error {
	d.mu.Lock()
	ids := make(map[string]runscGlobals, len(d.pending))
	for id, g := range d.pending {
		ids[id] = g
	}
	d.mu.Unlock()
	var errs []error
	for id, g := range ids {
		if _, err := control(d.runtime, d.workDir, d.cleanupTimeout, runscArgs(g, "delete", "--force", id)); err != nil {
			errs = append(errs, fmt.Errorf("sandbox: runsc delete --force %s: %w", id, err))
			continue
		}
		d.mu.Lock()
		delete(d.pending, id)
		d.mu.Unlock()
	}
	return errors.Join(errs...)
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
// symlink and touches nothing else.
//
// Call it once at startup, before creating the driver for workDir: it
// takes the work dir lock itself and refuses to run while a live driver
// (in this or another process) holds it, and it refuses a work dir that
// is a symlink, foreign-owned or group/world writable. Past that, it
// keeps going through failures and returns them joined; the caller
// should log the error, not abort. A missing workDir or a runtime that
// cannot be found means there is nothing of that kind to sweep.
func SweepOrphans(runtime, workDir string) error {
	return sweepOrphans(runtime, workDir, processStart)
}

func sweepOrphans(runtime, workDir string, before time.Time) error {
	workDir, err := cleanWorkDir(workDir)
	if err != nil {
		return fmt.Errorf("sandbox: sweep: %w", err)
	}
	if _, err := os.Lstat(workDir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := checkPrivateDir(workDir); err != nil {
		return fmt.Errorf("sandbox: sweep: %w", err)
	}
	lock, err := lockWorkDir(workDir)
	if err != nil {
		return fmt.Errorf("sandbox: sweep: %w", err)
	}
	defer unlockWorkDir(lock)

	var errs []error
	if rt, err := exec.LookPath(runtime); err == nil {
		if err := sweepContainers(rt, workDir, before); err != nil {
			errs = append(errs, err)
		}
	}
	if err := unmountNullNetns(filepath.Join(workDir, runscStateDir)); err != nil {
		errs = append(errs, err)
	}
	ents, err := os.ReadDir(workDir)
	if err != nil {
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
		if err := removeAllForce(p); err != nil {
			errs = append(errs, fmt.Errorf("sandbox: sweep: remove %s: %w", p, err))
		}
	}
	return errors.Join(errs...)
}

func isOrphanName(n string) bool {
	return strings.HasPrefix(n, orphanPrefix) && len(n) > len(orphanPrefix) && !strings.ContainsAny(n, "/\x00")
}

// sweepContainers force-deletes kritolith-* containers in the state
// root unless their bundle dir exists and is newer than before.
func sweepContainers(runtime, workDir string, before time.Time) error {
	g := runscGlobals{Root: filepath.Join(workDir, runscStateDir)}
	b, err := control(runtime, workDir, defaultCleanupTimeout, runscArgs(g, "list", "--quiet"))
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
		_, _ = control(runtime, workDir, defaultCleanupTimeout, runscArgs(g, "kill", id, "KILL"))
		if _, err := control(runtime, workDir, defaultCleanupTimeout, runscArgs(g, "delete", "--force", id)); err != nil {
			errs = append(errs, fmt.Errorf("sandbox: sweep: delete %s: %w", id, err))
		}
	}
	return errors.Join(errs...)
}
