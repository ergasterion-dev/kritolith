package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/config"
	"github.com/ergasterion-dev/kritolith/internal/ground"
	"github.com/ergasterion-dev/kritolith/internal/pipeline"
	"github.com/ergasterion-dev/kritolith/internal/sandbox"
)

// sandboxRunner is what the processor needs from the sandbox.
// *sandbox.Runner implements it.
type sandboxRunner interface {
	pipeline.SandboxRunner
	Close() error
}

// Seams for tests: the production sweep and constructor need runsc and
// Linux. Never reassigned outside tests.
var (
	sweepSandboxOrphans = sandbox.SweepOrphans
	newSandboxRunner    = func(cfg config.Sandbox, resolve sandbox.SourceResolver, workDir, dataDir string) (sandboxRunner, error) {
		r, err := sandbox.NewWithResolver(cfg, resolve, workDir, cfg.IgnoreCgroups)
		if err != nil {
			return nil, err
		}
		return r.WithForbidden(dataDir), nil
	}
)

// sandboxLogsDir is the directory under the data dir that keeps the
// capped sandbox phase logs, one subdirectory per report.
const sandboxLogsDir = "sandbox-logs"

// buildSandbox constructs the sandbox for a processor whose data dir is
// dataDir. It returns nil, nil when the sandbox is unavailable on this
// host or with this configuration (after saying so on stderr): a
// missing sandbox never stops a command. Any other failure, such as a
// work dir that overlaps the data dir, is a startup error.
func buildSandbox(cfg config.Sandbox, gs *ground.Service, dataDir string, stderr io.Writer) (sandboxRunner, error) {
	workDir, err := sandboxWorkDir(cfg, dataDir)
	if err != nil {
		return nil, err
	}
	if cfg.IgnoreCgroups {
		fmt.Fprintln(stderr, "kritolith: WARNING: sandbox.ignore_cgroups is set: memory, CPU and process limits are NOT enforced by cgroups (rlimits and the wall clock still apply); use it only in a nested dev setup, never in production")
	}
	// A missing work dir is nothing to sweep (SweepOrphans returns nil);
	// anything else is reported and the startup goes on, as the sweep's
	// contract asks. A held work dir lock stops the sweep and then the
	// constructor for the same cause, so the sweep's report waits until
	// the constructor has spoken.
	sweepErr := sweepSandboxOrphans(cfg.WithDefaults().Runtime, workDir)
	var inUse *sandbox.WorkDirInUse
	sweepLockHeld := errors.As(sweepErr, &inUse)
	if sweepErr != nil && !sweepLockHeld {
		reportSweepFailure(stderr, sweepErr)
	}
	resolve := func(repo string) (sandbox.Source, error) {
		m, err := gs.Mirror(repo)
		if err != nil {
			return nil, err
		}
		return m, nil
	}
	r, err := newSandboxRunner(cfg, resolve, workDir, dataDir)
	if errors.As(err, &inUse) {
		// One line for the one cause, whether or not the sweep hit it too.
		holder := "another Kritolith process"
		if inUse.PID > 0 {
			holder += fmt.Sprintf(" (pid %d)", inUse.PID)
		}
		fmt.Fprintf(stderr, "kritolith: sandbox unavailable: the work dir %s is in use by %s; PoCs will not be run\n", inUse.WorkDir, holder)
		return nil, nil
	}
	// The lock was free again for the constructor, or the constructor
	// failed for another reason: the skipped sweep is still worth a line.
	if sweepLockHeld {
		reportSweepFailure(stderr, sweepErr)
	}
	var u *sandbox.Unavailable
	switch {
	case errors.As(err, &u):
		fmt.Fprintf(stderr, "kritolith: sandbox unavailable: %s; PoCs will not be run\n", u.Reason)
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("sandbox: %w", err)
	}
	return r, nil
}

func reportSweepFailure(stderr io.Writer, err error) {
	fmt.Fprintf(stderr, "kritolith: sandbox: removing leftovers of an earlier run failed: %v\n", err)
}

// sandboxWorkDir returns the sandbox work dir: sandbox.work_dir, or a
// sibling of the data dir named "<dataDir>-sandbox". It refuses a work
// dir or rootfs that is, contains, or lies inside the data dir, both as
// written and with symlinks resolved: the data dir holds the database
// and the signing key, which must stay outside anything the sandbox
// could ever mount or write. It also refuses a rootfs that overlaps the
// work dir.
func sandboxWorkDir(cfg config.Sandbox, dataDir string) (string, error) {
	if !filepath.IsAbs(dataDir) {
		return "", fmt.Errorf("sandbox: data dir %q must be absolute", dataDir)
	}
	dataDir = filepath.Clean(dataDir)
	workDir := cfg.WorkDir
	if workDir == "" {
		if dataDir == "/" {
			return "", errors.New("sandbox: the data dir is /, so there is no sibling for the sandbox work dir; set sandbox.work_dir")
		}
		workDir = dataDir + "-sandbox"
	}
	if !filepath.IsAbs(workDir) {
		return "", fmt.Errorf("sandbox: work dir %q must be absolute", workDir)
	}
	workDir = filepath.Clean(workDir)
	for _, p := range []struct{ name, path string }{{"work dir", workDir}, {"rootfs", cfg.Rootfs}} {
		if p.path == "" {
			continue
		}
		if overlaps(p.path, dataDir) || overlaps(realPath(p.path), realPath(dataDir)) {
			return "", fmt.Errorf("sandbox: the sandbox %s %s must be outside the data dir %s (and must not contain it): the data dir holds the database and the signing key; set sandbox.work_dir / sandbox.rootfs elsewhere", p.name, p.path, dataDir)
		}
	}
	// The sandbox deletes what it left in its work dir, so the rootfs
	// must not be, contain or lie inside it.
	if r := cfg.Rootfs; r != "" && (overlaps(r, workDir) || overlaps(realPath(r), realPath(workDir))) {
		return "", fmt.Errorf("sandbox: the rootfs %s overlaps the work dir %s; the work dir must be a dedicated directory of its own", r, workDir)
	}
	return workDir, nil
}

// overlaps reports whether a and b are the same path or one lies
// inside the other. Both are clean absolute paths.
func overlaps(a, b string) bool { return within(a, b) || within(b, a) }

func within(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, string(filepath.Separator))+string(filepath.Separator))
}

// realPath resolves symlinks in the longest existing prefix of p (an
// absolute, clean path) and appends the rest unchanged.
func realPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	parent := filepath.Dir(p)
	if parent == p {
		return p
	}
	return filepath.Join(realPath(parent), filepath.Base(p))
}

var (
	logReportIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	logPhaseRe    = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)
)

// logPhaseName turns a phase key ("run", "control/build") into a file
// name stem ("run", "control-build"), or "" for any key that does not
// sanitise to [a-z0-9_-].
func logPhaseName(key string) string {
	n := strings.ReplaceAll(key, "/", "-")
	if !logPhaseRe.MatchString(n) {
		return ""
	}
	return n
}

// newSandboxLogSink returns a sink that writes each phase log to
// <dataDir>/sandbox-logs/<reportID>/<phase>.log: directories 0700,
// files 0600, never following a symlink and never replacing a file. The
// content is the runner's capped, hostile output; it is kept for the
// operator and never printed. Failures are logged without content and
// never stop the verdict.
//
// With retentionDays above 0 it also removes report log directories
// older than that many days (see logPruner): once now, and after a
// write when an hour has passed since the last pruning. 0 keeps every
// log. now is the clock, time.Now outside tests.
func newSandboxLogSink(dataDir string, retentionDays int, now func() time.Time) pipeline.SandboxLogSink {
	pruner := newLogPruner(dataDir, retentionDays, now)
	pruner.pruneIfDue()
	return func(reportID string, logs map[string][]byte) {
		if err := writeSandboxLogs(dataDir, reportID, logs); err != nil {
			slog.Default().Warn("sandbox logs not fully kept", "report_id", reportID, "error", err)
		}
		pruner.pruneIfDue()
	}
}

func writeSandboxLogs(dataDir, reportID string, logs map[string][]byte) error {
	if !logReportIDRe.MatchString(reportID) {
		return errors.New("sandbox logs: refusing an odd report id")
	}
	root := filepath.Join(dataDir, sandboxLogsDir)
	if err := privateDir(root); err != nil {
		return err
	}
	dir := filepath.Join(root, reportID)
	if err := privateDir(dir); err != nil {
		return err
	}
	var errs []error
	for key, content := range logs {
		name := logPhaseName(key)
		if name == "" {
			errs = append(errs, fmt.Errorf("sandbox logs: refusing an odd phase name %q", key))
			continue
		}
		if err := writeNewFile(filepath.Join(dir, name+".log"), content); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// privateDir creates p 0700, or accepts it if it already is a real
// directory (not a symlink) that only this user can write.
func privateDir(p string) error {
	if err := os.Mkdir(p, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("sandbox logs: %w", err)
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return fmt.Errorf("sandbox logs: %w", err)
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("sandbox logs: %s is not a directory", p)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("sandbox logs: %s is accessible to other users (%v)", p, fi.Mode().Perm())
	}
	return nil
}

// writeNewFile creates p 0600 and writes content; it fails if p exists
// or is a symlink.
func writeNewFile(p string, content []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("sandbox logs: %w", err)
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		return fmt.Errorf("sandbox logs: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("sandbox logs: %w", err)
	}
	return nil
}

// logPruneInterval is the shortest time between two prunings from one
// sink.
const logPruneInterval = time.Hour

// logPruner removes the sandbox log directories of reports whose logs
// are older than maxAge. It works only inside <data dir>/sandbox-logs,
// through an os.Root, so no name or symlink can take it anywhere else
// in the data dir (which holds the database and the signing key).
type logPruner struct {
	root   string // <data dir>/sandbox-logs
	maxAge time.Duration
	now    func() time.Time
	uid    uint32 // only directories owned by this user are removed

	mu   sync.Mutex
	last time.Time // when prune last ran; zero before the first run
}

// newLogPruner returns a pruner for the logs under dataDir, or nil when
// retentionDays is not above 0: no bound, nothing is ever removed.
func newLogPruner(dataDir string, retentionDays int, now func() time.Time) *logPruner {
	if retentionDays <= 0 {
		return nil
	}
	return &logPruner{
		root:   filepath.Join(dataDir, sandboxLogsDir),
		maxAge: time.Duration(retentionDays) * 24 * time.Hour,
		now:    now,
		uid:    uint32(os.Geteuid()),
	}
}

// pruneIfDue prunes on its first call and then when logPruneInterval
// has passed since the last pruning. A nil pruner does nothing.
func (p *logPruner) pruneIfDue() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if !p.last.IsZero() && now.Sub(p.last) < logPruneInterval {
		return
	}
	p.last = now
	p.prune()
}

// prune removes every report log directory whose newest modification
// time is more than maxAge ago. A candidate is an entry directly under
// sandbox-logs whose name is a report id and that is a real directory
// (not a symlink) owned by uid; every other entry is left as it is.
// Failures are logged, without any log content, and pruning goes on
// with the next directory.
func (p *logPruner) prune() {
	cutoff := p.now().Add(-p.maxAge)
	lfi, err := os.Lstat(p.root)
	if errors.Is(err, os.ErrNotExist) {
		return // no logs kept yet
	}
	if err != nil {
		slog.Default().Warn("sandbox logs: pruning skipped", "error", err)
		return
	}
	if !lfi.IsDir() || !ownedBy(lfi, p.uid) {
		slog.Default().Warn("sandbox logs: pruning skipped: the logs directory is not a directory owned by this user")
		return
	}
	root, err := os.OpenRoot(p.root)
	if err != nil {
		slog.Default().Warn("sandbox logs: pruning skipped", "error", err)
		return
	}
	defer root.Close()
	// OpenRoot follows a symlink in its last element: make sure it
	// opened the directory that Lstat saw.
	names, err := readRootDir(root, lfi)
	if err != nil {
		slog.Default().Warn("sandbox logs: pruning skipped", "error", err)
		return
	}
	for _, name := range names {
		if !logReportIDRe.MatchString(name) {
			continue
		}
		if err := p.pruneReport(root, name, cutoff); err != nil {
			slog.Default().Warn("sandbox logs: report logs not pruned", "report_id", name, "error", err)
		}
	}
}

// pruneReport removes the directory name under root, with the files in
// it, if nothing in it was modified after cutoff. It returns nil for an
// entry that is not a candidate or is still fresh. A directory that
// holds anything but regular files is left whole, with an error.
func (p *logPruner) pruneReport(root *os.Root, name string, cutoff time.Time) error {
	lfi, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if !lfi.IsDir() || !ownedBy(lfi, p.uid) {
		return nil // a symlink, a file, or someone else's: not ours to remove
	}
	dir, err := root.OpenRoot(name)
	if err != nil {
		return err
	}
	defer dir.Close()
	files, err := readRootDir(dir, lfi)
	if err != nil {
		return err
	}
	newest := lfi.ModTime()
	for _, f := range files {
		fi, err := dir.Lstat(f)
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() {
			return errors.New("skipped: the directory holds something that is not a regular file")
		}
		if fi.ModTime().After(newest) {
			newest = fi.ModTime()
		}
	}
	if !newest.Before(cutoff) {
		return nil
	}
	// Root.Remove never follows a symlink and never leaves the root. It
	// removes a file or an empty directory, so anything that appeared
	// since the listing makes the last Remove fail and stays.
	var errs []error
	for _, f := range files {
		if err := dir.Remove(f); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return root.Remove(name)
}

// readRootDir returns the names directly inside the directory r was
// opened on, after checking that it is the directory want describes (an
// Lstat result): the name could have been swapped for a symlink or
// another directory between the Lstat and the open.
func readRootDir(r *os.Root, want os.FileInfo) ([]string, error) {
	d, err := r.Open(".")
	if err != nil {
		return nil, err
	}
	defer d.Close()
	fi, err := d.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(want, fi) {
		return nil, errors.New("sandbox logs: the directory changed while it was being opened")
	}
	return d.Readdirnames(-1)
}

// ownedBy reports whether fi's file belongs to uid.
func ownedBy(fi os.FileInfo, uid uint32) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uid
}
