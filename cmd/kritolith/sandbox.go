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
	"syscall"

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
	// contract asks.
	if err := sweepSandboxOrphans(cfg.WithDefaults().Runtime, workDir); err != nil {
		fmt.Fprintf(stderr, "kritolith: sandbox: removing leftovers of an earlier run failed: %v\n", err)
	}
	resolve := func(repo string) (sandbox.Source, error) {
		m, err := gs.Mirror(repo)
		if err != nil {
			return nil, err
		}
		return m, nil
	}
	r, err := newSandboxRunner(cfg, resolve, workDir, dataDir)
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
func newSandboxLogSink(dataDir string) pipeline.SandboxLogSink {
	return func(reportID string, logs map[string][]byte) {
		if err := writeSandboxLogs(dataDir, reportID, logs); err != nil {
			slog.Default().Warn("sandbox logs not fully kept", "report_id", reportID, "error", err)
		}
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
