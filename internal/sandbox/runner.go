package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/ergasterion-dev/kritolith/internal/config"
	"github.com/ergasterion-dev/kritolith/internal/report"
)

// Control states (ReproResult.ControlState).
const (
	ControlFixed           = "fixed"
	ControlStillReproduces = "still_reproduces"
	ControlUnavailable     = "unavailable"
)

// weakAtHeadNote is the spec's wording for an assertion-only failure
// that also fails at HEAD.
const weakAtHeadNote = "the PoC also fails at HEAD, and an assertion-only failure cannot be told from a test that always fails"

// Request is one sandbox run: the report (its PoC), the ref grounding
// resolved, and the grounded claims.
type Request struct {
	Report      report.Report
	ResolvedRef string
	ViaFallback bool
	Claims      []report.Claim
	// Module is grounding's module path for the repository root. The
	// Runner reads the module path from the go.mod of the PoC's own
	// module root at the ref instead, so this is informational.
	Module     string
	PoCDirHint string
}

// Result is what the sandbox found. At most one of Skipped, NeedsInfo
// and Inconclusive is set; with none of them set, Repro says whether
// the PoC reproduced (Repro.Reproduced) or ran clean (Passed).
type Result struct {
	// Repro is the evidence, set once the PoC was tried at the ref.
	Repro *report.ReproResult
	// Skipped is why the stage did not run at all.
	Skipped string
	// NeedsInfo is set when the PoC is invalid or cannot be placed.
	NeedsInfo string
	// Inconclusive is why the run says nothing either way.
	Inconclusive string
	// Passed: the run at the ref exited 0 with tests completed.
	Passed bool
	// Weak: the reproduction is signal 3 (assertion-only failure).
	Weak bool
	// ViaFallback: the ref came from a fallback version, so a clean
	// run must not be read as NOT_REPRODUCED.
	ViaFallback bool
	// Logs are the capped phase outputs, keyed by phase, and by
	// "control/<phase>" for the control. They are hostile text for the
	// local store, never for the emailed bundle.
	Logs map[string][]byte
}

// Unavailable says why the sandbox cannot run on this host or with
// this configuration. It is never a judgement on a report. Err, when
// set, is the cause behind Reason (a *WorkDirInUse for a held work dir
// lock), for errors.As.
type Unavailable struct {
	Reason string
	Err    error
}

func (e *Unavailable) Error() string { return "sandbox unavailable: " + e.Reason }

func (e *Unavailable) Unwrap() error { return e.Err }

// hostOS is runtime.GOOS; tests replace it.
var hostOS = runtime.GOOS

// Available checks that the sandbox can run: a rootfs is configured
// and readable, the host is Linux, and the runtime is on PATH. Every
// failure is an *Unavailable.
func Available(cfg config.Sandbox) error {
	if !cfg.Enabled() {
		return &Unavailable{Reason: "no sandbox rootfs is configured"}
	}
	if hostOS != "linux" {
		return &Unavailable{Reason: "gVisor needs a Linux host; this host runs " + hostOS}
	}
	cfg = cfg.WithDefaults()
	if err := cfg.Validate(); err != nil {
		return &Unavailable{Reason: err.Error()}
	}
	if err := checkProxy(cfg.GoProxy); err != nil {
		return &Unavailable{Reason: "sandbox.goproxy: " + err.Error()}
	}
	fi, err := os.Stat(cfg.Rootfs)
	if err != nil || !fi.IsDir() {
		return &Unavailable{Reason: fmt.Sprintf("the sandbox rootfs %q is not a directory", cfg.Rootfs)}
	}
	if _, err := os.ReadDir(cfg.Rootfs); err != nil {
		return &Unavailable{Reason: fmt.Sprintf("the sandbox rootfs %q is not readable", cfg.Rootfs)}
	}
	if _, err := exec.LookPath(cfg.Runtime); err != nil {
		return &Unavailable{Reason: fmt.Sprintf("the sandbox runtime %q was not found", cfg.Runtime)}
	}
	return nil
}

// Runner runs PoCs in the sandbox. It is safe for concurrent use as far
// as its driver is.
type Runner struct {
	cfg config.Sandbox
	src Source
	// resolve, when set, picks the source per report repository and
	// takes precedence over src.
	resolve SourceResolver
	// forbidden are host paths (the data directory, key files) that no
	// container may mount; every ContainerSpec carries a copy.
	forbidden   []string
	d           driver
	scratchRoot string
	// uid/gid of the container user; chown when the host runs as root
	// and scratch dirs must be handed to that user.
	uid, gid      int
	chown         bool
	ignoreCgroups bool
	closer        func() error
	// bridge builds the fetch phase's network bridge; nil means the
	// fetch phase has no network and ends INCONCLUSIVE.
	bridge bridgeProvider
	// outFS mounts the run phase's size-capped /out; nil means the run
	// phase cannot start and ends INCONCLUSIVE.
	outFS outMounter

	raceOnce  sync.Once
	race      bool
	closeOnce sync.Once

	// mu guards closed; inflight counts Runs that Close waits for, so
	// the driver (its work dir lock, its runsc state) outlives every
	// Run's cleanup.
	mu       sync.Mutex
	closed   bool
	inflight sync.WaitGroup
}

// SourceResolver returns the Source for a report's repository
// (owner/name). Production resolves the repository's git mirror.
type SourceResolver func(repo string) (Source, error)

// NewRunner builds a Runner around a driver. scratchRoot holds the
// per-run scratch directories; it must be absolute, and must neither be
// nor contain the data directory (the caller asserts that).
func NewRunner(cfg config.Sandbox, src Source, d driver, scratchRoot string) *Runner {
	uid, gid := os.Geteuid(), os.Getegid()
	chown := false
	if uid <= 0 {
		uid, gid, chown = 65534, 65534, true
	}
	if gid <= 0 {
		gid = 65534
	}
	return &Runner{cfg: cfg.WithDefaults(), src: src, d: d, scratchRoot: scratchRoot, uid: uid, gid: gid, chown: chown}
}

// New builds the production Runner around one Source: it checks
// Available, then creates a runsc driver whose work dir (also the
// scratch root) is workDir. Every failure is an *Unavailable. It does
// not sweep orphans: call SweepOrphans(cfg.Runtime, workDir) at startup
// before New, since the driver New creates holds the work dir lock.
// Close the Runner when done.
func New(cfg config.Sandbox, src Source, workDir string, ignoreCgroups bool) (*Runner, error) {
	if err := Available(cfg); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, &Unavailable{Reason: "no source repository mirror"}
	}
	return newProduction(cfg, src, nil, workDir, ignoreCgroups)
}

// NewWithResolver is New for a Runner that serves many repositories:
// resolve picks the Source for each request's Report.Repo.
func NewWithResolver(cfg config.Sandbox, resolve SourceResolver, workDir string, ignoreCgroups bool) (*Runner, error) {
	if err := Available(cfg); err != nil {
		return nil, err
	}
	if resolve == nil {
		return nil, &Unavailable{Reason: "no source repository resolver"}
	}
	return newProduction(cfg, nil, resolve, workDir, ignoreCgroups)
}

func newProduction(cfg config.Sandbox, src Source, resolve SourceResolver, workDir string, ignoreCgroups bool) (*Runner, error) {
	cfg = cfg.WithDefaults()
	if err := checkWorkDirOverlap(workDir, cfg.Rootfs, nil); err != nil {
		return nil, &Unavailable{Reason: err.Error()}
	}
	d, err := newRunscDriver(cfg.Runtime, workDir)
	if err != nil {
		return nil, &Unavailable{Reason: err.Error(), Err: err}
	}
	d.ignoreCgroups = ignoreCgroups
	r := NewRunner(cfg, src, d, d.workDir)
	r.resolve = resolve
	r.ignoreCgroups = ignoreCgroups
	r.closer = d.Close
	r.bridge = newHostBridges(d.workDir)
	r.outFS = newHostOutFS()
	return r, nil
}

// WithForbidden adds host paths (the data directory, key files) that no
// container this Runner builds may mount: each goes into every
// ContainerSpec's Forbidden list, which BuildOCI enforces. Absolute
// paths are cleaned; anything else is kept as given so BuildOCI refuses
// the run rather than silently dropping the protection. Call it before
// the Runner is shared.
func (r *Runner) WithForbidden(paths ...string) *Runner {
	for _, p := range paths {
		if filepath.IsAbs(p) {
			p = filepath.Clean(p)
		}
		r.forbidden = append(r.forbidden, p)
	}
	return r
}

// Close refuses new Runs, waits for those in flight (with their
// cleanup), then releases the driver (its work dir lock and any
// containers it could not delete). It is idempotent.
func (r *Runner) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	r.inflight.Wait()
	if r.closer == nil {
		return nil
	}
	var err error
	r.closeOnce.Do(func() { err = r.closer() })
	return err
}

// enter registers a Run with Close; it is false once Close was called.
func (r *Runner) enter() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	r.inflight.Add(1)
	return true
}

// Run runs req's PoC at the resolved ref and, after a reproduction, at
// the remote's default-branch HEAD as a control. It never returns an
// error and never panics: every failure is a Result reason.
func (r *Runner) Run(ctx context.Context, req Request) (res Result) {
	defer func() {
		if p := recover(); p != nil {
			res = Result{Inconclusive: "the sandbox stage failed internally; the run says nothing about the report"}
		}
	}()
	if r == nil || !r.cfg.Enabled() {
		return Result{Skipped: "the sandbox is not configured"}
	}
	if !r.enter() {
		return Result{Skipped: "the sandbox is closed (shutting down)"}
	}
	defer r.inflight.Done()
	switch {
	case r.d == nil || (r.src == nil && r.resolve == nil):
		return Result{Skipped: "the sandbox is unavailable"}
	case req.ResolvedRef == "":
		return Result{Skipped: "no ref resolved, so there is nothing to run the PoC against"}
	case !filepath.IsAbs(r.scratchRoot) || filepath.Clean(r.scratchRoot) == "/",
		checkWorkDirOverlap(r.scratchRoot, r.cfg.Rootfs, r.forbidden) != nil:
		return Result{Skipped: "the sandbox scratch directory is misconfigured"}
	case checkProxy(r.cfg.GoProxy) != nil:
		return Result{Skipped: "the sandbox goproxy is not a single allowed proxy URL"}
	}
	p, err := ValidatePoC(req.Report.PoC)
	if err != nil {
		return Result{NeedsInfo: inconclusiveOrNeeds(err)}
	}
	src := r.src
	if r.resolve != nil {
		if src, err = r.resolve(req.Report.Repo); err != nil || src == nil {
			return Result{Skipped: "the repository's source mirror could not be opened"}
		}
	}

	a := r.attemptAt(ctx, src, req.ResolvedRef, p, req.PoCDirHint, req.Claims)
	res.Logs = map[string][]byte{}
	for k, v := range a.logs {
		res.Logs[k] = v
	}
	if a.needsInfo != "" {
		return Result{NeedsInfo: a.needsInfo, Logs: res.Logs}
	}
	res.Repro = a.repro()
	defer r.commonNotes(&res, req)
	switch {
	case a.inconc != "":
		res.Inconclusive = a.inconc
		return res
	case a.passed:
		res.Passed = true
		return res
	case !a.reproduced():
		res.Inconclusive = "the run ended without a result"
		return res
	}
	res.Weak = a.signal.Weak
	r.control(ctx, src, req, p, a, &res)
	return res
}

func inconclusiveOrNeeds(err error) string {
	var ni *NeedsInfo
	if errors.As(err, &ni) {
		return ni.Reason
	}
	return report.Printable(err.Error())
}

// commonNotes adds the notes every result with a Repro carries.
func (r *Runner) commonNotes(res *Result, req Request) {
	if res.Repro == nil {
		return
	}
	if req.ViaFallback {
		res.ViaFallback = true
		res.Repro.Notes = append(res.Repro.Notes, "the ref was resolved through a fallback version, not the exact claimed commit")
	}
	if r.ignoreCgroups {
		res.Repro.Notes = append(res.Repro.Notes, "cgroup limits (memory, CPU, processes) were not in force: the runtime ran with --ignore-cgroups; rlimits and the wall clock still applied")
	}
}

// control runs the PoC at the default-branch HEAD after a reproduction
// at the ref and folds the result into res.
func (r *Runner) control(ctx context.Context, src Source, req Request, p PoC, a *attempt, res *Result) {
	rr := res.Repro
	rr.Phase = PhaseControl
	head, err := src.DefaultBranchRef(ctx)
	switch {
	case err != nil:
		rr.ControlState = ControlUnavailable
		rr.Notes = append(rr.Notes, "the control could not run: the default branch head could not be resolved")
	case head == req.ResolvedRef:
		// The claimed commit is HEAD: the control is the run itself.
		c := *a.repro()
		c.Notes = append(c.Notes, "the claimed commit is the default branch head")
		rr.Control = &c
		rr.ControlState = ControlStillReproduces
	default:
		c := r.attemptAt(ctx, src, head, p, a.dir, req.Claims)
		for k, v := range c.logs {
			res.Logs[PhaseControl+"/"+k] = v
		}
		cr := c.repro()
		if c.needsInfo != "" {
			cr.Notes = append(cr.Notes, c.needsInfo)
		}
		rr.Control = cr
		switch {
		case c.reproduced():
			rr.ControlState = ControlStillReproduces
		case c.passed:
			rr.ControlState = ControlFixed
		default:
			rr.ControlState = ControlUnavailable
		}
	}

	switch {
	case res.Weak && rr.ControlState == ControlStillReproduces:
		rr.Reproduced = false
		res.Inconclusive = weakAtHeadNote
		rr.Notes = append(rr.Notes, weakAtHeadNote)
	case res.Weak && rr.ControlState == ControlUnavailable:
		rr.Reproduced = false
		res.Inconclusive = "an assertion-only failure counts only when the same PoC passes at HEAD, and the PoC could not be re-run at HEAD"
		rr.Notes = append(rr.Notes, res.Inconclusive)
	case rr.ControlState == ControlUnavailable:
		rr.Notes = append(rr.Notes, "could not be re-run at HEAD; whether it is fixed is unknown")
	}
}
