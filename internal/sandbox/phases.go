package sandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// Phases of one attempt, as recorded in ReproResult.Phase and as keys
// of ReproResult.LogSHA256.
const (
	PhaseFetch   = "fetch"
	PhaseBuild   = "build"
	PhaseRun     = "run"
	PhaseControl = "control"
)

// In-container layout. The source tree is at the same path in every
// phase so file names in stack traces match the build.
//
// TODO(task10): verify against a real runsc with the documented rootfs:
//   - mount points that do not exist in the read-only rootfs (/src,
//     /work/..., /out, /poc) are created by runsc (its default rootfs
//     overlay), or the rootfs recipe must create them;
//   - args[0] "go" is resolved through the container's PATH (ctrPath);
//   - the container user (the host's uid, or 65534 when the host runs
//     as root and the scratch tree is chowned) can read the rootfs and
//     use the scratch mounts through the gofer.
const (
	ctrSrc      = "/src"
	ctrModCache = "/work/modcache"
	ctrGoCache  = "/work/gocache"
	ctrOut      = "/out" // build: binary output; run: coverage profile
	ctrBin      = "/poc" // run: the build output, read-only
	ctrTmp      = "/tmp"
	// ctrPath is the only PATH a container sees: a fixed value, never
	// the host's. The go tool needs it to find a C compiler for -race.
	ctrPath = "/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

	testBinary = "poc.test"
	progBinary = "poc"
	coverFile  = "cover.out"
)

// Per-phase file size rlimits (KiB): module zips and test binaries
// (with -race and -cover) are large; the run phase writes only a
// coverage profile and whatever the PoC writes to /tmp.
const (
	fetchFileSizeKB = 1 << 20
	buildFileSizeKB = 2 << 20
	runFileSizeKB   = 256 << 10
)

// newerGoText is what the go tool prints when go.mod needs a newer Go
// than the toolchain it runs (with GOTOOLCHAIN=local it cannot switch).
const newerGoText = "requires go >= "

// reasonNoRace is the Inconclusive reason for a clean run of a PoC
// built without -race (no C compiler in the rootfs).
const reasonNoRace = "the PoC ran clean, but it was built without -race (the sandbox rootfs has no C compiler), so a clean run cannot rule out a data race; install a C compiler in the rootfs"

const reasonNewerGo = "the repository needs a newer Go than the sandbox rootfs provides (go.mod requires go >= a version the rootfs does not have)"

// attempt is the result of running the PoC at one ref.
type attempt struct {
	ref       string
	shape     Shape
	dir       string // placement directory, tree-relative
	phase     string // phase that ended the attempt; "" before any container
	sums      map[string]string
	logs      map[string][]byte
	signal    Signal
	notes     []string
	passed    bool   // the run exited 0 and tests ran
	inconc    string // why the attempt says nothing
	needsInfo string // the PoC or its placement needs the reporter
}

func (a *attempt) reproduced() bool {
	return a.inconc == "" && a.needsInfo == "" && a.signal.Kind != "" && a.signal.Kind != KindNone
}

// signalText renders the signal for ReproResult.Signal.
func (a *attempt) signalText() string {
	switch {
	case a.signal.Kind == "":
		return ""
	case a.signal.Kind == KindNone:
		return KindNone + " (" + a.signal.Reason + "): " + a.signal.Detail
	}
	return a.signal.Kind + ": " + a.signal.Detail
}

func (a *attempt) repro() *report.ReproResult {
	rr := &report.ReproResult{
		Ref:        a.ref,
		Reproduced: a.reproduced(),
		Signal:     a.signalText(),
		Phase:      a.phase,
		Shape:      string(a.shape),
		Notes:      append([]string(nil), a.notes...),
	}
	if len(a.sums) > 0 {
		rr.LogSHA256 = map[string]string{}
		for k, v := range a.sums {
			rr.LogSHA256[k] = v
		}
	}
	if a.inconc != "" {
		rr.Notes = append(rr.Notes, a.inconc)
	}
	return rr
}

func (a *attempt) fail(reason string) *attempt {
	a.inconc = reason
	return a
}

func (a *attempt) record(phase string, out []byte) {
	a.phase = phase
	sum := sha256.Sum256(out)
	a.sums[phase] = hex.EncodeToString(sum[:])
	a.logs[phase] = out
}

// layout is the host side of one attempt's scratch directory.
type layout struct {
	root, src, build, modcache, gocache, tmp, out, runout string
}

func newLayout(root string) (layout, error) {
	l := layout{root: root}
	for _, d := range []struct {
		p    *string
		name string
	}{{&l.modcache, "modcache"}, {&l.gocache, "gocache"}, {&l.tmp, "tmp"}, {&l.out, "out"}, {&l.runout, "runout"}} {
		*d.p = filepath.Join(root, d.name)
		if err := os.Mkdir(*d.p, 0o700); err != nil {
			return layout{}, err
		}
	}
	l.src = filepath.Join(root, "src")
	l.build = filepath.Join(root, "build")
	return l, nil
}

func goEnv(proxy, goflags, gocache string) []string {
	return []string{
		"GOPROXY=" + proxy,
		"GOFLAGS=" + goflags,
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		"GOENV=off",
		"GOPATH=" + ctrTmp + "/gopath",
		"GOMODCACHE=" + ctrModCache,
		"GOCACHE=" + gocache,
		"HOME=" + ctrTmp,
		"TMPDIR=" + ctrTmp,
		"PATH=" + ctrPath,
	}
}

// fetchEnv is built from scratch: the configured proxy only (no
// "direct", no list), the checksum database left at its default.
// -modcacherw keeps the module cache's directories writable so the
// scratch tree can be removed; it stays a read-only mount in build
// and run.
func fetchEnv(proxy string) []string { return goEnv(proxy, "-mod=mod -modcacherw", ctrTmp+"/gocache") }

func buildEnv(race bool) []string {
	env := goEnv("off", "-mod=mod", ctrGoCache)
	if race {
		env = append(env, "CGO_ENABLED=1")
	}
	return env
}

func runEnv() []string {
	return []string{"HOME=" + ctrTmp, "TMPDIR=" + ctrTmp, "PATH=" + ctrPath}
}

// tmpfsMB sizes the in-memory /tmp of the fetch and run phases.
func (r *Runner) tmpfsMB() int {
	mb := r.cfg.MemoryMB / 4
	switch {
	case mb < 64:
		return 64
	case mb > 512:
		return 512
	}
	return mb
}

// runSpec builds one container's spec. netns is the fetch bridge's
// container namespace; only a spec with one gets network access.
func (r *Runner) runSpec(args, env []string, cwd string, mounts []Mount, netns string, timeoutSec, fileSizeKB int) RunSpec {
	cpuSec := timeoutSec*r.cfg.CPUs + 10
	if cpuSec > maxCPUSeconds {
		cpuSec = maxCPUSeconds
	}
	return RunSpec{
		Container: ContainerSpec{
			Rootfs: r.cfg.Rootfs, Args: args, Env: env, Cwd: cwd, Mounts: mounts, Network: netns != "", NetnsPath: netns,
			MemoryMB: r.cfg.MemoryMB, CPUs: r.cfg.CPUs, PIDs: r.cfg.PIDs,
			CPUSeconds: cpuSec, FileSizeKB: fileSizeKB, UID: r.uid, GID: r.gid,
			Forbidden: append([]string(nil), r.forbidden...),
		},
		Timeout:     time.Duration(timeoutSec) * time.Second,
		OutputLimit: r.cfg.OutputLimitKB * 1024,
	}
}

func ctrDir(rel string) string { return path.Join(ctrSrc, rel) }

// fetchSpec: `go mod download` in the module root, source and module
// cache writable, no PoC anywhere in the container. The container joins
// the fetch bridge's namespace and uses its forwarder as GOPROXY: the
// configured proxy is reached only through it.
func (r *Runner) fetchSpec(l layout, modRoot string, b fetchBridge) RunSpec {
	mounts := []Mount{
		{Source: l.src, Dest: ctrSrc, Writable: true},
		{Source: l.modcache, Dest: ctrModCache, Writable: true},
		{Dest: ctrTmp, Tmpfs: true, Writable: true, SizeMB: r.tmpfsMB()},
	}
	return r.runSpec([]string{"go", "mod", "download"}, fetchEnv(b.ProxyURL()), ctrDir(modRoot), mounts,
		b.NetnsPath(), r.cfg.FetchTimeoutSeconds, fetchFileSizeKB)
}

// buildArgs is the build command run in the module root.
func buildArgs(p PoC, module, modRoot, dir string, race bool, coverPkgs []string) []string {
	if p.Shape == ShapeProgram {
		args := []string{"go", "build", "-o", path.Join(ctrOut, progBinary)}
		if race {
			args = append(args, "-race")
		}
		return append(args, "./"+pocProgramDir)
	}
	args := []string{"go", "test", "-c", "-o", path.Join(ctrOut, testBinary), "-vet=off"}
	if race {
		args = append(args, "-race")
	}
	if len(coverPkgs) > 0 {
		pkgs := make([]string, len(coverPkgs))
		for i, d := range coverPkgs {
			pkgs[i] = module
			if d != "." {
				pkgs[i] = module + "/" + d
			}
		}
		args = append(args, "-cover", "-coverpkg="+strings.Join(pkgs, ","))
	}
	rel, _ := relTo(modRoot, dir)
	pkg := "."
	if rel != "." {
		pkg = "./" + rel
	}
	return append(args, pkg)
}

// buildSpec: no network, the PoC in a writable copy of the tree, the
// module cache read-only, writable build cache, tmp and output.
func (r *Runner) buildSpec(l layout, args []string, modRoot string, race bool) RunSpec {
	mounts := []Mount{
		{Source: l.build, Dest: ctrSrc, Writable: true},
		{Source: l.modcache, Dest: ctrModCache},
		{Source: l.gocache, Dest: ctrGoCache, Writable: true},
		{Source: l.tmp, Dest: ctrTmp, Writable: true},
		{Source: l.out, Dest: ctrOut, Writable: true},
	}
	return r.runSpec(args, buildEnv(race), ctrDir(modRoot), mounts, "", r.cfg.BuildTimeoutSeconds, buildFileSizeKB)
}

// runArgs is the command line of the built PoC. Every name that ends
// up in -test.run goes through regexp.QuoteMeta and is anchored.
func runArgs(p PoC, runTimeout time.Duration, cover bool) []string {
	if p.Shape == ShapeProgram {
		return []string{path.Join(ctrBin, progBinary)}
	}
	var pattern string
	if p.Shape == ShapeFuzz {
		seeds := make([]string, 0, len(p.Files))
		for _, f := range p.Files {
			_, seed, _ := fuzzParts(f.Name)
			seeds = append(seeds, regexp.QuoteMeta(seed))
		}
		seed := seeds[0]
		if len(seeds) > 1 {
			seed = "(?:" + strings.Join(seeds, "|") + ")"
		}
		pattern = "^" + regexp.QuoteMeta(p.FuzzName) + "$/^" + seed + "$"
	} else {
		names := make([]string, len(p.TestNames))
		for i, n := range p.TestNames {
			names[i] = regexp.QuoteMeta(n)
		}
		pattern = "^" + names[0] + "$"
		if len(names) > 1 {
			pattern = "^(?:" + strings.Join(names, "|") + ")$"
		}
	}
	// Go's own timeout fires before the host's wall clock so a hang
	// still prints the goroutine dump.
	limit := runTimeout * 9 / 10
	if limit < time.Second {
		limit = time.Second
	}
	args := []string{path.Join(ctrBin, testBinary), "-test.run=" + pattern, "-test.v", "-test.count=1", "-test.timeout=" + limit.String()}
	if cover {
		args = append(args, "-test.coverprofile="+path.Join(ctrOut, coverFile))
	}
	return args
}

// runSpec: no network, the tree (with the PoC) and the binary
// read-only, a writable output dir for the coverage profile and a
// size-capped tmpfs /tmp. Working directory is the package directory.
func (r *Runner) runPhaseSpec(l layout, args []string, dir string) RunSpec {
	mounts := []Mount{
		{Source: l.build, Dest: ctrSrc},
		{Source: l.modcache, Dest: ctrModCache},
		{Source: l.out, Dest: ctrBin},
		{Source: l.runout, Dest: ctrOut, Writable: true},
		{Dest: ctrTmp, Tmpfs: true, Writable: true, SizeMB: r.tmpfsMB()},
	}
	return r.runSpec(args, runEnv(), ctrDir(dir), mounts, "", r.cfg.RunTimeoutSeconds, runFileSizeKB)
}

// raceAvailable reports, once per Runner, whether the rootfs has a C
// compiler, which -race needs (through cgo). It only reads the rootfs
// directory listing; links that leave the rootfs are not followed.
func (r *Runner) raceAvailable() bool {
	r.raceOnce.Do(func() {
		t := DirTree(r.cfg.Rootfs)
		for _, d := range []string{"usr/bin", "usr/local/bin", "bin"} {
			names, err := t.ReadDir(d)
			if err != nil {
				continue
			}
			for _, n := range names {
				if n == "gcc" || n == "cc" || n == "clang" {
					r.race = true
					return
				}
			}
		}
	})
	return r.race
}

// phaseFailure is the Inconclusive reason for a fetch or build that
// did not finish cleanly.
func phaseFailure(ctx context.Context, phase string, out RunOutput, err error) string {
	switch {
	case ctx.Err() != nil:
		return fmt.Sprintf("the %s phase was cancelled", phase)
	case err != nil:
		return fmt.Sprintf("the %s phase could not run: %s", phase, report.Printable(err.Error()))
	case out.TimedOut:
		return fmt.Sprintf("the %s phase hit its time limit", phase)
	case out.OOM:
		return fmt.Sprintf("the %s phase hit its memory limit", phase)
	case bytes.Contains(out.Output, []byte(newerGoText)):
		return reasonNewerGo
	case phase == PhaseFetch:
		return "go mod download failed (exit " + strconv.Itoa(out.ExitCode) + ")"
	}
	return "the PoC does not build at this ref (exit " + strconv.Itoa(out.ExitCode) + ")"
}

// attemptAt runs the PoC at one ref: prepare (archive, place, check
// go.mod, compute targets), fetch, build and run, each in a fresh
// container. hint is the placement hint; control attempts pass the
// directory the ref attempt used. The scratch directory is removed on
// every return path, including a panic.
func (r *Runner) attemptAt(ctx context.Context, src Source, ref string, p PoC, hint string, claims []report.Claim) *attempt {
	a := &attempt{ref: ref, shape: p.Shape, sums: map[string]string{}, logs: map[string][]byte{}}
	work, err := os.MkdirTemp(r.scratchRoot, orphanPrefix+"run-*")
	if err != nil {
		return a.fail("could not create a scratch directory: " + report.Printable(err.Error()))
	}
	defer func() {
		if err := removeScratch(work); err != nil {
			slog.Warn("sandbox: scratch directory not fully removed; the next start sweeps it", "dir", work, "error", errnoText(err))
			a.notes = append(a.notes, "the scratch directory could not be fully removed; it is swept at the next start")
		}
	}()
	l, err := newLayout(work)
	if err != nil {
		return a.fail("could not lay out the scratch directory: " + report.Printable(err.Error()))
	}

	// Prepare (host).
	if err := src.Archive(ctx, ref, l.src); err != nil {
		return a.fail("could not extract the source at the ref: " + report.Printable(err.Error()))
	}
	tree := DirTree(l.src)
	dir, err := PlacePoC(p, tree, hint, claims)
	if err != nil {
		var ni *NeedsInfo
		if errors.As(err, &ni) {
			a.needsInfo = ni.Reason
			return a
		}
		return a.fail(report.Printable(err.Error()))
	}
	a.dir = dir
	modRoot, err := ModuleRoot(tree, dir)
	if err != nil {
		return a.fail(inconclusiveReason(err))
	}
	gomod, err := tree.ReadFile(path.Join(modRoot, "go.mod"))
	if err != nil {
		return a.fail("go.mod at the module root is not readable")
	}
	if err := CheckGoMod(gomod); err != nil {
		return a.fail(inconclusiveReason(err))
	}
	module := goModModule(gomod)
	if module == "" {
		return a.fail("go.mod declares no usable module path")
	}
	if p.Shape == ShapeFuzz && !hasFuzzTarget(tree, dir, p.FuzzName) {
		a.needsInfo = fmt.Sprintf("the package directory %s has no fuzz target %s for the PoC's seeds", quote(dir), quote(p.FuzzName))
		return a
	}
	kept, ranges := claimRanges(tree, modRoot, moduleClaims(tree, modRoot, claims))
	targets := TargetsFromClaims(kept, module)
	targets.FuncRanges = ranges
	_, targets.PoCFiles = pocPaths(p, modRoot, dir)
	if len(targets.Funcs) == 0 && len(targets.Files) == 0 {
		a.notes = append(a.notes, "no verified claim names code in this module, so no run can reproduce")
	}

	// Fetch (network on, no PoC).
	if err := r.ownScratch(work); err != nil {
		return a.fail("could not hand the scratch directory to the sandbox user")
	}
	out, why, err := r.fetch(ctx, a, l, modRoot)
	if why != "" {
		return a.fail(why)
	}
	a.record(PhaseFetch, out.Output)
	if err != nil || out.TimedOut || out.OOM || out.ExitCode != 0 {
		return a.fail(phaseFailure(ctx, PhaseFetch, out, err))
	}

	// Build (no network): the PoC goes into a copy of the tree.
	if err := copyTree(l.src, l.build); err != nil {
		return a.fail("could not copy the source tree for the build: " + report.Printable(err.Error()))
	}
	if err := writePoC(l.build, p, modRoot, dir); err != nil {
		var ni *NeedsInfo
		if errors.As(err, &ni) {
			a.needsInfo = ni.Reason
			return a
		}
		return a.fail("could not place the PoC: " + inconclusiveReason(err))
	}
	race := r.raceAvailable()
	if !race {
		a.notes = append(a.notes, "race detector unavailable: the sandbox rootfs has no C compiler, so the PoC was built without -race")
	}
	cover := p.Shape != ShapeProgram && len(targets.PkgDirs) > 0
	var coverPkgs []string
	if cover {
		coverPkgs = targets.PkgDirs
	}
	if err := r.ownScratch(work); err != nil {
		return a.fail("could not hand the scratch directory to the sandbox user")
	}
	out, err = r.d.Run(ctx, r.buildSpec(l, buildArgs(p, module, modRoot, dir, race, coverPkgs), modRoot, race))
	a.record(PhaseBuild, out.Output)
	if err != nil || out.TimedOut || out.OOM || out.ExitCode != 0 {
		why := phaseFailure(ctx, PhaseBuild, out, err)
		if err == nil && !out.TimedOut && !out.OOM && why != reasonNewerGo {
			// The one place a "build" signal comes from: the build
			// phase's own exit status.
			a.signal = none(ReasonBuild, "the PoC did not build")
		}
		return a.fail(why)
	}
	bin := testBinary
	if p.Shape == ShapeProgram {
		bin = progBinary
	}
	if fi, err := os.Lstat(filepath.Join(l.out, bin)); err != nil || !fi.Mode().IsRegular() {
		a.signal = none(ReasonNoTestsRan, "the build produced no test binary")
		return a.fail("no test ran: the build produced no binary (the PoC's files may be excluded by build constraints)")
	}

	// Run (no network, source read-only).
	runTimeout := time.Duration(r.cfg.RunTimeoutSeconds) * time.Second
	out, err = r.d.Run(ctx, r.runPhaseSpec(l, runArgs(p, runTimeout, cover), dir))
	a.record(PhaseRun, out.Output)
	if err != nil {
		return a.fail(phaseFailure(ctx, PhaseRun, out, err))
	}
	if cover {
		if prof, err := readBounded(filepath.Join(l.runout, coverFile), maxScanBytes); err == nil {
			out.Coverage = prof
		}
	}
	sig := Analyze(out, targets)
	if sig.Reason == ReasonBuild {
		// Build text in the run output is something the PoC printed: a
		// build outcome comes only from the build phase.
		sig = none(ReasonExitNoSignal, fmt.Sprintf("the run exited %d without a signal in claimed code", out.ExitCode))
	}
	a.signal = sig
	switch {
	case sig.Kind != KindNone:
		return a
	case sig.Reason == ReasonPassed:
		switch passedAllRequested(p, out.Output) {
		case "":
			if !race {
				// A clean run without the race detector says nothing
				// about a data race: a sandbox gap, never a negative.
				return a.fail(reasonNoRace)
			}
			a.passed = true
			return a
		case ReasonSkipped:
			a.signal = none(ReasonSkipped, "a requested test was skipped")
			return a.fail("the run exited 0 but a requested test was skipped, which says nothing about the code")
		}
		a.signal = none(ReasonNoTestsRan, "a requested test did not pass")
		return a.fail("the run exited 0 but a requested test did not pass or never ran")
	case sig.Reason == ReasonNoTestsRan:
		return a.fail("no test ran (the PoC's tests may be excluded by build constraints or a GOOS/GOARCH file name)")
	}
	return a.fail(sig.Detail)
}

// fetch runs the fetch container behind a fresh fetch bridge and tears
// the bridge down before it returns, on every path. why is set when
// the bridge could not be built; the fetch then never ran.
func (r *Runner) fetch(ctx context.Context, a *attempt, l layout, modRoot string) (out RunOutput, why string, err error) {
	if r.bridge == nil {
		return RunOutput{}, "the fetch phase has no network bridge, so it cannot reach the module proxy", nil
	}
	b, berr := r.bridge.Open(ctx, r.cfg.GoProxy)
	if berr != nil || b == nil {
		if ctx.Err() != nil {
			return RunOutput{}, fmt.Sprintf("the %s phase was cancelled", PhaseFetch), nil
		}
		reason := "unknown error"
		if berr != nil {
			reason = report.Printable(berr.Error())
		}
		return RunOutput{}, "the fetch phase's network bridge could not be set up, so the module proxy is unreachable: " + reason, nil
	}
	defer func() {
		if cerr := b.Close(); cerr != nil {
			slog.Warn("sandbox: fetch bridge not fully removed; the next start sweeps it", "error", cerr)
			a.notes = append(a.notes, "the fetch bridge could not be fully removed; it is swept at the next start")
		}
	}()
	out, err = r.d.Run(ctx, r.fetchSpec(l, modRoot, b))
	return out, "", err
}

// inconclusiveReason is the reason of an *Inconclusive, or the printable
// error text.
func inconclusiveReason(err error) string {
	var inc *Inconclusive
	if errors.As(err, &inc) {
		return inc.Reason
	}
	return report.Printable(err.Error())
}

// ownScratch hands the scratch tree to the container user when the
// host process runs as root.
func (r *Runner) ownScratch(work string) error {
	if !r.chown {
		return nil
	}
	return chownTree(work, r.uid, r.gid)
}
