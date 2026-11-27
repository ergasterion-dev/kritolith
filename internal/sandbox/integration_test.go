//go:build sandbox

// Integration tests against a real runsc and Go rootfs. They need
// Linux, runsc on PATH and KRITOLITH_SANDBOX_ROOTFS pointing at a Go
// toolchain rootfs (docs/sandbox.md); without them every test skips
// and says why. `make sandbox-test` runs them in a privileged container.
//
// Environment:
//
//	KRITOLITH_SANDBOX_ROOTFS   the rootfs directory (required)
//	KRITOLITH_SANDBOX_CGROUPS  "1" on a real Linux host where runsc can
//	                           configure cgroups; otherwise the runs use
//	                           --ignore-cgroups and cgroup-only cases skip
//	KRITOLITH_SANDBOX_INTERNET "1" to also probe fetch-phase egress to
//	                           the public Go module proxy
package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/config"
	"github.com/ergasterion-dev/kritolith/internal/ground"
	"github.com/ergasterion-dev/kritolith/internal/report"
	"github.com/ergasterion-dev/kritolith/internal/verdict"
)

const (
	envRootfs   = "KRITOLITH_SANDBOX_ROOTFS"
	envCgroups  = "KRITOLITH_SANDBOX_CGROUPS"
	envInternet = "KRITOLITH_SANDBOX_INTERNET"
	// envHostCanary is set in the test process; its value must never
	// show up inside a container.
	envHostCanary = "KRITOLITH_HOST_CANARY"

	testRepo   = "kritolith-test/victim"
	testModule = "example.com/victim"
)

type sbEnv struct {
	rootfs        string
	ignoreCgroups bool
}

// needSandbox skips the test, with the reason, unless runsc and a rootfs
// are available.
func needSandbox(t *testing.T) sbEnv {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("sandbox integration tests need Linux (gVisor); this host runs %s", runtime.GOOS)
	}
	rootfs := os.Getenv(envRootfs)
	if rootfs == "" {
		t.Skipf("%s is not set: point it at a Go toolchain rootfs (docs/sandbox.md, \"Producing the rootfs\")", envRootfs)
	}
	if fi, err := os.Stat(rootfs); err != nil || !fi.IsDir() {
		t.Skipf("%s=%q is not a directory", envRootfs, rootfs)
	}
	if _, err := exec.LookPath("runsc"); err != nil {
		t.Skip("runsc is not on PATH (docs/sandbox.md, \"Installing runsc\")")
	}
	return sbEnv{rootfs: filepath.Clean(rootfs), ignoreCgroups: os.Getenv(envCgroups) != "1"}
}

func randHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// world is the host side of one integration test: a data dir with a
// signing key, a canary file outside everything the sandbox may touch,
// a canary environment variable, HTTP listeners that count hits, an
// origin repository and the sandbox work dir.
type world struct {
	env                         sbEnv
	base, dataDir, workDir      string
	canaryDir, canaryFile       string
	keyFile                     string
	canary, keySecret, envValue string
	origin                      string
	hits                        atomic.Int64
	subst                       map[string]string
}

func newWorld(t *testing.T, env sbEnv) *world {
	t.Helper()
	w := &world{env: env, base: t.TempDir()}
	w.dataDir = filepath.Join(w.base, "data")
	w.canaryDir = filepath.Join(w.base, "canary")
	w.workDir = filepath.Join(w.base, "work")
	w.origin = filepath.Join(w.base, "origin")
	for _, d := range []string{w.dataDir, w.canaryDir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	w.keySecret = "kritolith-key-secret-" + randHex(t)
	w.keyFile = filepath.Join(w.dataDir, "signing.key")
	if err := os.WriteFile(w.keyFile, []byte(w.keySecret), 0o600); err != nil {
		t.Fatal(err)
	}
	w.canary = "kritolith-host-canary-" + randHex(t)
	w.canaryFile = filepath.Join(w.canaryDir, "canary.txt")
	if err := os.WriteFile(w.canaryFile, []byte(w.canary), 0o644); err != nil {
		t.Fatal(err)
	}
	w.envValue = "kritolith-env-canary-" + randHex(t)
	t.Setenv(envHostCanary, w.envValue)

	loop := w.listen(t, "127.0.0.1:0")
	hostIP := ""
	if ip := hostAddr(); ip != "" {
		hostIP = net.JoinHostPort(ip, portOf(w.listen(t, net.JoinHostPort(ip, "0"))))
	}
	w.subst = map[string]string{
		phDataDir: w.dataDir, phHostCanary: w.canaryFile, phHostHTTP: loop,
		phHostIPHTTP: hostIP, phOrigin: w.origin,
	}
	return w
}

// listen serves HTTP on addr and counts every request; it returns the
// bound address.
func (w *world) listen(t *testing.T, addr string) string {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		w.hits.Add(1)
		fmt.Fprintln(rw, "kritolith host listener")
	}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().String()
}

func portOf(addr string) string {
	_, p, _ := net.SplitHostPort(addr)
	return p
}

// hostAddr is a non-loopback IPv4 address of this host, or "".
func hostAddr() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
			return n.IP.String()
		}
	}
	return ""
}

func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	full := append([]string{"-c", "user.name=kritolith-test", "-c", "user.email=test@example.invalid",
		"-c", "commit.gpgsign=false", "-c", "core.symlinks=true"}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// commit writes files (and symlinks, name -> target) into the origin
// repository, creating it on first use, commits, and returns the commit.
func (w *world) commit(t *testing.T, files map[string][]byte, links map[string]string) string {
	t.Helper()
	if _, err := os.Stat(filepath.Join(w.origin, ".git")); err != nil {
		if err := os.MkdirAll(w.origin, 0o755); err != nil {
			t.Fatal(err)
		}
		gitRun(t, w.origin, "init", "-q", "-b", "main")
	}
	for name, b := range files {
		p := filepath.Join(w.origin, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range links {
		p := filepath.Join(w.origin, filepath.FromSlash(name))
		_ = os.Remove(p)
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	gitRun(t, w.origin, "add", "-A")
	gitRun(t, w.origin, "commit", "-q", "--allow-empty", "-m", "fixture")
	return gitRun(t, w.origin, "rev-parse", "HEAD")
}

// baseRepo is the victim module with an optional overlay directory.
func (w *world) baseRepo(t *testing.T, overlay string) map[string][]byte {
	t.Helper()
	files := readFixtureTree(t, fixturePath("repo"), w.subst)
	if overlay != "" {
		for k, v := range readFixtureTree(t, overlay, w.subst) {
			files[k] = v
		}
	}
	return files
}

// outwardLinks are symlinks a hostile repository commits next to the
// claimed code.
func (w *world) outwardLinks() map[string]string {
	return map[string]string{
		"vuln/hostroot": "/",
		"vuln/canary":   w.canaryFile,
		"vuln/up":       "../../../../../../../../../..",
		"vuln/data":     w.dataDir,
	}
}

// mirror is the production source: a bare mirror of the origin under
// the data dir, as `kritolith check` makes it.
func (w *world) mirror(t *testing.T, ref string) *ground.Mirror {
	t.Helper()
	m, err := ground.OpenMirror(w.dataDir, testRepo, w.origin)
	if err != nil {
		t.Fatal(err)
	}
	sha, ok, _, err := m.EnsureAndResolve(context.Background(), ref, nil)
	if err != nil || !ok || sha != ref {
		t.Fatalf("mirror resolve %s = %q, %v, %v", ref, sha, ok, err)
	}
	return m
}

// testConfig keeps hostile runs short; the build gets room for a cold
// -race build of the standard library.
func testConfig() config.Sandbox {
	return config.Sandbox{
		FetchTimeoutSeconds: 120, BuildTimeoutSeconds: 600, RunTimeoutSeconds: 20,
		MemoryMB: 2048, CPUs: 1, PIDs: 128, OutputLimitKB: 256,
	}
}

// runner builds the production Runner the way the CLI does: sweep
// first, then New, then the data dir forbidden.
func (w *world) runner(t *testing.T, cfg config.Sandbox, src Source) *Runner {
	t.Helper()
	cfg.Rootfs = w.env.rootfs
	cfg.IgnoreCgroups = w.env.ignoreCgroups
	if err := SweepOrphans(cfg.WithDefaults().Runtime, w.workDir); err != nil {
		t.Fatalf("SweepOrphans: %v", err)
	}
	r, err := New(cfg, src, w.workDir, w.env.ignoreCgroups)
	if err != nil {
		t.Fatalf("sandbox.New: %v", err)
	}
	r = r.WithForbidden(w.dataDir)
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Errorf("Runner.Close: %v", err)
		}
	})
	return r
}

func victimClaims() []report.Claim {
	return []report.Claim{
		{Kind: report.ClaimFunction, Value: "vuln.Parse", Source: "deterministic", Verified: report.TriYes,
			Evidence: "fixture", DeclPkgDir: "vuln", DeclName: "Parse"},
		{Kind: report.ClaimFile, Value: "vuln/vuln.go", Source: "deterministic", Verified: report.TriYes, Evidence: "fixture"},
	}
}

func (w *world) request(ref string, poc []report.Artifact) Request {
	return Request{
		Report: report.Report{ID: "01KRITOLITHSANDBOXTEST0000", Source: report.SourceFile, Repo: testRepo,
			ClaimedRef: ref, Title: "fixture", Body: "vuln.Parse in vuln/vuln.go panics", PoC: poc},
		ResolvedRef: ref, Claims: victimClaims(), Module: testModule,
	}
}

// compose turns a Result into the verdict outcome the pipeline would
// give it (the same conversion as pipeline.runSandbox).
func compose(req Request, res Result) report.Verdict {
	sb := verdict.SandboxOutcome{Repro: res.Repro, Skipped: res.Skipped, NeedsInfo: res.NeedsInfo,
		Inconclusive: res.Inconclusive, Passed: res.Passed, Weak: res.Weak, ViaFallback: res.ViaFallback}
	if sb.Repro == nil {
		sb.Passed = false
		if sb.Skipped == "" && sb.NeedsInfo == "" && sb.Inconclusive == "" {
			sb.Inconclusive = "the sandbox returned no result"
		}
	}
	return verdict.Compose(req.Report, verdict.StageResults{
		Claims: req.Claims, GroundingRan: true, RefResolved: true, ResolvedRef: req.ResolvedRef,
		Module: req.Module, HasPoC: true, SandboxRan: true, SandboxConfigured: true, Sandbox: sb,
	})
}

func describe(res Result) string {
	s := fmt.Sprintf("skipped=%q needsInfo=%q inconclusive=%q passed=%v weak=%v", res.Skipped, res.NeedsInfo, res.Inconclusive, res.Passed, res.Weak)
	if res.Repro != nil {
		s += fmt.Sprintf(" repro{reproduced=%v signal=%q phase=%q control=%q notes=%q}",
			res.Repro.Reproduced, res.Repro.Signal, res.Repro.Phase, res.Repro.ControlState, res.Repro.Notes)
	}
	return s
}

// logTail is the last part of every phase log, for failure messages.
func logTail(res Result) string {
	var b strings.Builder
	for k, v := range res.Logs {
		if len(v) > 2048 {
			v = v[len(v)-2048:]
		}
		fmt.Fprintf(&b, "--- %s (%d bytes, tail) ---\n%s\n", k, len(res.Logs[k]), report.Printable(string(v)))
	}
	return b.String()
}

// assertContained checks that a run had no effect on the host and saw
// none of its secrets.
func (w *world) assertContained(t *testing.T, res Result, outputLimit int) {
	t.Helper()
	if b, err := os.ReadFile(w.canaryFile); err != nil || string(b) != w.canary {
		t.Errorf("host canary file changed or unreadable: %q, %v", b, err)
	}
	if ents, err := os.ReadDir(w.canaryDir); err != nil || len(ents) != 1 {
		t.Errorf("host canary dir changed: %d entries, %v", len(ents), err)
	}
	if b, err := os.ReadFile(w.keyFile); err != nil || string(b) != w.keySecret {
		t.Errorf("data dir key changed or unreadable: %v", err)
	}
	if st := gitRun(t, w.origin, "status", "--porcelain", "--ignored"); st != "" {
		t.Errorf("origin repository changed:\n%s", st)
	}
	if n := w.hits.Load(); n != 0 {
		t.Errorf("host HTTP listeners got %d requests from the sandbox", n)
	}
	w.checkLogs(t, res.Logs)
	for phase, out := range res.Logs {
		if outputLimit > 0 && len(out) > outputLimit {
			t.Errorf("%s log is %d bytes, over the %d byte cap", phase, len(out), outputLimit)
		}
	}
	assertNoLeftovers(t, w.workDir)
}

// assertNoLeftovers checks that no bundle or scratch dir, no runsc
// container and no runsc process of this work dir is left, waiting a
// little for process exit to be reaped.
func assertNoLeftovers(t *testing.T, workDir string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		left := leftovers(workDir)
		if len(left) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("the sandbox left things behind:\n%s", strings.Join(left, "\n"))
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func leftovers(workDir string) []string {
	var out []string
	if ents, err := os.ReadDir(workDir); err == nil {
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), orphanPrefix) {
				out = append(out, "work dir entry "+e.Name())
			}
		}
	}
	state := filepath.Join(workDir, runscStateDir)
	if ents, err := os.ReadDir(state); err == nil {
		for _, e := range ents {
			if strings.Contains(e.Name(), orphanPrefix) {
				out = append(out, "runsc state entry "+e.Name())
			}
		}
	}
	if _, err := os.Stat(state); err == nil {
		cmd := exec.Command("runsc", "--root="+state, "list", "--quiet")
		cmd.Env = []string{"PATH=" + runscPath}
		b, err := cmd.CombinedOutput()
		switch {
		case err != nil:
			out = append(out, fmt.Sprintf("runsc list failed: %v: %s", err, b))
		case strings.TrimSpace(string(b)) != "":
			out = append(out, "runsc containers: "+strings.Join(strings.Fields(string(b)), " "))
		}
	}
	// Mounts: only runsc's own null-netns may stay while the driver lives.
	mps, err := mountPointsUnder(workDir)
	if err != nil {
		out = append(out, err.Error())
	}
	for _, mp := range mps {
		if mp != keptMount(state) {
			out = append(out, "mount "+mp)
		}
	}
	return append(out, processesMentioning(workDir)...)
}

// processesMentioning lists processes other than this one whose command
// line contains s (runsc, its sandbox and gofer carry --root and
// --bundle paths under the work dir).
func processesMentioning(s string) []string {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return []string{"cannot read /proc: " + err.Error()}
	}
	var out []string
	self := os.Getpid()
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil || !bytes.Contains(b, []byte(s)) {
			continue
		}
		out = append(out, fmt.Sprintf("process %d: %s", pid, bytes.ReplaceAll(b, []byte{0}, []byte(" "))))
	}
	return out
}

// TestSandboxBenignPoCNotReproduced: a passing test PoC at the claimed
// commit is NOT_REPRODUCED.
func TestSandboxBenignPoCNotReproduced(t *testing.T) {
	env := needSandbox(t)
	w := newWorld(t, env)
	sha := w.commit(t, w.baseRepo(t, ""), nil)
	cfg := testConfig()
	r := w.runner(t, cfg, w.mirror(t, sha))
	req := w.request(sha, fixtureArtifacts(t, fixturePath("poc", "benign"), w.subst))
	res := r.Run(context.Background(), req)
	v := compose(req, res)
	if v.Outcome != report.OutcomeNotReproduced || !res.Passed {
		t.Fatalf("outcome %s, want NOT_REPRODUCED; %s\n%s", v.Outcome, describe(res), logTail(res))
	}
	w.assertContained(t, res, cfg.OutputLimitKB*1024)
}

// TestSandboxPanicInClaimedCodeReproduced: a panic through the claimed
// function at a ref that is also HEAD is REPRODUCED.
func TestSandboxPanicInClaimedCodeReproduced(t *testing.T) {
	env := needSandbox(t)
	w := newWorld(t, env)
	sha := w.commit(t, w.baseRepo(t, ""), nil)
	cfg := testConfig()
	r := w.runner(t, cfg, w.mirror(t, sha))
	req := w.request(sha, fixtureArtifacts(t, fixturePath("poc", "panic"), w.subst))
	res := r.Run(context.Background(), req)
	v := compose(req, res)
	if v.Outcome != report.OutcomeReproduced {
		t.Fatalf("outcome %s, want REPRODUCED; %s\n%s", v.Outcome, describe(res), logTail(res))
	}
	if !strings.HasPrefix(res.Repro.Signal, KindPanic) || res.Repro.ControlState != ControlStillReproduces {
		t.Errorf("signal %q control %q, want %s and %s", res.Repro.Signal, res.Repro.ControlState, KindPanic, ControlStillReproduces)
	}
	w.assertContained(t, res, cfg.OutputLimitKB*1024)
}

// TestSandboxPanicFixedAtHead: the same panic at an old ref, with HEAD
// fixed, is REPRODUCED_FIXED_AT_HEAD (the control runs at HEAD).
func TestSandboxPanicFixedAtHead(t *testing.T) {
	env := needSandbox(t)
	w := newWorld(t, env)
	ref := w.commit(t, w.baseRepo(t, ""), nil)
	head := w.commit(t, readFixtureTree(t, fixturePath("repo-fixed"), w.subst), nil)
	cfg := testConfig()
	m := w.mirror(t, ref)
	if got, err := m.DefaultBranchRef(context.Background()); err != nil || got != head {
		t.Fatalf("DefaultBranchRef = %q, %v, want %s", got, err, head)
	}
	r := w.runner(t, cfg, m)
	req := w.request(ref, fixtureArtifacts(t, fixturePath("poc", "panic"), w.subst))
	res := r.Run(context.Background(), req)
	v := compose(req, res)
	if v.Outcome != report.OutcomeReproducedFixedAtHead || res.Repro.ControlState != ControlFixed {
		t.Fatalf("outcome %s, want REPRODUCED_FIXED_AT_HEAD; %s\n%s", v.Outcome, describe(res), logTail(res))
	}
	w.assertContained(t, res, cfg.OutputLimitKB*1024)
}

// TestSandboxHostileFixtures runs every hostile fixture: each must end
// INCONCLUSIVE or NEEDS_INFO, never a reproduction, within its time
// limits, with no effect on the host and none of its secrets visible.
func TestSandboxHostileFixtures(t *testing.T) {
	env := needSandbox(t)
	for _, fx := range hostileFixtures {
		t.Run(fx.name, func(t *testing.T) {
			if fx.needsCgroups && env.ignoreCgroups {
				t.Skipf("needs cgroup limits in force: under --ignore-cgroups nothing caps memory, so the bomb would only hit the outer container; set %s=1 on a real Linux host where runsc configures cgroups", envCgroups)
			}
			w := newWorld(t, env)
			overlay := fixturePath("hostile", fx.name, "repo")
			var links map[string]string
			if fx.repoLinks {
				links = w.outwardLinks()
			}
			sha := w.commit(t, w.baseRepo(t, overlay), links)
			cfg := testConfig()
			r := w.runner(t, cfg, w.mirror(t, sha))
			req := w.request(sha, fixtureArtifacts(t, fixturePath("hostile", fx.name, "poc"), w.subst))

			start := time.Now()
			res := r.Run(context.Background(), req)
			elapsed := time.Since(start)
			v := compose(req, res)
			t.Logf("%s after %v: %s", v.Outcome, elapsed.Round(time.Second), describe(res))

			if v.Outcome != report.OutcomeInconclusive && v.Outcome != report.OutcomeNeedsInfo {
				t.Errorf("outcome %s, want INCONCLUSIVE or NEEDS_INFO\n%s", v.Outcome, logTail(res))
			}
			if res.Repro != nil && res.Repro.Reproduced {
				t.Errorf("hostile fixture counted as reproduced: %s", describe(res))
			}
			if fx.reason != "" && !strings.Contains(res.Inconclusive+res.NeedsInfo, fx.reason) {
				t.Errorf("reason %q, want it to contain %q", res.Inconclusive+res.NeedsInfo, fx.reason)
			}
			if fx.noContainer && len(res.Logs) > 0 {
				t.Errorf("a container ran (%d phase logs); the run must stop before any", len(res.Logs))
			}
			// Each phase is bounded by its timeout plus the driver's
			// worst-case cleanup (about 65s, see driver.go).
			bound := time.Duration(cfg.FetchTimeoutSeconds+cfg.BuildTimeoutSeconds+cfg.RunTimeoutSeconds)*time.Second + 3*65*time.Second
			if elapsed > bound {
				t.Errorf("run took %v, over the %v bound: the wall clock did not hold", elapsed, bound)
			}
			w.assertContained(t, res, cfg.OutputLimitKB*1024)
		})
	}
}

// TestSandboxRunOutIsCapped: a PoC that writes 256 MiB files to the
// run phase's /out until a write fails is stopped at the size cap, the
// coverage profile still reaches the host (the assertion failure is
// seen as reaching claimed code), and no mount is left behind.
func TestSandboxRunOutIsCapped(t *testing.T) {
	env := needSandbox(t)
	w := newWorld(t, env)
	sha := w.commit(t, w.baseRepo(t, ""), nil)
	cfg := testConfig()
	r := w.runner(t, cfg, w.mirror(t, sha))
	req := w.request(sha, fixtureArtifacts(t, fixturePath("hostile", "out-flood", "poc"), w.subst))
	res := r.Run(context.Background(), req)
	v := compose(req, res)
	t.Logf("%s: %s", v.Outcome, describe(res))
	if v.Outcome != report.OutcomeInconclusive || (res.Repro != nil && res.Repro.Reproduced) {
		t.Fatalf("outcome %s, want INCONCLUSIVE\n%s", v.Outcome, logTail(res))
	}
	run := string(res.Logs[PhaseRun])
	i := strings.Index(run, "KRITOLITH-OUT wrote ")
	if i < 0 {
		t.Fatalf("the flood never reported\n%s", logTail(res))
	}
	var total int64
	var files int
	if _, err := fmt.Sscanf(run[i:], "KRITOLITH-OUT wrote %d bytes in %d files", &total, &files); err != nil {
		t.Fatalf("parse %q: %v", run[i:], err)
	}
	t.Logf("the PoC wrote %d bytes in %d files before a write failed", total, files)
	if total > runOutBytes || total == 0 {
		t.Errorf("wrote %d bytes to /out, want at most the %d byte cap", total, runOutBytes)
	}
	if res.Repro == nil || !strings.HasPrefix(res.Repro.Signal, KindFailingTest) {
		t.Errorf("signal %v, want %s: the coverage profile did not come back through the capped /out", res.Repro, KindFailingTest)
	}
	w.assertContained(t, res, cfg.OutputLimitKB*1024)
}

// TestSandboxHostilePoCNames: file names that leave the package
// directory are NEEDS_INFO, and nothing runs.
func TestSandboxHostilePoCNames(t *testing.T) {
	env := needSandbox(t)
	w := newWorld(t, env)
	sha := w.commit(t, w.baseRepo(t, ""), nil)
	cfg := testConfig()
	r := w.runner(t, cfg, w.mirror(t, sha))
	content := readFixtureTree(t, fixturePath("poc", "benign"), w.subst)["parse_test.go"]
	for _, name := range hostilePoCNames {
		req := w.request(sha, []report.Artifact{{Name: name, Content: content}})
		res := r.Run(context.Background(), req)
		v := compose(req, res)
		if v.Outcome != report.OutcomeNeedsInfo || res.NeedsInfo == "" {
			t.Errorf("name %q: outcome %s, want NEEDS_INFO; %s", name, v.Outcome, describe(res))
		}
		if len(res.Logs) > 0 {
			t.Errorf("name %q: a container ran", name)
		}
	}
	w.assertContained(t, Result{}, 0)
}

// TestSandboxHarnessCatchesLeaks checks the harness itself: a log
// carrying an escape marker or a host secret is caught. It needs no
// runsc.
func TestSandboxHarnessCatchesLeaks(t *testing.T) {
	w := newWorld(t, sbEnv{})
	for _, leak := range []string{escapeMarker + " write /src", w.envValue, w.canary, w.keySecret} {
		rec := &recorder{}
		w.checkLogs(rec, map[string][]byte{"run": []byte("x " + leak + " y")})
		if len(rec.errs) == 0 {
			t.Errorf("leak %q not caught", leak)
		}
	}
	rec := &recorder{}
	w.checkLogs(rec, map[string][]byte{"run": []byte("clean output")})
	if len(rec.errs) != 0 {
		t.Errorf("clean log flagged: %v", rec.errs)
	}
}

// recorder collects errors for TestSandboxHarnessCatchesLeaks.
type recorder struct{ errs []string }

func (r *recorder) Errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}

// checkLogs is the secret scan of assertContained, separated so the
// harness test can check it.
func (w *world) checkLogs(t interface{ Errorf(string, ...any) }, logs map[string][]byte) {
	for phase, out := range logs {
		for what, secret := range map[string]string{
			"host environment canary": w.envValue, "host canary file content": w.canary,
			"data dir signing key": w.keySecret, "escape marker": escapeMarker,
		} {
			if bytes.Contains(out, []byte(secret)) {
				t.Errorf("%s log contains the %s", phase, what)
			}
		}
	}
}
