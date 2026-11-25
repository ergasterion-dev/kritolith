//go:build sandbox

// Probes of the runsc facts earlier tasks could only take from the
// documentation (the TODO(task10) lists in runsc.go and phases.go).
// Each probe drives the driver directly with a minimal container, so a
// failure names the one fact that does not hold on this host. The
// "First run checklist" in docs/sandbox.md lists them.
package sandbox

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/config"
)

// probe is a runsc driver on its own work dir plus the container user
// the Runner would use.
type probe struct {
	env       sbEnv
	base      string
	d         *runscDriver
	uid, gid  int
	chown     bool
	forbidden []string
}

func newProbe(t *testing.T, env sbEnv) *probe {
	t.Helper()
	return newProbeAt(t, env, filepath.Join(t.TempDir(), "work"))
}

func newProbeAt(t *testing.T, env sbEnv, workDir string) *probe {
	t.Helper()
	p := &probe{env: env, base: filepath.Dir(workDir)}
	d, err := newRunscDriver("runsc", workDir)
	if err != nil {
		t.Fatalf("newRunscDriver: %v", err)
	}
	d.ignoreCgroups = env.ignoreCgroups
	p.d = d
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Errorf("driver Close: %v", err)
		}
	})
	// The same user choice as NewRunner.
	r := NewRunner(config.Sandbox{}, nil, nil, "/unused")
	p.uid, p.gid, p.chown = r.uid, r.gid, r.chown
	data := filepath.Join(p.base, "data")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	p.forbidden = []string{data}
	return p
}

// dir makes a host directory for a mount, owned by the container user.
func (p *probe) dir(t *testing.T, name string, files map[string]string) string {
	t.Helper()
	d := filepath.Join(p.base, "mounts", name)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(d, n), []byte(c), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if p.chown {
		if err := chownTree(d, p.uid, p.gid); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func (p *probe) spec(args []string, mounts []Mount, network bool, timeout time.Duration) RunSpec {
	return RunSpec{
		Container: ContainerSpec{
			Rootfs: p.env.rootfs, Args: args, Env: []string{"PATH=" + ctrPath, "HOME=/tmp"}, Cwd: "/",
			Mounts: mounts, Network: network, MemoryMB: 512, CPUs: 1, PIDs: 64, CPUSeconds: 60,
			FileSizeKB: 4096, UID: p.uid, GID: p.gid, Forbidden: p.forbidden,
		},
		Timeout: timeout, OutputLimit: 1 << 20,
	}
}

// run runs one container and fails the test on a driver error.
func (p *probe) run(t *testing.T, s RunSpec) RunOutput {
	t.Helper()
	out, err := p.d.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("driver Run: %v\noutput:\n%s", err, out.Output)
	}
	return out
}

func (p *probe) sh(t *testing.T, script string, mounts ...Mount) RunOutput {
	t.Helper()
	return p.run(t, p.spec([]string{"/bin/sh", "-c", script}, mounts, false, 60*time.Second))
}

// TestProbeDevContents: /dev holds the four devices of the OCI config
// and runsc's own links, nothing from the host.
func TestProbeDevContents(t *testing.T) {
	p := newProbe(t, needSandbox(t))
	out := p.sh(t, "ls -1A /dev; echo ---; ls -la /dev")
	t.Logf("/dev inside the sandbox:\n%s", out.Output)
	listing, _, _ := strings.Cut(string(out.Output), "---")
	have := map[string]bool{}
	for _, n := range strings.Fields(listing) {
		have[n] = true
	}
	for _, n := range []string{"null", "zero", "urandom", "tty"} {
		if !have[n] {
			t.Errorf("/dev/%s missing", n)
		}
	}
	allowed := map[string]bool{"null": true, "zero": true, "urandom": true, "tty": true,
		"fd": true, "stdin": true, "stdout": true, "stderr": true, "pts": true, "ptmx": true, "shm": true}
	for n := range have {
		if !allowed[n] {
			t.Errorf("/dev/%s present: not in the OCI device list (linux.devices) nor a runsc link; check runsc.go's TODO(task10) and BuildOCI", n)
		}
	}
}

// TestProbeRlimits: the OCI rlimits are applied inside the sandbox.
func TestProbeRlimits(t *testing.T) {
	p := newProbe(t, needSandbox(t))
	s := p.spec([]string{"/bin/cat", "/proc/self/limits"}, nil, false, 60*time.Second)
	out := p.run(t, s)
	t.Logf("limits:\n%s", out.Output)
	want := map[string]uint64{
		"Max cpu time":   uint64(s.Container.CPUSeconds),
		"Max file size":  uint64(s.Container.FileSizeKB) * 1024,
		"Max open files": noFileMax,
		"Max processes":  uint64(s.Container.PIDs),
	}
	sc := bufio.NewScanner(strings.NewReader(string(out.Output)))
	seen := map[string]bool{}
	for sc.Scan() {
		line := sc.Text()
		for name, v := range want {
			if !strings.HasPrefix(line, name+" ") {
				continue
			}
			seen[name] = true
			f := strings.Fields(strings.TrimPrefix(line, name))
			if len(f) < 2 || f[0] != strconv.FormatUint(v, 10) || f[1] != strconv.FormatUint(v, 10) {
				t.Errorf("%s = %v, want soft and hard %d", name, f, v)
			}
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("%s not reported in /proc/self/limits", name)
		}
	}
}

// TestProbeMountPointsInReadOnlyRootfs: the phase mount points that the
// rootfs does not have (/src, /work/*, /out, /poc) are created, the
// rootfs and the read-only binds refuse writes, the writable ones take
// them, and a file written to /out lands on the host owned by the
// container user (through the gofer).
func TestProbeMountPointsInReadOnlyRootfs(t *testing.T) {
	p := newProbe(t, needSandbox(t))
	src := p.dir(t, "src", map[string]string{"hello.txt": "hello\n"})
	out := p.dir(t, "out", nil)
	mounts := []Mount{
		{Source: src, Dest: ctrSrc},
		{Source: p.dir(t, "modcache", nil), Dest: ctrModCache},
		{Source: p.dir(t, "gocache", nil), Dest: ctrGoCache, Writable: true},
		{Source: out, Dest: ctrOut, Writable: true},
		{Source: p.dir(t, "bin", nil), Dest: ctrBin},
		{Dest: ctrTmp, Tmpfs: true, Writable: true, SizeMB: 16},
	}
	script := `fail=0
for d in /src /work/modcache /work/gocache /out /poc /tmp; do [ -d "$d" ] || { echo "MISSING $d"; fail=1; }; done
for d in /work/gocache /out /tmp; do touch "$d/kritolith-w" 2>/dev/null || { echo "NOT-WRITABLE $d"; fail=1; }; done
for d in /src /work/modcache /poc / /usr /usr/local/go /etc; do touch "$d/kritolith-w" 2>/dev/null && { echo "WRITABLE $d"; fail=1; }; done
cat /src/hello.txt >/dev/null || { echo "UNREADABLE /src/hello.txt"; fail=1; }
exit $fail`
	res := p.sh(t, script, mounts...)
	if res.ExitCode != 0 {
		t.Fatalf("mount check exit %d:\n%s", res.ExitCode, res.Output)
	}
	fi, err := os.Lstat(filepath.Join(out, "kritolith-w"))
	if err != nil {
		t.Fatalf("file written to /out not on the host: %v", err)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != p.uid {
		t.Errorf("file written to /out is owned by uid %v, want the container user %d", fi.Sys(), p.uid)
	}
	if _, err := os.Lstat(filepath.Join(src, "kritolith-w")); err == nil {
		t.Error("a write to the read-only /src reached the host")
	}
}

// TestProbeUser: the container runs as the Runner's unprivileged user.
func TestProbeUser(t *testing.T) {
	p := newProbe(t, needSandbox(t))
	out := p.sh(t, "id -u; id -g")
	f := strings.Fields(string(out.Output))
	if len(f) != 2 || f[0] != strconv.Itoa(p.uid) || f[1] != strconv.Itoa(p.gid) {
		t.Errorf("id = %q, want %d %d", out.Output, p.uid, p.gid)
	}
}

// TestProbeGoOnPath: args[0] "go" resolves through the container PATH,
// and the rootfs has the C compiler -race needs.
func TestProbeGoOnPath(t *testing.T) {
	env := needSandbox(t)
	p := newProbe(t, env)
	s := p.spec([]string{"go", "version"}, []Mount{{Dest: ctrTmp, Tmpfs: true, Writable: true, SizeMB: 16}}, false, 60*time.Second)
	out := p.run(t, s)
	if out.ExitCode != 0 || !strings.HasPrefix(string(out.Output), "go version go") {
		t.Errorf("go version: exit %d: %s", out.ExitCode, out.Output)
	}
	t.Logf("%s", out.Output)
	cc := p.sh(t, "gcc --version")
	if cc.ExitCode != 0 {
		t.Errorf("gcc --version: exit %d: %s", cc.ExitCode, cc.Output)
	}
	r := NewRunner(config.Sandbox{Rootfs: env.rootfs}, nil, nil, "/unused")
	if !r.raceAvailable() {
		t.Error("raceAvailable() is false for this rootfs: PoCs would be built without -race")
	}
}

// TestProbeExitStatus: a contained exit status comes back as is, a
// signal as 128+n, and a runsc failure cannot be told from a contained
// exit 128 (runsc.go documents that; the phases treat both alike).
func TestProbeExitStatus(t *testing.T) {
	p := newProbe(t, needSandbox(t))
	for script, want := range map[string]int{"exit 0": 0, "exit 1": 1, "exit 42": 42, "exit 128": 128, "kill -9 $$": 137} {
		if got := p.sh(t, script).ExitCode; got != want {
			t.Errorf("%q: exit %d, want %d", script, got, want)
		}
	}
	out, err := p.d.Run(context.Background(), p.spec([]string{"/kritolith-no-such-binary"}, nil, false, 60*time.Second))
	t.Logf("a container whose command does not exist: exit %d, err %v, output %q", out.ExitCode, err, out.Output)
	if err == nil && out.ExitCode == 0 {
		t.Error("a container that cannot start reported success")
	}
	if err == nil && out.ExitCode == 128 {
		t.Log("confirmed: runsc's own failure exits 128, the same as a contained `exit 128`")
	}
}

// TestProbeWallClockKillLeavesNothing: after the host wall clock kills
// a run (with children of its own), no sandbox or gofer process, no
// container and no bundle remain.
func TestProbeWallClockKillLeavesNothing(t *testing.T) {
	p := newProbe(t, needSandbox(t))
	start := time.Now()
	out, err := p.d.Run(context.Background(), p.spec([]string{"/bin/sh", "-c", "sleep 600 & sleep 600 & sleep 600"}, nil, false, 3*time.Second))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("driver Run: %v", err)
	}
	if !out.TimedOut {
		t.Errorf("run not reported timed out (exit %d)", out.ExitCode)
	}
	if elapsed > 3*time.Second+65*time.Second {
		t.Errorf("kill and cleanup took %v", elapsed)
	}
	assertNoLeftovers(t, p.d.workDir)
}

// TestProbeCancelDuringCreate: a run cancelled at any point, including
// while runsc is still creating the sandbox, leaves nothing behind.
func TestProbeCancelDuringCreate(t *testing.T) {
	p := newProbe(t, needSandbox(t))
	for _, delay := range []time.Duration{0, 5 * time.Millisecond, 20 * time.Millisecond, 50 * time.Millisecond,
		100 * time.Millisecond, 250 * time.Millisecond, 500 * time.Millisecond, time.Second} {
		ctx, cancel := context.WithTimeout(context.Background(), delay)
		_, err := p.d.Run(ctx, p.spec([]string{"/bin/sleep", "600"}, nil, false, time.Minute))
		cancel()
		t.Logf("cancel after %v: %v", delay, err)
		if err == nil {
			t.Errorf("cancel after %v: no error from a cancelled run", delay)
		}
		assertNoLeftovers(t, p.d.workDir)
	}
}

// TestProbeRunscGlobalFlagsAccepted: kill, delete and list accept the
// global flags runscArgs gives every subcommand (marked UNVERIFIED in
// runsc.go), and delete --force of a missing container succeeds.
func TestProbeRunscGlobalFlagsAccepted(t *testing.T) {
	p := newProbe(t, needSandbox(t))
	for _, network := range []bool{false, true} {
		g := p.d.globals(network)
		for _, args := range [][]string{
			runscArgs(g, "list", "--quiet"),
			runscArgs(g, "delete", "--force", orphanPrefix+"no-such"),
			runscArgs(g, "kill", orphanPrefix+"no-such", "KILL"),
		} {
			b, err := control(p.d.runtime, p.d.workDir, 30*time.Second, args)
			t.Logf("runsc %v: err %v: %s", args, err, b)
			if strings.Contains(string(b), "flag provided but not defined") || strings.Contains(string(b), "unknown flag") {
				t.Errorf("runsc %v rejects a global flag: %s", args, b)
			}
			if args[len(args)-1] != "KILL" && err != nil {
				t.Errorf("runsc %v failed: %v: %s", args, err, b)
			}
		}
	}
}

// TestProbeLongWorkDir: a long work dir path (runsc puts sockets under
// --root) still runs.
func TestProbeLongWorkDir(t *testing.T) {
	env := needSandbox(t)
	work := filepath.Join(t.TempDir(), strings.Repeat("w", 60), strings.Repeat("x", 60), "work")
	p := newProbeAt(t, env, work)
	t.Logf("work dir is %d bytes", len(work))
	if out := p.sh(t, "true"); out.ExitCode != 0 {
		t.Errorf("exit %d: %s", out.ExitCode, out.Output)
	}
}

// netProbeSrc is a static helper run inside the sandbox: "dial" fetches
// each URL and prints REACHED or BLOCKED, "alloc" eats memory.
const netProbeSrc = `package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	switch os.Args[1] {
	case "dial":
		c := &http.Client{Timeout: 5 * time.Second}
		for _, u := range os.Args[2:] {
			resp, err := c.Get(u)
			if err != nil {
				fmt.Println("BLOCKED", u, err)
				continue
			}
			resp.Body.Close()
			fmt.Println("REACHED", u, resp.Status)
		}
	case "alloc":
		var keep [][]byte
		for {
			b := make([]byte, 32<<20)
			for i := 0; i < len(b); i += 4096 {
				b[i] = 1
			}
			keep = append(keep, b)
			fmt.Println("holding MiB", len(keep)*32)
		}
	}
}
`

// buildNetProbe builds the helper statically for this host and returns
// a mount of the directory holding it at /poc.
func (p *probe) buildNetProbe(t *testing.T) Mount {
	t.Helper()
	src := t.TempDir()
	for n, c := range map[string]string{"go.mod": "module netprobe\n\ngo 1.22\n", "main.go": netProbeSrc} {
		if err := os.WriteFile(filepath.Join(src, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	bin := p.dir(t, "netprobe", nil)
	cmd := exec.Command("go", "build", "-o", filepath.Join(bin, "netprobe"), ".")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOWORK=off", "GOFLAGS=-mod=mod")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build netprobe: %v\n%s", err, out)
	}
	if p.chown {
		if err := chownTree(bin, p.uid, p.gid); err != nil {
			t.Fatal(err)
		}
	}
	return Mount{Source: bin, Dest: ctrBin}
}

// countingServer serves HTTP on addr and counts requests.
func countingServer(t *testing.T, addr string) (string, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		fmt.Fprintln(w, "ok")
	}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().String(), &hits
}

// TestProbeNoNetworkInBuildAndRun: with Network off nothing is
// reachable: not a host listener on loopback or on a host address, not
// a public address.
func TestProbeNoNetworkInBuildAndRun(t *testing.T) {
	p := newProbe(t, needSandbox(t))
	bin := p.buildNetProbe(t)
	loop, loopHits := countingServer(t, "127.0.0.1:0")
	urls := []string{"http://" + loop + "/", "http://1.1.1.1/", "https://proxy.golang.org/"}
	var ipHits *atomic.Int64
	if ip := hostAddr(); ip != "" {
		var a string
		a, ipHits = countingServer(t, net.JoinHostPort(ip, "0"))
		urls = append(urls, "http://"+a+"/")
	}
	out := p.run(t, p.spec(append([]string{"/poc/netprobe", "dial"}, urls...), []Mount{bin}, false, 2*time.Minute))
	t.Logf("%s", out.Output)
	if strings.Contains(string(out.Output), "REACHED") {
		t.Errorf("network reachable with --network=none:\n%s", out.Output)
	}
	if loopHits.Load() != 0 || (ipHits != nil && ipHits.Load() != 0) {
		t.Error("a host listener was reached with --network=none")
	}
}

// TestProbeLoopbackProxyInFetchNetns: config accepts an http:// GOPROXY
// on loopback (a local caching proxy). The fetch container runs in its
// own network namespace, so its loopback may not be the host's; this
// probe says whether such a proxy is reachable from the fetch phase.
func TestProbeLoopbackProxyInFetchNetns(t *testing.T) {
	p := newProbe(t, needSandbox(t))
	bin := p.buildNetProbe(t)
	loop, hits := countingServer(t, "127.0.0.1:0")
	out := p.run(t, p.spec([]string{"/poc/netprobe", "dial", "http://" + loop + "/"}, []Mount{bin}, true, 2*time.Minute))
	t.Logf("%s", out.Output)
	if hits.Load() == 0 || !strings.Contains(string(out.Output), "REACHED") {
		t.Errorf("a GOPROXY on host loopback (%s) is not reachable from the fetch phase: either config.ValidateGoProxy must stop accepting http://127.0.0.1 / localhost proxies, or docs/sandbox.md must say how to expose one to the fetch netns", loop)
	}
}

// TestProbeFetchEgressToProxy: the fetch phase reaches the public Go
// module proxy (the default goproxy). Opt in with
// KRITOLITH_SANDBOX_INTERNET=1 on a host with internet access.
func TestProbeFetchEgressToProxy(t *testing.T) {
	env := needSandbox(t)
	if os.Getenv(envInternet) != "1" {
		t.Skipf("set %s=1 to probe fetch-phase egress to https://proxy.golang.org", envInternet)
	}
	p := newProbe(t, env)
	bin := p.buildNetProbe(t)
	out := p.run(t, p.spec([]string{"/poc/netprobe", "dial", "https://proxy.golang.org/golang.org/x/text/@v/list"}, []Mount{bin}, true, 2*time.Minute))
	t.Logf("%s", out.Output)
	if !strings.Contains(string(out.Output), "REACHED") {
		t.Error("the fetch phase (--network=sandbox) cannot reach the public Go module proxy: `go mod download` of any repository with dependencies will fail; see runsc's network setup for a fresh network namespace")
	}
}

// TestProbeCgroupMemoryLimit: with cgroups in force the memory limit
// ends a container that allocates past it. It also records how the
// kill shows in the exit status (runsc.go's OOM TODO).
func TestProbeCgroupMemoryLimit(t *testing.T) {
	env := needSandbox(t)
	if env.ignoreCgroups {
		t.Skipf("cgroup limits are not in force (--ignore-cgroups); set %s=1 on a real Linux host", envCgroups)
	}
	p := newProbe(t, env)
	bin := p.buildNetProbe(t)
	s := p.spec([]string{"/poc/netprobe", "alloc"}, []Mount{bin}, false, 2*time.Minute)
	s.Container.MemoryMB = 256
	out := p.run(t, s)
	t.Logf("memory hog: exit %d, timed out %v, last output %q", out.ExitCode, out.TimedOut, lastLine(out.Output))
	if out.TimedOut || out.ExitCode == 0 {
		t.Error("a 256 MiB container allocated until the wall clock: the memory limit is not enforced")
	}
}

func lastLine(b []byte) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	return lines[len(lines)-1]
}
