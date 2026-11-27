# The PoC sandbox

Kritolith runs a reporter's proof of concept inside gVisor (`runsc`). For each report it runs three phases at the claimed commit, each in a fresh container: fetch (`go mod download`), build, and run. After a reproduction it runs the same phases again at the default branch's HEAD as a control. Anything that goes wrong in the sandbox ends `INCONCLUSIVE`. It never turns into a rejection.

This page covers what the operator has to set up, the config keys, what the sandbox does and does not isolate, and how to run the integration tests.

> Status: the code, its unit tests and the `TestProbe*` integration tests pass on a real runsc (20261102.0, Ubuntu 24.04 arm64; probes on 2026-11-25, re-run on 2026-11-26 after the security-review fixes). On that host the corpus eval reproduces 15 of 20 real PoC reports. The whole-branch security review is done and its findings are fixed. The hostile-fixture suite (`TestSandboxHostileFixtures`) has not been re-run since those fixes; do not run Kritolith on real embargoed reports until it passes.

## Requirements

- A Linux host. gVisor supports x86_64 and ARM64 and needs Linux 5.6 or later ([gVisor install guide](https://gvisor.dev/docs/user_guide/install/)). On macOS or Windows the sandbox reports itself unavailable, and reports with a PoC end `INCONCLUSIVE` as they did before.
- `runsc` on `PATH` (see [Installing runsc](#installing-runsc)).
- A Go toolchain rootfs (see [Producing the rootfs](#producing-the-rootfs)).
- **Root.** Kritolith calls `runsc run` without `--rootless`, because the gVisor rootless guide says rootless mode supports neither `create` (which `run` uses) nor netstack. `runsc` therefore runs with the privileges of the Kritolith process, and creating the sandbox's namespaces and its gofer needs root. When Kritolith runs as root, the container process runs as uid/gid 65534 (nobody) with every capability dropped and `no_new_privs` set, and Kritolith chowns each run's scratch tree to 65534 before handing it over. If Kritolith runs as another user, the container runs as that uid, and `runsc` will normally fail to start the sandbox at all. When that happens, the stage ends `INCONCLUSIVE` with the error.
- **iproute2** (`ip`, in `/usr/sbin`, `/usr/bin`, `/sbin` or `/bin`) and root, for the fetch phase's network bridge (see [Fetch egress](#fetch-egress)). Without either, the sandbox still starts, but every fetch ends `INCONCLUSIVE` with the reason.
- With `sandbox.ignore_cgroups` off (the default and the only production setting), `runsc` must be able to create cgroups on the host. That means a real Linux host or VM, not a container.

## Producing the rootfs

The rootfs is a plain directory holding an exported Go image. Every container mounts it read-only as `/`. It supplies `go` (`/usr/local/go/bin`), and the C compiler that `-race` needs (gcc ships in the official `golang` images on amd64 and arm64). Pin the image by version. The Go in the rootfs must be at least as new as the `go` line of the repositories you check: the sandbox runs with `GOTOOLCHAIN=local`, so a repository that needs a newer Go ends `INCONCLUSIVE` with that reason.

```sh
GO_IMAGE=golang:1.26.0-bookworm
ROOTFS=/var/lib/kritolith-rootfs/go1.26.0

sudo mkdir -p "$ROOTFS"
cid=$(docker create "$GO_IMAGE")
docker export "$cid" | sudo tar -x --numeric-owner -C "$ROOTFS"
docker rm "$cid"
sudo chown root:root "$ROOTFS"
sudo chmod 0755 "$ROOTFS"

# Checks: both must succeed.
sudo chroot "$ROOTFS" /usr/local/go/bin/go version
sudo chroot "$ROOTFS" /usr/bin/gcc --version
```

Rules the code enforces, so choose the path with them in mind:

- `sandbox.rootfs` must be an absolute, clean path (no `..`, no trailing slash).
- It must not be, contain, or sit inside the data directory, nor lie under `/etc`, `/run`, `/var/run`, `/proc`, `/sys` or `/dev`. Symlinks are resolved before these checks.
- Keep it root-owned and not writable by anyone else. Every PoC runs on top of it.

Without Docker, any tool that unpacks an OCI image into a directory will do (for example `skopeo copy` followed by `umoci unpack`). Run the same two checks afterwards.

## Installing runsc

These commands come from the [gVisor install guide](https://gvisor.dev/docs/user_guide/install/) (checked 2026-11-25). The release tarball holds `runsc`, `containerd-shim-runsc-v1` and a `gvisor-bin/` directory of sidecar binaries. Keep `gvisor-bin/` next to `runsc` if you move it.

Latest release:

```sh
(
  set -e
  ARCH=$(uname -m)
  URL=https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}
  wget ${URL}/gvisor.tar.zstd ${URL}/gvisor.tar.zstd.sha512
  sha512sum -c gvisor.tar.zstd.sha512
  sudo tar --zstd -xf gvisor.tar.zstd -C /usr/local/bin
  rm -f gvisor.tar.zstd gvisor.tar.zstd.sha512
)
```

Pin a release instead of tracking `latest`. The guide's URL forms are `.../release/${yyyymmdd}/${ARCH}` for a release and `.../release/${yyyymmdd}.${rc}/${ARCH}` for a point release. The flags Kritolith uses were last checked against `20261102.0`, which is also what `make sandbox-test` installs:

```sh
URL=https://storage.googleapis.com/gvisor/releases/release/20261102.0/${ARCH}
```

If `zstd` is not installed, the guide offers `gvisor.tar.bz2` (and its `.sha512`) instead. The checksum is fetched from the same bucket over HTTPS. It catches a corrupt download, not a compromised bucket. Check `runsc --version` afterwards.

Kritolith passes `runsc` only fixed flags: `--root=<work_dir>/runsc-state`, `--platform=systrap`, `--network=none` (or `--network=sandbox` for the fetch phase, which always runs in a fetch bridge namespace), and `--ignore-cgroups` when configured. It never uses `--network=host`, `runsc do` or the Docker socket.

## Config keys

The `sandbox` section of `kritolith.json`. The sandbox is off until `rootfs` is set.

| Key | Default | Meaning |
|---|---|---|
| `rootfs` | (none) | Absolute path of the Go rootfs. Setting it turns the sandbox on. |
| `runtime` | `runsc` | Runtime binary, looked up on `PATH`. |
| `goproxy` | `https://proxy.golang.org` | The only module proxy the fetch phase uses. Exactly one URL: no list (`,` `\|`), no `direct`, no `off`, no userinfo, query or fragment. `https://`, or `http://` only to a loopback host. The fetch container reaches it only through the fetch bridge's forwarder, which runs on the host, so a loopback proxy works. |
| `fetch_timeout_seconds` | 900 | Wall clock for `go mod download`. A large module graph takes several minutes behind the fetch bridge. The forwarder still limits a single upstream request to 10 minutes (600 seconds), which is shorter than this phase limit, so one very slow download fails before the phase does. |
| `build_timeout_seconds` | 900 | Wall clock for the build. A cold `-race` build compiles the standard library plus the repository under gVisor, because each run has its own build cache, and that takes several minutes. |
| `run_timeout_seconds` | 120 | Wall clock for running the PoC. Go's own `-test.timeout` is set to 90% of it, so a hang still prints a goroutine dump. |
| `memory_mb` | 2048 | cgroup memory limit per container. `-race` and `-cover` are memory hungry. |
| `cpus` | 2 | cgroup CPU quota. The CPU-time rlimit is `timeout × cpus + 10` seconds. |
| `pids` | 512 | cgroup pids limit, and `RLIMIT_NPROC`. |
| `output_limit_kb` | 1024 | Combined stdout+stderr kept per phase. The rest is read and dropped, so the writer never blocks. |
| `work_dir` | `<data_dir>-sandbox` | Holds bundles, `runsc` state, per-run scratch trees and `fetch-bridges/` (one marker file per live fetch bridge). It must be a directory of its own: Kritolith uses it only if it is new, empty, or already carries the `.kritolith-workdir` marker (0600) that Kritolith writes there at first use, and refuses any other directory (so never point it at a shared parent such as `/var/lib`). It must not be, contain or lie inside the data dir, and the rootfs must not be, contain or lie inside it. It is created 0700, must be owned by the Kritolith user, and is refused if it is a symlink, group/world writable, or has an ancestor that is a symlink, owned by another non-root user, or group/world writable without the sticky bit. One live Kritolith process per work dir (flock). Startup removes leftovers older than the process, and only the names Kritolith creates (`kritolith-<digits>` bundles, `kritolith-run-<digits>` scratch trees). A tree is left for the next start while a container that may still write into it could be running: `runsc` is missing, `runsc list` fails, the container's delete fails, or it is still listed afterwards. Read-only trees are removed with directory fds opened `O_NOFOLLOW`, so a directory swapped for a symlink is never chmodded or removed through the link. |
| `ignore_cgroups` | `false` | Runs `runsc --ignore-cgroups`: memory, CPU and pids limits are **not** enforced. Only for a nested dev setup (runsc inside a container). Kritolith warns at startup and adds a note to every repro result. rlimits and the wall clock still apply. |

Example:

```json
"sandbox": {
  "rootfs": "/var/lib/kritolith-rootfs/go1.26.0",
  "work_dir": "/var/lib/kritolith-sandbox",
  "run_timeout_seconds": 120,
  "memory_mb": 2048,
  "cpus": 2
}
```

## What is and is not isolated

What the sandbox does:

- **Kernel boundary.** The PoC talks to gVisor's user-space kernel, not to the host kernel. gVisor is not a microVM: it still uses a small set of host syscalls, and a gVisor bug is a host bug. Every layer below exists because of that.
- **No network in build and run.** Those phases run with `--network=none`. Only the fetch phase has a network, and the PoC is not in the container then: it is copied in for the build.
- **Fetch egress reaches the forwarder and nothing else.** See [Fetch egress](#fetch-egress). The fetch phase runs only `go mod download`, with `GOPROXY` set to the bridge's forwarder, `GOTOOLCHAIN=local`, `GOFLAGS=-mod=mod -modcacherw` and the checksum database at its default. `go mod download` runs no module code. A hostile `go.mod` can make it download arbitrary modules from the proxy (checksums still apply). A `go.mod` with a `toolchain` line, or a `replace` to a local path outside the module, is refused before any container starts.
- **Filesystem.** The rootfs is read-only. In the run phase the source tree and the built binary are read-only, and the only writable places are a size-capped tmpfs `/tmp` and an output directory for the coverage profile. Each phase gets a fresh scratch tree, which is removed afterwards. Source extraction never carries a symlink out of the tree.
- **Never mounted.** The data directory (database, signing key, mirrors, logs), any path under `/etc`, `/run`, `/var/run`, `/proc`, `/sys` and `/dev`, `/` itself, and anything named `docker.sock`. Symlinks are resolved before the check.
- **Process.** The environment is empty apart from a fixed `PATH`, `HOME`, `TMPDIR` and the Go variables above. No host variable is passed through, not even to `runsc` itself. Every capability is dropped and `no_new_privs` is set. The process runs as an unprivileged user. `/dev` holds only `null`, `zero`, `urandom` and `tty`.
- **Limits.** rlimits on CPU time, file size, open files and processes are always applied. cgroup limits on memory, CPU and pids apply when cgroups are usable. The host kills the whole container at the wall clock, on cancellation and on every error path, then force-deletes it. A container that cannot be deleted makes the run `INCONCLUSIVE` and is retried. Output is capped. The run phase's only writable host directory, `/out` (where the coverage profile goes), is a host tmpfs Kritolith mounts for that one run: 8 MiB and 1024 files at most, `nosuid,nodev,noexec`, owned by the container user. It is unmounted right after the run, once the profile is read, and the startup sweep unmounts any a crash left. `RLIMIT_FSIZE` alone bounds only each file, so without it a PoC could fill the host disk with 256 MiB files. If the mount fails, the run does not start and the result is `INCONCLUSIVE`.

What it does not do, or does not do yet:

- **A hostile PoC controls its own output, so it can forge `REPRODUCED`.** Reproduction is read from what the PoC's process prints (panic and race stacks), from the coverage profile it writes, and from the HEAD control. The PoC can print a fake panic trace that names the claimed function. It can write a fake coverage profile. It can read the source tree and behave differently at the claimed commit than at HEAD. A deliberate adversary can therefore make a report read `REPRODUCED` or `REPRODUCED_FIXED_AT_HEAD`. This is an accepted limitation of v1: no channel exists that hostile code inside the container cannot write to. It works in one direction only. It can make a report look stronger, and it can never get a real report rejected, because a sandbox failure of any kind is `INCONCLUSIVE` and the sandbox never produces `GROUNDING_FAILED`. Read `REPRODUCED` as "the PoC produced evidence through the claimed code". A human still reads the PoC before acting on it.
- **cgroup limits need a real Linux host.** Under `ignore_cgroups` (any nested setup), memory is bounded only by the outer host, and CPU and process count only by rlimits. The verdict notes say so.
- **OOM is not detected.** `runsc`'s exit status does not say why a container was SIGKILLed, so a memory-limit kill is reported as a run with no signal (`INCONCLUSIVE`), not as "out of memory".
- **runsc's own failures are ambiguous.** `runsc` exits 128 when it fails to start a container, which cannot be told apart from a contained `exit 128`. Both are `INCONCLUSIVE`.
- **Logs stay local.** Capped phase logs go to `<data_dir>/sandbox-logs/<report id>/` (0600) and are never put in the emailed bundle. The signed verdict carries each log's SHA-256. The logs have no retention limit yet.
- **Reports through `check --ghsa` and `serve` never reach the sandbox yet.** GitHub's advisory API returns no attachments, and code blocks in the report body are not run. `serve` therefore does not start the sandbox at all: it runs no startup sweep and does not take the work dir lock, so `check --poc` and `ingest --eml` can use the sandbox on the same host while `serve` runs. With a `sandbox` section in its config, `serve` prints one line at startup saying so.

## Fetch egress

The fetch phase needs the module proxy and must reach nothing else. runsc's `--network=sandbox` copies the interfaces and addresses of the network namespace the sandbox starts in, and a fresh namespace has only an unconfigured loopback, so the container needs a prepared namespace. For every fetch Kritolith builds a *fetch bridge*:

1. Two network namespaces, `kvc<id>` (the container's) and `kvb<id>` (the bridge's), where `<id>` is 8 hex digits from `crypto/rand`. A veth pair joins them, one end in each, never in the host's namespace. Both ends get an address in a random `169.254.X.Y/30` (`X` in 1..168, never 169; a block that overlaps a host address is skipped). Loopback and both ends are brought up. There is no default route, no IP forwarding, no NAT and no firewall rule: the container's namespace can reach the bridge namespace's address and nothing else.
2. An HTTP forwarder inside Kritolith. Its listening socket is created inside the bridge namespace (the thread switches in with `setns` for the socket call only); everything else it does, including connecting to the proxy, happens in the host's namespace. Keeping the host end out of the host's namespace means the container cannot reach host services bound to the wildcard address.
3. The fetch container joins `/run/netns/kvc<id>` (OCI `linux.namespaces`) and runs with `--network=sandbox`, with `GOPROXY=http://<bridge ip>:<port>`.

The forwarder has exactly two upstreams, both fixed: the configured `sandbox.goproxy`, and the Go checksum database `https://sum.golang.org` (a constant in the code, not configurable). go asks the proxy `/sumdb/sum.golang.org/supported` before it consults the checksum database; the forwarder answers that itself with 200, so go fetches lookups and tiles through `/sumdb/sum.golang.org/...` and never connects to the database directly. The forwarder relays those paths to `https://sum.golang.org` and every other path to the configured proxy; any other `/sumdb/<name>/` path is refused. This holds whatever proxy is configured. go checks the database's signed tree heads with its built-in key, so the relay cannot forge entries.

The forwarder relays `GET` and `HEAD` only, for origin-form paths (`/...`) with no `.` or `..` segment, no encoded dot, slash, backslash or NUL, no control bytes, and nothing `path.Clean` would change. The upstream URL is always one of the two fixed bases plus the request's path and query (for the checksum database, the path after `/sumdb/sum.golang.org`): `Host`, `X-Forwarded-*` and absolute-form targets cannot change it. Only `Accept`, `Accept-Encoding` and `User-Agent` are passed upstream. Each upstream request has a 10 minute limit, one response is capped at 512 MiB and one fetch at 2 GiB in total; a response over a cap cuts the connection rather than passing a short body. A redirect is followed only on the scheme and host the request was sent to, or to an `https` URL. A connection from any address other than the container's end of the pair is closed unread.

The bridge is torn down after the fetch on every path (success, error, cancellation, wall clock, panic): the forwarder stops, both namespaces are deleted, and the veth pair is deleted if it is still there. runsc takes the container namespace's addresses over when the sandbox starts, so a bridge serves exactly one container. A marker file per bridge in `<work_dir>/fetch-bridges/` lets the startup sweep remove the namespaces and links a crashed run left; only bridges with a marker in this work dir are touched.

`ip` is run by absolute path with fixed argument lists, an empty environment apart from a fixed `PATH`, and a 15 second limit per call. If Kritolith is not root, `ip` is missing, or any step fails, there is no bridge and the fetch ends `INCONCLUSIVE` with the reason. It is never a rejection.

What the bridge does not cover:

- **Other checksum databases.** Only `sum.golang.org` is relayed. A repository needing another `GOSUMDB` is not supported (the sandbox leaves `GOSUMDB` at its default).
- **Any proxy but the configured one.** Operators behind an outbound HTTP proxy: the forwarder ignores `HTTP_PROXY`/`HTTPS_PROXY`, so the configured `goproxy` must be reachable directly from the host.

## Running the integration tests

The tests behind the `sandbox` build tag drive a real `runsc`. They need Linux, `runsc` on `PATH` and `KRITOLITH_SANDBOX_ROOTFS`. Without any of these, every test skips and says why. Plain `go test ./...` does not compile them. The hostile programs live in `testdata/sandbox/` with a `.fixture` suffix so that no Go tool ever builds them outside the sandbox. Never build or run them on a host directly.

| Variable | Meaning |
|---|---|
| `KRITOLITH_SANDBOX_ROOTFS` | The rootfs directory (required). |
| `KRITOLITH_SANDBOX_CGROUPS=1` | The host lets runsc configure cgroups. Otherwise the tests run with `--ignore-cgroups` and the cgroup-only cases (memory bomb, memory limit probe) skip. |
| `KRITOLITH_SANDBOX_INTERNET=1` | Also probe fetch-phase egress to `https://proxy.golang.org`. |

**On a real Linux host** (the full suite, including cgroup limits), as root:

```sh
sudo KRITOLITH_SANDBOX_ROOTFS=/var/lib/kritolith-rootfs/go1.26.0 KRITOLITH_SANDBOX_CGROUPS=1 \
  KRITOLITH_SANDBOX_INTERNET=1 go test -tags sandbox -count=1 -v -timeout 90m ./internal/sandbox
```

**In Docker** (any OS with Docker, including Docker Desktop):

```sh
make sandbox-rootfs   # once: exports the Go image into the docker volume kritolith-sandbox-rootfs and checks go and gcc
make sandbox-test
```

`make sandbox-test` starts a **privileged** container (`docker run --rm --privileged`). runsc needs privileges inside Docker to create its own namespaces and its gofer, which an unprivileged container cannot grant. The container uses the pinned `golang:1.26.0-bookworm` image. It installs runsc `20261102.0` with the download and `sha512sum -c` steps above, mounts the repository read-only at `/repo` and the rootfs volume read-only at `/rootfs`, and runs `go test -tags sandbox ./internal/sandbox`. The host Docker socket is not mounted into it. Docker caps it with `--memory` and `--pids-limit`, which also bound the hostile fixtures, since cgroups are ignored inside. Because it is privileged, running it is the owner's decision. Nothing in Kritolith's automation runs it.

What the tests cover:

- `TestSandboxBenignPoCNotReproduced`: a passing test PoC ends `NOT_REPRODUCED`.
- `TestSandboxPanicInClaimedCodeReproduced`: a panic through the claimed function, against a small git repository built in the test, ends `REPRODUCED`.
- `TestSandboxPanicFixedAtHead`: the same PoC with HEAD fixed ends `REPRODUCED_FIXED_AT_HEAD`.
- `TestSandboxHostileFixtures`: one subtest per directory in `testdata/sandbox/hostile/` (fork bomb, memory bomb, infinite loop, output flood, 256 MiB files written to `/out` until a write fails, network attempt, reading `/proc`, host paths and the environment, writing to the source tree, reading the data directory, symlinks out of the tree, `go.mod` with a host `replace` or a `toolchain` line, `os.Exit(1)` only, a panic outside claimed code). Each must end `INCONCLUSIVE` or `NEEDS_INFO`, never as a reproduction, within its time bounds. After each one, the test checks that:
  - a canary file outside the sandbox is unchanged;
  - the data dir key and the origin repository are unchanged;
  - no host HTTP listener was hit;
  - neither the host's canary environment variable nor any host secret appears in any log;
  - output stayed under the cap;
  - no `kritolith-*` bundle, scratch dir, mount, runsc container or runsc process is left.
- `TestSandboxRunOutIsCapped`: the `/out` flood stops at the 8 MiB cap, the coverage profile still comes back, and no mount is left.
- `TestSandboxHostilePoCNames`: PoC file names with `..`, absolute paths, separators or NUL end `NEEDS_INFO`, and no container runs.
- `TestProbe*`: the runsc facts listed below.

## First run checklist

Earlier tasks took these from the gVisor documentation and could not check them on a real runsc. Each has a tagged test. The first real run must pass all of them, or the code must be fixed before the sandbox is trusted. Every `TestProbe*` below passed on runsc 20261102.0, Ubuntu 24.04 arm64, on 2026-11-25, and again on 2026-11-26 after the security-review fixes.

- [x] `TestProbeDevContents`: `/dev` holds `null`, `zero`, `urandom`, `tty` and runsc's own links (`fd`, `stdin`, `stdout`, `stderr`, `pts`, `ptmx`, `shm`), and nothing else (OCI `linux.devices` honoured). Passed on runsc 20261102.0, Ubuntu 24.04 arm64, 2026-11-25; re-run 2026-11-26.
- [x] `TestProbeRlimits`: `RLIMIT_CPU`, `RLIMIT_FSIZE`, `RLIMIT_NOFILE` and `RLIMIT_NPROC` from the OCI config are in force inside the sandbox. Passed on runsc 20261102.0, Ubuntu 24.04 arm64, 2026-11-25; re-run 2026-11-26.
- [x] `TestProbeMountPointsInReadOnlyRootfs`: the mount points `/src`, `/work/modcache`, `/work/gocache`, `/out` and `/poc`, which the read-only rootfs does not have, are created. The rootfs and read-only binds refuse writes. Writable binds take them, and a file written there lands on the host owned by the container user (through the gofer). Passed on runsc 20261102.0, Ubuntu 24.04 arm64, 2026-11-25; re-run 2026-11-26.
- [x] `TestProbeUser`: the container runs as the Runner's uid/gid (65534 when Kritolith runs as root). Passed on runsc 20261102.0, Ubuntu 24.04 arm64, 2026-11-25; re-run 2026-11-26.
- [x] `TestProbeGoOnPath`: `go` resolves through the container `PATH`, `gcc` is in the rootfs, and `-race` is used. Passed on runsc 20261102.0, Ubuntu 24.04 arm64, 2026-11-25; re-run 2026-11-26.
- [x] `TestProbeExitStatus`: contained exit codes come back unchanged, and a signal comes back as 128+n. The test also logs what a runsc start failure looks like (the exit-128 ambiguity). Passed on runsc 20261102.0, Ubuntu 24.04 arm64, 2026-11-25; re-run 2026-11-26.
- [x] `TestProbeWallClockKillLeavesNothing`: after a wall-clock kill, no sandbox or gofer process, runsc container, state entry or bundle remains. Passed on runsc 20261102.0, Ubuntu 24.04 arm64, 2026-11-25; re-run 2026-11-26.
- [x] `TestProbeCancelDuringCreate`: a run cancelled at any point, including while runsc is still creating the sandbox, leaves nothing behind. Passed on runsc 20261102.0, Ubuntu 24.04 arm64, 2026-11-25; re-run 2026-11-26.
- [x] `TestProbeRunscGlobalFlagsAccepted`: `kill`, `delete --force` and `list` accept the global flags (`--root`, `--platform`, `--network`, `--ignore-cgroups`), and `delete --force` of a missing container succeeds. Passed on runsc 20261102.0, Ubuntu 24.04 arm64, 2026-11-25; re-run 2026-11-26.
- [x] `TestProbeLongWorkDir`: a long work dir path stays within runsc's socket path limits. Passed on runsc 20261102.0, Ubuntu 24.04 arm64, 2026-11-25; re-run 2026-11-26.
- [x] `TestProbeNoNetworkInBuildAndRun`: with `--network=none`, nothing is reachable: not a host listener on loopback, not one on a host address, not a public address. Passed on runsc 20261102.0, Ubuntu 24.04 arm64, 2026-11-25; re-run 2026-11-26.
- [x] `TestProbeLoopbackProxyInFetchNetns`: an `http://127.0.0.1` GOPROXY (which config accepts) is reached through the fetch bridge's forwarder, and `go mod download` of a module without dependencies succeeds behind the bridge. It also logs the container namespace after the run (runsc has removed its addresses). Passed on runsc 20261102.0, Ubuntu 24.04 arm64, 2026-11-25. The first real run, before the bridge, found that a fresh namespace has no usable network at all (even loopback was unreachable), which is why the bridge exists.
- [x] `TestProbeFetchEgressToProxy` (`KRITOLITH_SANDBOX_INTERNET=1`): through the bridge the fetch phase reaches `https://proxy.golang.org`, and `go mod download` of a module with dependencies (`rsc.io/quote` v1.5.2 and its two dependencies) succeeds both with a complete `go.sum` and without one. Without `go.sum`, go consults the checksum database through the forwarder's `/sumdb/sum.golang.org/` relay (`proxy.golang.org` itself answers 404 to `/sumdb/sum.golang.org/supported`, so without the relay go would connect to `sum.golang.org` directly, which the bridge does not allow). Passed on the same host.
- [x] `TestProbeFetchBridgeReachesNothingElse`: from inside the fetch container, host loopback ports, `localhost`, `1.1.1.1`, `https://proxy.golang.org`, `169.254.169.254`, every host interface address (on a wildcard-bound host listener's port and on 22), and the bridge's host IP on any port but the forwarder's are all unreachable, and no host listener sees a connection. The forwarder itself answers, in the same container, so the result is not vacuous. Passed on the same host.
- [x] `TestProbeSweepRemovesFetchBridges`: a bridge left by a crashed run is removed (namespaces, links and marker) by the startup sweep. Passed on the same host.
- [x] `TestProbeCgroupMemoryLimit` (`KRITOLITH_SANDBOX_CGROUPS=1`): the memory limit kills an allocator. The test logs its exit status, which shows whether an OOM kill can be recognised. Passed on runsc 20261102.0, Ubuntu 24.04 arm64, 2026-11-25; re-run 2026-11-26.
- [ ] `TestSandboxHostileFixtures`, `TestSandboxHostilePoCNames`, and the benign and reproduction tests: all pass. Also note which signal fires for `go-2023-2328` when `kritolith eval` runs on the configured host (its expectation relies on the race signal).
