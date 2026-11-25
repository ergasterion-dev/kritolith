# Sandbox (Milestone 5) — design

Date: 2026-11-25. Status: draft for approval. Binding context: repo `CLAUDE.md` ("Sandbox spec"), `docs/threat-model.md`.

## Intent and why

Today every real report ends `INCONCLUSIVE`, because nothing runs the PoC. The sandbox is the stage that runs a reporter's proof of concept at the claimed commit, in a place where hostile code can do no harm, and says what happened. It is what makes `REPRODUCED`, `REPRODUCED_FIXED_AT_HEAD` and `NOT_REPRODUCED` possible, and so it is what turns Kritolith from a claim checker into a first-pass triage tool. Humans still decide; the sandbox only adds evidence.

Success: on the eval corpus, at least 60% of the 20 real reports with a runnable PoC end `REPRODUCED` or `REPRODUCED_FIXED_AT_HEAD` (all 20 are expected `REPRODUCED_FIXED_AT_HEAD`), with the two "must be 0" lines still 0, and every hostile fixture contained.

## Goals

- Run a PoC at the resolved ref with no network in build and run, read-only source, hard limits on time, memory, CPU, processes and output.
- Recognise reproduction by deterministic signals tied to the claimed code, not by any crash.
- Run the same PoC at HEAD as a control after a reproduction.
- Slot into the existing pipeline without changing what the earlier stages decide.
- Work without an LLM and without a container runtime when no PoC exists (all current behaviour is unchanged).

## Non-goals

- Languages other than Go. PoC shapes beyond the three below.
- Running anything on a Windows or macOS host (gVisor is Linux only; those hosts keep today's behaviour, and the sandbox stage reports itself unavailable).
- A microVM. gVisor's isolation is weaker; the layers below compensate and the threat model says so.
- Judging exploitability or severity.
- Making fabricated reports look worse. The sandbox adds `REPRODUCED` evidence; it never rejects.

## Anti-goals (failures even if it "works")

- A crafted report that earns `REPRODUCED` with a PoC that merely crashes or prints a string.
- Any path by which report text, a PoC, or a hostile `go.mod` reaches the host: the Docker socket, the signing key, the GitHub token, host environment, the data directory.
- A real report downgraded to a rejection. A sandbox failure of any kind (runtime missing, build error, timeout, odd output) is `INCONCLUSIVE`, never `GROUNDING_FAILED` and never `NOT_REPRODUCED`.

## Constraints

- Standard library only (the one third-party module stays `modernc.org/sqlite`). `runsc` and a Go toolchain rootfs are runtime prerequisites, not linked code.
- Sandbox integration tests sit behind a `sandbox` build tag; everything else must run in plain `go test ./...` on any OS.
- Exact `runsc` flags are copied from the gVisor documentation for the installed version, never from memory. Verified so far (2026-11-11, release-20261102.0, linux/arm64, in a privileged container on Docker Desktop): `--network=none`, `--platform=systrap`, `--ignore-cgroups`. Cgroup limits cannot be tested in that nested setup.

## Approaches considered

**How the PoC is isolated and where the toolchain comes from**

1. **OCI bundle with an operator-provided rootfs (chosen).** `runsc run` on a generated OCI config; rootfs is an exported Go image directory named in config (`sandbox.rootfs`), mounted read-only. Reproducible, toolchain is explicit and versioned, nothing of the host is visible. Cost: operator exports an image once; docs give the exact recipe.
2. `runsc do`. Exposes the host filesystem read-only, including the data directory and signing key. Rejected outright.
3. Bind-mount the host's GOROOT into a minimal rootfs. Less setup, but ties results to whatever Go the host has, mixes host files into the sandbox, and cgo/race needs a C toolchain the host may lack. Rejected.

**Fetch-phase egress (the spec says "only to the configured Go module proxy")**

1. **Network on for the fetch phase only, restricted by tool configuration (chosen).** The fetch phase runs only `go mod download` with `GOPROXY=<configured proxy>` (no `direct`), `GOTOOLCHAIN=local`, `GOFLAGS=-mod=mod`, `GONOSUMDB`/`GOFLAGS` left default so the checksum database applies. `go mod download` runs no code from the modules. The PoC is not in the sandbox yet: it is copied in only for the build phase, which has no network. This is a restriction by configuration, not by the network, and the threat model says so plainly.
2. Real egress filter (nftables allow-list on a netns). Strictly stronger, but needs root and distro-specific setup for a "single binary" tool. Left as a later hardening option; the design does not preclude it.
3. Download dependencies on the host. Puts the Go tool on the host with hostile `go.mod` input. Rejected.

**Race detector.** `-race` needs cgo and a C compiler. Using the official golang image as rootfs includes gcc on amd64 and arm64, so the default is available; if it is missing the PoC is built without `-race` and the verdict note says so. To be verified on both architectures in the first plan task.

## Design

### Parts

```
internal/sandbox/
  runner.go      Runner: Run(ctx, Request) (Result, error). The one type the pipeline sees.
  driver.go      driver interface: run one command in a fresh runsc container, return exit, output, resource facts.
  runsc.go       driver using `runsc run` and a generated OCI bundle (build tag-free; shells out).
  oci.go         pure function: Request -> OCI config JSON. Unit tested everywhere.
  poc.go         PoC shape detection, placement, validation of names and sizes.
  phases.go      fetch -> build -> run, then the control run.
  signals.go     parse test/panic/race output into signals; pure, unit tested everywhere.
  sandbox_test.go (+ sandbox-tagged tests)
```

`Runner` is configured from the `sandbox` section of `kritolith.json` (now parsed instead of kept raw): `runtime` (default `runsc`), `rootfs` (required to enable), `goproxy` (default `https://proxy.golang.org`), `run_timeout_seconds` (default 120), `build_timeout_seconds` (default 300), `fetch_timeout_seconds` (default 300), `memory_mb` (default 2048; `-race` and `-cover` are memory hungry), `cpus` (default 2), `pids` (default 512), `output_limit_kb` (default 1024). Missing `rootfs` or a non-Linux host means "sandbox not configured": the stage is skipped and the verdict note says why, exactly like today.

### Phases for one run at one ref

1. **Prepare (host).** `git archive` the ref from the existing mirror into a fresh scratch directory (mode 0700, outside the data directory's keys and database). Validate the PoC (below). Create a per-run module cache directory.
2. **Fetch (container, network on).** Source mounted writable only for this phase; no PoC present. Command: `go mod download`. Environment is built from scratch (no host variables). Limits apply. Output captured.
3. **Build (container, no network).** PoC copied into its package directory; module cache read-only; a writable build cache and output directory. Command: `go test -c [-race] [-cover -coverpkg=<pkg>] -o <bin>` for a test PoC, `go build -o <bin>` for a `main` program. `GOPROXY=off`, `GOFLAGS=-mod=mod` (spec), `GOTOOLCHAIN=local`, `CGO_ENABLED` only when `-race` is on. A repository that needs a newer Go than the rootfs provides stops here as `INCONCLUSIVE` with the reason.
4. **Run (container, no network).** Source read-only, tmp writable and size-capped, working directory is the package directory (as `go test` does). Command: the built test binary with `-test.run '^<name>$' -test.timeout <limit>`, or the built program. Wall-clock timeout enforced by the host as well as by Go.
5. **Control.** Only after a reproduction: repeat steps 1 to 4 at the repository's default-branch HEAD. A fresh container, fresh scratch directory, fresh module cache.

Every container is created, run and destroyed per phase; none is reused. Output from each phase is read through a size cap and kept (capped) as evidence.

### Container profile (all phases)

- Root filesystem read-only; the only writable paths are named tmpfs/scratch mounts with size caps.
- No network (`--network=none`) except the fetch phase.
- Empty environment plus the few Go variables above; no host variables, no secrets, no Docker socket, never the data directory, key files or token.
- Unprivileged user inside the container, all capabilities dropped, no new privileges, minimal `/proc` and no `/dev` beyond null, zero, urandom, tty.
- Limits as OCI `process.rlimits` (CPU time, file size, open files, processes) plus cgroup limits (memory, CPU, PIDs) where cgroups are usable. Where they are not (the dev setup above), rlimits and the wall-clock kill still apply, and the fact that cgroup limits were not in force is recorded in the result.
- Host-side wall-clock kill of the whole container, then its removal, on every exit path including host cancellation and crashes (a startup sweep removes orphaned containers and scratch dirs owned by this tool).
- Output is read through a cap and truncated; the verdict never embeds raw PoC output (it goes through `report.Printable` like all report-derived text).

### PoC shapes

| Shape | How it is recognised | How it is run |
|---|---|---|
| Test | one or more `_test.go` files, `package X` or `X_test` | dropped into the target package directory, `-test.run` on the test function names declared in it |
| Program | a single `package main` with `func main` | built in a scratch subdirectory of the module (`cmd/kritolith-poc`) so imports resolve; run once |
| Fuzz input | a file under `testdata/fuzz/<FuzzName>/` matching an existing fuzz target in the claimed package | `-test.run '^FuzzName$/<seed>'` |

Anything else, an empty PoC, more than 64 files, a file over 256 KiB, a path with `..` or an absolute path, a non-regular file, or a name that is not a plain file name: `NEEDS_INFO`, with the reason. Names are sanitised by the existing intake code and re-checked here; the sandbox trusts nothing it is handed.

**Module and working directory.** The unit is the nearest `go.mod` above the target directory (go-2024-3279's PoC sits in `math/`, its own module inside a larger repository). All phases run with that module root as working directory, `GOWORK=off`, and the `replace`/`toolchain` checks read that `go.mod`. `go mod download` runs only there.

**Fuzz inputs** are the one case where a PoC file name may contain a path: exactly `testdata/fuzz/<FuzzName>/<seed>` with plain-name components, validated separately from the plain-file-name rule above.

**Package placement** is deterministic and never taken from free text. The target directory is, in order: an operator-supplied `--poc-dir` (also read from a new `poc_dir` field in corpus `meta.json`, which replaces the "PoC dir:" sentence in the notes), then the directory of a verified function or file claim whose directory holds Go files of the PoC's package name, then the single directory in the repository holding that package name. Zero or more than one candidate means `NEEDS_INFO`. The directory is validated to be inside the source tree.

### Reproduced signals

A run is `reproduced` only for one of these, all deterministic, all recorded in `ReproResult.Signal`:

1. **panic-in-claimed-code** — the run panicked or hit a fatal runtime error and the stack contains a frame whose function matches a claimed function (or a function in a claimed file).
2. **race-in-claimed-code** — the race detector reported and a stack frame in the report is in a claimed function or file.
3. **failing-test-reaching-claimed-code** — a test PoC failed, and the coverage profile shows a statement of the claimed function executed (or, with only a file claim, a statement in that file). This is what the existing corpus PoCs rely on (they assert on behaviour and fail with a message, not a stack). It is weaker than 1 and 2: a PoC that calls the function and then calls `t.Fatal` meets it. The signal name says which kind it is, the verdict text says so, and the control run is what separates fixed code from always-failing code.
Resource-blowup (a limit hit, compared with a benign control) is **not in this milestone**: no corpus PoC exercises it and a benign input cannot be derived in general. A DoS PoC still reproduces through signals 1 to 3 when it panics, overflows the stack or fails an assertion (all 20 corpus PoCs are of that kind). A run that only hits a limit is `INCONCLUSIVE` with that reason.

**Which claims a signal may match** (the anti-forgery boundary, decided here): only claims with `Verified: yes` whose declaring file is inside the repository's own module, from either source (an LLM claim is already kept only if it appears verbatim in the report). A claim grounding could not verify, or that names a standard-library or dependency function, never counts, so a report that claims `json.Unmarshal` plus any panic reproduces nothing. Frames inside the PoC's own files are excluded. The coverage scope (`-coverpkg`) is the set of packages declaring the matched claims, which may differ from the PoC's package (go-2022-0300: PoC in `graphql_test`, claimed code in `internal/validation`).

**Signal 3 alone is not enough for `REPRODUCED`** (decided here, to keep the first anti-goal): an assertion-only failure at the ref gives `REPRODUCED_FIXED_AT_HEAD` when the same PoC passes at HEAD. If it also fails at HEAD, the outcome is `INCONCLUSIVE` with the note "the PoC also fails at HEAD, and an assertion-only failure cannot be told from a test that always fails". Signals 1 and 2 (a panic or race through the claimed code) give `REPRODUCED` whether or not HEAD is fixed.

A crash, timeout, `os.Exit(non-zero)` or killed process with none of the above is `INCONCLUSIVE` with the reason, not a reproduction. Compile errors and missing symbols are `INCONCLUSIVE` ("PoC does not build at this ref").

### Outcomes and where it plugs in

- `pipeline.Pipeline` gains `WithSandbox(sandbox.Runner)` (nil = skipped, as for the other stages).
- It runs only when grounding did not hard-fail (a hard-claim failure through a fallback version also does not run it; that stays `INCONCLUSIVE` as today), a ref resolved, and there is a runnable PoC.
- **PoC sources are explicit only:** files given with `--poc`, `.eml` attachments, and the corpus `poc/` directories. Fenced code blocks in the report body are **not** run in this milestone (`ghsa-9pmm-cxww-rrr7` carries a stub test in its text that must end `NEEDS_INFO`). GitHub's advisory API returns no attachments, so reports taken through `check --ghsa` and `serve` never reach the sandbox yet; running body code blocks is a separate, later decision.
- **No runnable PoC → `NEEDS_INFO`** (matches the `CLAUDE.md` definition and the four no-PoC real corpus cases). Today such reports end `INCONCLUSIVE`; this milestone changes that, and the commit that does so reports the scoreboard.
- `verdict.StageResults` gains `SandboxRan`, `Repro` (and its control). `Compose` precedence, highest first: no ref / unresolved ref → `NEEDS_INFO` (unchanged); hard grounding failure → `GROUNDING_FAILED` (unchanged; PoC not run, noted); reproduced at the ref and not at HEAD → `REPRODUCED_FIXED_AT_HEAD`; reproduced at the ref and at HEAD → `REPRODUCED`; ran to completion with exit 0 at the exact claimed commit → `NOT_REPRODUCED`; anything else → `INCONCLUSIVE`. A reproduction outranks `LIKELY_DUPLICATE`, which is then listed alongside it; an exact duplicate outranks `NOT_REPRODUCED` and `INCONCLUSIVE`, as today.
- **The control that cannot run.** If the PoC does not build at HEAD (renamed symbols, a new module path such as `go-2024-3250`'s v5, a v3 rewrite such as `go-2023-2328`), the control is "unavailable", not "fixed": the outcome is `REPRODUCED` with the note "could not be re-run at HEAD; whether it is fixed is unknown". The control does not re-ground claims; it places the PoC at the same relative directory and reports unavailable if that is gone. `go-2023-2328`'s corpus expectation changes to `REPRODUCED` (its `meta.json` already says its PoC does not compile at HEAD). The 60% target counts both reproduction outcomes.
- **HEAD means the remote default branch.** The mirror's `HEAD` symref is not refreshed by `fetch --prune`, so the control resolves the default branch from the remote (`git ls-remote --symref`) rather than trusting the mirror's `HEAD`.
- When the ref was resolved through a fallback version, the PoC still runs, but `NOT_REPRODUCED` is downgraded to `INCONCLUSIVE` (the version may simply be wrong). A reproduction through a fallback is reported as such in the note.
- The "sandbox stage is not implemented yet" note goes away. `report.ReproResult` is extended with `Control *ReproResult`, `Phase` and `Limits` facts (JSON keys additive, so old bundles still verify).
- The signed verdict covers the repro result, including the SHA-256 of each capped phase log. The logs themselves stay in the local store and are **not** put in the emailed bundle: PoC output is reporter-controlled and may echo embargoed detail, and `ReadBundle` rejects unknown entries, so the bundle format does not change and bundles already issued still verify. New verdict fields are additive.

## What is decided versus left to the builder

Decided here: isolation approach, rootfs, fetch egress, phases, container profile, PoC shapes, placement rule, signals, outcome precedence, config keys and defaults.

Left to the builder: exact `runsc` and OCI config fields (from the docs for the installed version, verified by test), how scratch and cache directories are laid out, the internal driver interface, retry and error-text wording, and how the evidence bundle names its sandbox files.

## Testing

- Unit tests everywhere: OCI config generation (assert no host path leaks, no network, correct mounts and limits), PoC validation and placement, signal parsing from golden outputs (panics, races, test failures, coverage profiles), phase orchestration against a fake driver (including every failure path ending in `INCONCLUSIVE`, never a rejection).
- Fuzz targets for the signal parser and PoC validator, like the other parsers of hostile input.
- `sandbox`-tagged integration tests (need Linux and `runsc`): a benign test PoC, each corpus PoC, and hostile fixtures in `testdata/sandbox/hostile/` (test inputs, not scored `eval` cases, so the scoreboard denominators do not change): fork bomb, memory bomb, infinite loop, output flood, network attempt (must fail), read of `/proc`, host paths and environment (must be empty), write to the source tree (must fail), reading the data directory path (must not exist), symlink and `..` file names, a `go.mod` with `replace` to a host path or a `toolchain` line, a PoC that only calls `os.Exit(1)` or panics outside claimed code (must not reproduce).
- Dev loop: `make sandbox-test` runs the tagged tests in a privileged Linux container (needs your approval for `docker run --privileged`). Cgroup-limit tests run on a real Linux host and are marked so; CI keeps `-tags sandbox` off until a runner with `runsc` exists.
- Acceptance: `kritolith eval` on a Linux host with the sandbox configured reports the real-with-PoC reproduction rate; target 60% or more. The scoreboard gains that line.

## Threat-model additions (to write with the code)

`docs/threat-model.md` currently says a crash counts only if the claimed function is in the stack or race report; `CLAUDE.md` also lists "test failure whose output matches the report's stated behavior". This design replaces the second with the coverage-tied signal 3 and the HEAD-control rule above; the threat model is updated in the same change, and the `CLAUDE.md` sandbox section is reworded to match.

State plainly: fetch-phase egress is restricted by tool configuration, not by the network; gVisor shares the host kernel's risk profile for a small set of syscalls and is not a microVM; a `go mod download` of a hostile `go.mod` can fetch arbitrary modules from the proxy (checksum database applies) but executes none; the dev-container testing gap for cgroups.

## Out of scope for this milestone

Shared module cache across runs (per-run only; slower, safer), a real egress filter, GitHub App auth, Windows/macOS host support, non-Go PoCs.

## Addendum (2026-11-25): the fetch bridge

The first run on a real runsc (20261102.0, Ubuntu 24.04 arm64) showed that the chosen fetch egress approach cannot work as written: the fetch container's fresh network namespace has no usable network at all (even `127.0.0.1` is unreachable and DNS fails), so `go mod download` reaches no proxy.

The fetch phase now runs behind a per-fetch *fetch bridge*, which supersedes "restricted by tool configuration only" above. Kritolith, as root, creates a container network namespace and a bridge namespace joined by a veth pair with link-local `/30` addresses and no route anywhere else. An in-process HTTP forwarder listens inside the bridge namespace and relays `GET`/`HEAD` requests, from the host's namespace, to two fixed upstreams: the configured proxy for module paths, and `https://sum.golang.org` (a constant, not configurable) for `/sumdb/sum.golang.org/...`. The forwarder answers go's `/sumdb/sum.golang.org/supported` probe itself, because `proxy.golang.org` does not proxy the checksum database and go would otherwise connect to it directly. go verifies the database's signatures, so the relay cannot forge entries. The fetch container joins the container namespace (OCI `linux.namespaces` with a path) and runs with `--network=sandbox` and `GOPROXY` set to the forwarder. The sandbox therefore has network reach to the forwarder and nothing else; this was checked from inside a fetch container against host loopback, host interface addresses, a public address, the metadata address and other ports of the bridge address.

Consequences: the sandbox needs root and iproute2 (without them, fetch ends `INCONCLUSIVE`); build and run are unchanged (`--network=none`); a configured loopback proxy works because the forwarder runs on the host. Only the default checksum database (`sum.golang.org`) is relayed. Details are in `docs/sandbox.md`, "Fetch egress".
