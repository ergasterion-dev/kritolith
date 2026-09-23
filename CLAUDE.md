# CLAUDE.md — Kritolith

Kritolith verifies incoming security vulnerability reports before a maintainer reads them. It checks every concrete claim in a report against the actual code, reproduces the PoC in a locked-down sandbox, flags duplicates, and produces a signed evidence verdict. Humans make every decision; Kritolith only gathers evidence.

- Repo: `github.com/ergasterion-dev/kritolith`
- Module path: `kritolith.dev/kritolith` (vanity import, never the GitHub path)
- License: Apache-2.0
- Status: pre-alpha. Do not run on real embargoed reports until sandbox hardening lands.

---

## Scope (v1)

In scope:
- Go projects only
- Intake: GitHub private vulnerability reporting (PVR), piped `.eml` files, local file/CLI
- Grounding against git at the claimed commit
- Dedupe against past reports and a local OSV mirror
- Sandbox reproduction with gVisor, no network during build and run
- Pluggable LLM layer, local-first
- Signed evidence verdicts
- Eval corpus and scoreboard

Out of scope for v1 (do not build):
- Languages other than Go
- HackerOne / Bugcrowd integrations
- IMAP client (use `.eml` piping)
- LLM exploitability judgment of any kind
- CSAF / VEX / CRA reporting
- Web dashboard UI
- Multi-tenant hosted service

---

## Non-negotiable principles

1. **Deterministic checks are the authority.** The LLM extracts and drafts. It never decides a verdict. Everything it extracts is re-verified against git or the sandbox.
2. **Never wrongly reject a real report.** A false `GROUNDING_FAILED` on a real vulnerability is the worst possible bug. When unsure, return `INCONCLUSIVE`.
3. **Local-first LLMs.** Reports are embargoed, unfixed vulnerabilities. Cloud providers are an explicit per-project opt-in, logged loudly on every call.
4. **Everything from a report is hostile input.** Report text, PoC code, attachments. Expect prompt injection and sandbox escape attempts.
5. **Minimal dependencies.** Standard library first. No vendor SDKs. See Dependency policy.
6. **Single static binary.** `kritolith serve` on one Linux box with gVisor installed.

---

## Architecture

Modular monolith, one binary, subcommands. Pipeline:

```
intake (github PVR webhook | ingest --eml | check file)
  → extract (deterministic first, LLM fills gaps → strict JSON)
  → ground  (git at claimed ref + go/parser lookups; continue on partial failure)
  → dedupe  (fingerprint + embeddings vs past reports + OSV mirror)
  → sandbox (gVisor: fetch → build (no net) → run (no net))
  → verdict (compose → sign ed25519 → deliver)
```

The pipeline runs as an in-process job queue (goroutine workers backed by a `jobs` table). No external queue.

## Repo layout

```
cmd/kritolith/            main.go, subcommand wiring
internal/
  config/                 load + validate kritolith.json
  report/                 Report, Claim, Verdict types (core model)
  intake/{github,eml,file}/
  ghapp/                  GitHub App auth (own RS256 JWT, installation tokens)
  extract/{deterministic,llmextract}/
  ground/                 git ops (shell out to git), go/parser lookups
  dedupe/                 fingerprints, embeddings, OSV mirror
  sandbox/                runsc driver, phases, limits, result capture
  verdict/                compose, render (markdown), sign, verify
  llm/                    provider.go + {openaicompat,anthropic,gemini,router}/
  store/                  SQLite schema, migrations, queries
  jobs/                   in-process queue and workers
  eval/                   corpus runner and scoreboard
testdata/corpus/{real,fabricated}/
docs/{architecture.md,threat-model.md}
site/                     vanity import page for kritolith.dev
Makefile
kritolith.example.json
```

---

## Data model (`internal/report`)

Keep types boring and explicit.

```go
type Report struct {
    ID         string    // ulid, self-generated
    Source     Source    // github_pvr | eml | file
    SourceRef  string    // GHSA id, message-id, or file path
    Repo       string    // owner/name
    ClaimedRef string    // commit sha or tag the reporter tested
    Title      string
    Body       string    // raw text, never trusted
    PoC        []Artifact
    ReceivedAt time.Time
}

type Claim struct {
    Kind     ClaimKind // file | function | line | version | vuln_class | sink
    Value    string
    Source   string    // "deterministic" or "llm:<model>"
    Verified Tri       // yes | no | unknown
    Evidence string    // what we found (or didn't) and where
}

type Verdict struct {
    ReportID   string
    Outcome    Outcome
    Claims     []Claim
    Duplicates []DupMatch
    Repro      *ReproResult
    DraftReply string // LLM-drafted, clearly marked as draft
    Signature  []byte
    SignedAt   time.Time
}
```

Outcomes (exactly these in v1):
- `REPRODUCED` — PoC triggered the claimed behavior at the claimed ref
- `REPRODUCED_FIXED_AT_HEAD` — reproduces at claimed ref, not at HEAD
- `NOT_REPRODUCED` — PoC ran cleanly, behavior not observed
- `GROUNDING_FAILED` — a hard claim (file, function) provably doesn't exist at the claimed ref
- `LIKELY_DUPLICATE` — high-confidence match to an earlier report or published advisory
- `NEEDS_INFO` — no runnable PoC or no identifiable ref
- `INCONCLUSIVE` — build failure, timeout, sandbox error, or anything ambiguous

Precedence: `GROUNDING_FAILED` only on a *hard* claim failure, never on a line number alone (lines drift). `LIKELY_DUPLICATE` is reported alongside a repro result, not instead of it.

Storage: SQLite, single file, `0600`. Tables: `reports`, `claims`, `verdicts`, `jobs`, `embeddings` (vector as blob), `osv_entries`, `projects`.

---

## Pipeline stages

### Intake
- **GitHub PVR.** GitHub App subscribed to `repository_advisory`. A new private report fires action `reported` (the other is `published`). Needs read on "Repository security advisories". Fetch with `GET /repos/{owner}/{repo}/security-advisories/{ghsa_id}` (installation tokens supported). Confirm `state: triage` on a live test repo.
- **Email.** `kritolith ingest --eml < message.eml`, parsed with `net/mail` + `mime/multipart`.
- **File.** `kritolith check --repo owner/name --ref <sha> report.md [--poc dir/]`. The eval corpus runs through this path.

### Extract
1. **Deterministic:** regex/structure parsing for file paths, `pkg.Func` / `Type.Method`, `file.go:123`, versions, commit SHAs, fenced code blocks (candidate PoCs).
2. **LLM** (optional): strict JSON matching the Claim schema. Decode with `DisallowUnknownFields`, validate every field, drop anything malformed. No tools; output is data, never instructions.

Deterministic claims win on conflict.

### Ground
- Shell out to `git`. Bare mirror per project under the data dir, fetched on demand.
- Resolve `ClaimedRef`; fall back to tags matching claimed versions. Nothing resolves → at most `NEEDS_INFO`.
- Per claim: file exists? function/method declared (`go/parser` + `go/ast`)? line exists and sits inside the claimed function (soft claim)? sink/vuln_class recorded only.
- Record evidence for every check, e.g. "`parseHeader` not declared in package `http2` at a3f9c1; closest match `parseHeaders` in frame.go".

### Dedupe
- Fingerprint = normalized (repo, package, function, vuln_class). Exact match → strong signal.
- Embedding similarity over title + body via the `embed` task, brute-force cosine.
- Local OSV mirror for Go, refreshed daily from the bulk export. Match on module + symbol.
- Output top 3 matches with scores. `LIKELY_DUPLICATE` threshold is tuned on the corpus.

### Sandbox
See Sandbox spec below. Run the PoC at `ClaimedRef`; if it reproduces, run again at HEAD.

### Verdict
- Compose, render markdown, canonical JSON for signing.
- Sign with ed25519 (`crypto/ed25519`), key at `0600` under the data dir (`kritolith keygen`).
- Evidence bundle = `verdict.json` + sandbox logs + grounding evidence, tarred, detached signature. `kritolith verify-bundle` checks it.
- Deliver by email to configured maintainers and always write to the local store. There is no GitHub API to comment on an advisory, so never write verdicts into the advisory itself.

Verdict style, short and factual:

```
Kritolith: GROUNDING_FAILED at a3f9c1
• function http2.parseHeader — not found (closest: parseHeaders, frame.go:412)
• file internal/hpack/decode.go — found
PoC not run: grounding failed on a hard claim.
Evidence bundle: sha256:… (signed)
```

---

## LLM layer

```go
type Provider interface {
    Complete(ctx context.Context, req CompleteRequest) (CompleteResponse, error)
    Embed(ctx context.Context, texts []string) ([][]float32, error)
    Name() string
    IsLocal() bool
}
```

Adapters, plain `net/http`, zero SDKs: `openaicompat` (Ollama, llama.cpp, vLLM, LM Studio, OpenAI), `anthropic` (Messages API), `gemini`.

Router: each task (`extract`, `embed`, `draft`) has an ordered chain; fall through on timeout, schema failure, or error. Providers with `IsLocal() == false` are skipped unless the project has `allow_cloud: true`, and every cloud call logs a warning with the report ID. v1 tasks: `extract`, `embed`, `draft` only.

Config is `kritolith.json` (JSON keeps us on the standard library):

```json
{
  "data_dir": "/var/lib/kritolith",
  "projects": [
    { "repo": "owner/name", "allow_cloud": false, "notify": ["sec@example.org"] }
  ],
  "llm": {
    "providers": {
      "local-big":   { "type": "openaicompat", "base_url": "http://127.0.0.1:11434/v1", "model": "<32b coder model>" },
      "local-small": { "type": "openaicompat", "base_url": "http://127.0.0.1:11434/v1", "model": "<8b model>" },
      "local-embed": { "type": "openaicompat", "base_url": "http://127.0.0.1:11434/v1", "model": "<embedding model>" },
      "claude":      { "type": "anthropic", "api_key_env": "ANTHROPIC_API_KEY", "model": "<model id>" }
    },
    "tasks": {
      "extract": ["local-big", "local-small"],
      "embed":   ["local-embed"],
      "draft":   ["local-small", "claude"]
    }
  },
  "sandbox": { "runtime": "runsc", "run_timeout_seconds": 120, "memory_mb": 2048, "cpus": 2 }
}
```

Kritolith must run fully with **no LLM configured** (deterministic extraction only).

---

## Sandbox spec

Runtime: gVisor (`runsc`), chosen because it runs on any Linux host or Kubernetes node without KVM. Isolation is weaker than a microVM, so every layer below matters. gVisor is Linux-only; sandbox work needs a Linux host.

Phases:
1. **Fetch.** Copy source at the ref into a scratch dir. `go mod download` with egress only to the configured Go module proxy.
2. **Build.** No network. `GOFLAGS=-mod=mod`, `GOPROXY=off`, module cache read-only. `-race` when the PoC is a test.
3. **Run.** No network. Read-only source, writable tmp only. Wall-clock timeout, memory cap, CPU cap, PID limit, output size cap.

Accepted PoC shapes: a `_test.go` dropped into the claimed package (`go test -run <TestName> -race`), a `main` package program, or an input file for an existing fuzz target. Anything else → `NEEDS_INFO`.

Reproduced signals:
- panic with a stack through the claimed function
- race detector report touching the claimed code
- test failure whose output matches the report's stated behavior
- resource blowup far above a control run with benign input (DoS claims)

Every repro is also run at HEAD as a control.

Never: mount the Docker socket, pass through host env vars, mount the signing key or GitHub App key, allow network in build or run.

Check the exact `runsc` flags (network-none, resource limits) against the gVisor docs for the installed version. Don't copy flags from memory.

---

## Threat model (summary)

- **Hostile PoC:** escape, resource exhaustion, fork bombs, huge output → gVisor + limits + no network.
- **Prompt injection:** LLM has no tools, output is schema-bound data, everything re-verified deterministically.
- **Kritolith as a target:** crafted reports seeking fake `REPRODUCED` → repro requires the claimed function in the stack/race output, not just any crash.
- **Embargo leaks:** local-first LLMs, per-project cloud opt-in, SQLite `0600`, no report content in logs above debug, no telemetry.
- **Key theft:** signing key and App private key never enter a sandbox, `0600`, separate from data files.

---

## Eval corpus

```
testdata/corpus/
  real/<id>/        report.md, meta.json, poc/
  fabricated/<id>/  report.md, meta.json, poc/ (optional)
```

- `real/`: published Go advisories with PoCs (GHSA / Go vuln DB). `meta.json` holds repo, ref, expected outcome.
- `fabricated/`: hand-written reports with invented functions, wrong files, fake PoCs, near-duplicates, and hostile sandbox tests.
- **Never** put content from real embargoed reports here.

`make eval` runs everything through `kritolith check` and prints a scoreboard. v1 targets:
- Zero `GROUNDING_FAILED` on real reports (hard requirement)
- Grounding catches ≥80% of fabricated reports citing fake code
- ≥60% of real reports with runnable PoCs reach `REPRODUCED` or `REPRODUCED_FIXED_AT_HEAD`
- Duplicate top-1 accuracy ≥80% on the near-duplicate set

---

## Dependency policy

Allowed:
- Go standard library (`net/http` with Go 1.22+ routing; no web frameworks)
- `modernc.org/sqlite` (pure Go, no cgo) — the only third-party library in v1

Runtime prerequisites (not linked): `git`, `runsc`, `go` toolchain.

Anything else needs a written justification in `docs/architecture.md` before it's added. No vendor SDKs.

---

## Milestones

1. Skeleton: scaffold, Makefile, GitHub Actions CI (vet, test, race), report types, SQLite schema, `kritolith check` stub end to end (outputs `INCONCLUSIVE`), first corpus items.
2. Extraction + LLM layer: deterministic extractor, providers, router, cloud gating, LLM extractor.
3. Grounding: git mirrors, ref resolution, go/parser lookups, evidence strings.
4. Dedupe: fingerprints, embeddings, OSV mirror + refresh, threshold tuning.
5. Sandbox: runsc driver, phases, limits, PoC shapes, signal detection, HEAD control, hardening tests.
6. Verdicts + delivery: composition, rendering, signing, bundles, `verify-bundle`, email delivery, `.eml` intake, draft replies.
7. Hardening: public threat model, README, install docs (incl. CPU-only LLM profile), install script.

Each milestone is done only when its eval targets pass on the corpus.

---

## Commands

```
kritolith serve                         # webhook server + workers
kritolith check --repo o/n --ref <sha> report.md [--poc dir]
kritolith ingest --eml < msg.eml
kritolith eval                          # corpus scoreboard
kritolith keygen                        # ed25519 signing key
kritolith verify-bundle <bundle.tar>
kritolith osv sync                      # refresh local OSV mirror
```

No short alias: `krit` is taken by an existing Go static analysis tool.

---

## Conventions

- Wrap errors with context (`fmt.Errorf("ground: resolve ref %s: %w", ref, err)`); never swallow them
- `log/slog` structured logs; report content only at debug level
- Table-driven tests in every package; sandbox tests behind a build tag (they need runsc)
- No global state; pass dependencies explicitly
- Conventional commits (`feat(ground): …`)
- Public API is the CLI and the config file. `internal/` can change freely until v1.0
