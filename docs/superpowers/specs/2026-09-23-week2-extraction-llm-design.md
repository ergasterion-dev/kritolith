# Design: Week 2 — Claim Extraction + LLM Layer

Status: approved for planning
Owner: cipherprofessor
Written: 2026-09-23

## 1. Goal

Turn a `report.Report`'s free-text body into structured, checkable
`report.Claim`s, deterministically first and optionally with an LLM,
without changing any verdict outcome yet (that's Week 3, grounding).
Everything the LLM extracts is data, never trusted, and is re-verified
later. Kritolith must work identically with zero LLM configured.

This design also resolves the carry-forward items from Week 1's review
that block on extraction touching report text or on `verdict.Compose`'s
signature (see `kritolith-week1-carry-forward` memory, items 1–5).

## 2. Non-negotiables carried in from CLAUDE.md

- Deterministic checks decide; the LLM only extracts and drafts.
- Deterministic claims win over LLM claims on conflict.
- The LLM gets no tools; its output is strict-JSON data, never
  instructions, decoded with `DisallowUnknownFields` and validated
  field by field.
- Cloud LLM providers are opt-in per project (`allow_cloud`) and every
  cloud call is logged loudly (a `slog` warning with the report ID,
  never body content above debug).
- Standard library plus `net/http`; no vendor SDKs for any provider.
- No new third-party dependency without written justification in
  `docs/architecture.md`.

## 3. Packages

```
internal/extract/deterministic/   regex/structure parsing, pure functions
internal/extract/llmextract/      LLM-backed extraction, depends on internal/llm
internal/llm/                     Provider interface, router
internal/llm/openaicompat/        Ollama, llama.cpp, vLLM, LM Studio, OpenAI
internal/llm/anthropic/           native Messages API
internal/llm/gemini/              native generateContent/embedContent API
```

### 3.1 `internal/extract/deterministic`

Pure functions over `report.Body` (and fenced code blocks within it)
producing `[]report.Claim` with `Source: "deterministic"`:

- file paths (e.g. `internal/hpack/decode.go`)
- `pkg.Func`, `Type.Method`, `(*Type).Method` identifiers
- `file.go:123` line references
- version strings (`v1.2.3`)
- commit SHAs (7–40 hex chars)
- fenced code blocks, recorded as candidate PoC artifacts (not yet
  written to disk — that stays the intake layer's job)
- a vuln-class guess from a small keyword table, best-effort only

Rules:

- No panics on any input. A `FuzzExtract` fuzz test with a seed corpus
  covering ANSI escapes, bidi overrides, huge input, deeply nested
  markdown/code fences, and null bytes.
- A cap on matches per claim kind (bound the work; hostile input must
  not produce unbounded claim counts).
- Table-driven unit tests are the primary spec; the fuzz test is a
  safety net, not the main test strategy.

### 3.2 `internal/llm`

```go
type Provider interface {
    Complete(ctx context.Context, req CompleteRequest) (CompleteResponse, error)
    Embed(ctx context.Context, texts []string) ([][]float32, error)
    Name() string
    IsLocal() bool
}
```

**IsLocal rule (resolved):** computed at config-load time from the
provider's `base_url`, never from a flag. A provider is local iff its
base_url host resolves to loopback (`127.0.0.1`, `::1`), an
RFC1918/link-local address, or the literal hostname `localhost` (or a
`.local` suffix). This applies to `openaicompat` only, since its
base_url is operator-configured. `anthropic` and `gemini` adapters
report `IsLocal() == false` unconditionally — their base URLs are
fixed public endpoints. No adapter trusts an operator-supplied "local"
flag; a report's confidentiality must not depend on a config typo.

**Adapters**, plain `net/http`, zero SDKs. Verify every request/response
shape from live docs (`context7` / WebFetch, not memory) before coding:
Anthropic Messages API, Gemini `generateContent`/`embedContent`, OpenAI
chat completions and embeddings (also covers Ollama/llama.cpp/vLLM/LM
Studio, which speak the OpenAI-compatible shape). Each adapter gets
`httptest.NewServer`-backed tests asserting exact request shape (path,
headers, JSON body) for: success, timeout, 429/5xx, malformed JSON,
and a schema violation that must cause router fall-through. No test
calls a real network API.

**Router:**

- One ordered provider chain per task: `extract`, `embed`, `draft`.
- Falls through to the next provider in the chain on timeout, error,
  or schema-validation failure.
- Skips any provider with `IsLocal() == false` unless the report's
  project has `allow_cloud: true`.
- Every call to a non-local provider logs a `slog` warning carrying
  the report ID.
- Chain exhausted → the caller proceeds without that task's output
  (extraction falls back to deterministic-only; draft is simply
  omitted). This is not an error condition.

**Config parsing:** `config.Config.LLM` (currently `json.RawMessage`)
becomes a typed, strictly-validated structure:

```go
type Config struct {
    Providers map[string]ProviderConfig `json:"providers"`
    Tasks     map[string][]string       `json:"tasks"` // task -> ordered provider names
}

type ProviderConfig struct {
    Type       string `json:"type"` // "openaicompat" | "anthropic" | "gemini"
    BaseURL    string `json:"base_url"`
    Model      string `json:"model"`
    APIKeyEnv  string `json:"api_key_env,omitempty"` // env var name; never a literal key
}
```

Validation: `base_url` must be an absolute `http(s)` URL; `type` must
be one of the three known adapters; every provider name referenced in
`tasks` must exist in `providers`; `api_key_env`, if set, only names
the environment variable to read at call time — the config loader
never reads or stores the key itself. Record the final `IsLocal`
derivation rule in `docs/architecture.md` (CLAUDE.md's Week 2 scope
explicitly asks for this).

### 3.3 `internal/extract/llmextract`

- One prompt, strict JSON output matching the `report.Claim` schema
  (plus whatever bounded metadata the model needs to produce, e.g. a
  claim-kind enum string).
- Decode with `DisallowUnknownFields`; validate every field (`Kind`
  must be a known `report.ClaimKind`, `Value` non-empty and bounded in
  length, etc.); drop any claim that fails validation rather than
  erroring the whole extraction.
- Every claim gets `Source: "llm:<model name>"`.
- Nothing this package produces changes a verdict outcome in Week 2 —
  outcomes stay `NEEDS_INFO`/`INCONCLUSIVE`. Week 3's grounding stage
  is what starts consuming claims for real.

## 4. Wiring changes

### 4.1 `verdict.Compose` signature (resolved)

```go
type StageResults struct {
    Claims []report.Claim
}

func Compose(r report.Report, res StageResults) report.Verdict
```

A simple typed struct, not a generic bag. Week 3 adds a `Grounding`
field, Week 4 a `Dedupe` field, Week 5/6 a `Repro` field — each is a
non-breaking additive change as long as call sites use named-field
struct literals (a lint/review concern, not a type-system one). This
signature change happens once, now, per the carry-forward note; later
weeks widen the struct, not the function signature.

Week 2's `Compose` logic itself is unchanged: it still only decides
between `NEEDS_INFO` (no ref) and `INCONCLUSIVE` (otherwise), but now
stores `res.Claims` onto the returned `Verdict.Claims`.

### 4.2 `pipeline.Run`

New sequence: save report → deterministic extract (always runs) → LLM
extract (only when a router is configured for the pipeline) → merge
(deterministic claims win on `(Kind, Value)` conflict with an LLM
claim) → `verdict.Compose(r, StageResults{Claims: merged})` → save
verdict.

`Pipeline` gains an optional extractor dependency (interface, so it's
a no-op/nil-safe path when no LLM is configured — deterministic
extraction always runs regardless). Distinct error prefixes per
carry-forward item 3: `pipeline: save report: %w` vs
`pipeline: save verdict: %w` vs a new `pipeline: extract: %w` (though
per the "never wrongly reject" principle, an extraction error should
degrade to deterministic-only claims and a note, not abort the
pipeline — only a save failure aborts).

### 4.3 CLI (`check`, `eval`)

- Both already accept `--config`; `eval` gains it too if not present
  (carry-forward item 4), so extraction and LLM routing run over the
  corpus.
- When a config is loaded and has `projects` entries, `--repo` must
  match one of them (carry-forward item 5) — needed so the
  `allow_cloud` lookup has something to key off. No config loaded →
  no such restriction (matches today's `check`-without-config path).

### 4.4 JSON output sanitization (carry-forward item 1)

Once `Claim.Value`, `Claim.Evidence`, or `Verdict.DraftReply` can carry
report-derived text, `check --json` must not leak raw hostile text.
`encoding/json` escapes C0 controls but not U+202E and other bidi
override characters. Pass every report-derived string field through
`report.Printable` before it's placed on the `Claim`/`Verdict` struct
that gets marshaled — i.e. sanitize at extraction time, not by adding
a bespoke JSON output path. Add a test with a bidi override character
inside a claim value, asserting the emitted JSON doesn't contain it
unsanitized.

## 5. Testing strategy

- **Deterministic extractor:** table-driven unit tests per claim kind,
  plus `FuzzExtract` (30s local run per the handoff's manual-test
  section; CI runs only the seed corpus).
- **LLM adapters:** `httptest.NewServer` fakes, one test file per
  adapter, covering the five cases in §3.2. No real network calls in
  any automated test.
- **Router:** a test proving `allow_cloud=false` skips every
  non-local provider in a chain and falls through correctly; a test
  proving a cloud call logs a warning with the report ID.
- **llmextract:** malformed/extra-field JSON is dropped, not fatal;
  a valid claim round-trips with the right `Source` tag.
- **Pipeline:** merge behavior (deterministic wins on conflict);
  pipeline succeeds with no LLM configured.
- **Eval:** add a scoreboard column (or a dedicated test) reporting
  deterministic-extraction hit rate on named file/function claims
  across all 40 corpus cases, run both with and without a stub LLM
  provider. This gives Week 3 a grounding baseline to improve on.
- **Security-focused cases**, per report CLAUDE.md's threat model:
  hostile report text (ANSI, bidi, huge input, deeply nested
  markdown), prompt injection text that must not change extraction
  semantics beyond producing ordinary (and validated) data, and LLM
  responses with unknown/extra/wrong-typed fields that must be
  dropped rather than crashing extraction.

## 6. Out of scope for Week 2

- Grounding, dedupe, sandbox — claims are stored but not yet verified
  against git or reproduced. Outcomes remain `NEEDS_INFO`/
  `INCONCLUSIVE` only.
- `report.ValidateRef` tightening (Week 3 item, since it only matters
  once grounding shells out to git).
- PoC-walk caps, `os.Root` sandbox writes, eval ctx cancellation
  (Week 5/6 items).
- `kritolith serve`, `ingest --eml`, GitHub App auth, jobs/worker
  queue — unbuilt, unrelated to this milestone.

## 7. Acceptance (from the handoff, restated)

- Extraction runs on all 40 corpus cases, with and without an LLM
  configured; claims are stored.
- `make ci` green locally and on `main`; no new third-party
  dependencies.
- Deterministic extraction finds at least the named file and function
  claims in every fabricated `GROUNDING_FAILED` case, and in most real
  cases (reported via the new eval column/test).
- `allow_cloud=false` provably blocks cloud providers (router test);
  every cloud call logs the report ID.
- No report text reaches the terminal or logs unsanitized, including
  `check --json`.

## 8. Repo-specific execution notes

This repo is exempt from the global no-GitHub-Actions and
no-direct-to-main rules (`kritolith-global-rules-override` memory):
GitHub Actions CI stays, and work lands on `main` directly, no
branches or PRs. Every dispatch prompt to a subagent must say so
explicitly, since subagents otherwise default to the global rule.
Commits are DCO-signed, conventional-commit style
(`git commit -s -m "feat(extract): …"`), and go through the global
quality-gate hook (gofmt/vet/build/test) — never `SKIP_GATE`.
