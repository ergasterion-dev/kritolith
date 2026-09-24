# Design: Week 3 — Grounding

Status: approved for planning
Owner: cipherprofessor
Written: 2026-09-23

## 1. Goal

Check every extracted claim against the actual code at the commit the
reporter claims to have tested, using git and `go/parser` — no network
LLM calls, no sandbox. This is the stage that starts changing verdict
outcomes: a report naming a file or function that doesn't exist at the
claimed ref becomes `GROUNDING_FAILED`; everything else stays
`INCONCLUSIVE`/`NEEDS_INFO` until dedupe (Week 4) and the sandbox
(Weeks 5–6) land.

## 2. Non-negotiables carried in from CLAUDE.md

- **Zero false `GROUNDING_FAILED` on real reports is a hard v1 target.**
  A false rejection of a real vulnerability is the worst possible bug
  (CLAUDE.md principle 2). When grounding can't be sure, the claim's
  `Verified` stays `unknown` and the outcome doesn't move to
  `GROUNDING_FAILED` on its account.
- `GROUNDING_FAILED` fires only on a **hard** claim (`file`,
  `function`) failing. A line-number mismatch alone (`line`, a soft
  claim) never causes it — lines drift between the reporter's copy and
  the actual commit.
- Deterministic checks decide; nothing here is an LLM call.
- Minimal dependencies: stdlib plus `net/http`/`os/exec` only. No
  `go/packages`, no `go-git`, nothing beyond what's already allowed.
- Every report-derived string that reaches evidence text or JSON
  output still goes through `report.Printable`.

## 3. Packages

```
internal/ground/          mirror management, ref resolution, claim grounding
```

### 3.1 `ground.Mirror`

One bare git mirror per repo, under
`<data_dir>/git-mirrors/<owner>/<repo>.git`. Bare mirrors, not working
copies — grounding never checks out a working tree (resolved
brainstorming decision: plumbing-only file access, no worktree
lifecycle to manage before Week 5's sandbox isolation exists).

```go
type Mirror struct {
    path string // <data_dir>/git-mirrors/<owner>/<repo>.git
    repo string // "owner/name", already validated by report.ValidateRepo
}

func OpenMirror(dataDir, repo string) (*Mirror, error)
```

`OpenMirror` only computes the path; it touches neither disk nor
network. All git operations run through `os/exec`, matching the
project's existing "shell out to git" pattern (no `go-git`).

**Ref resolution (fetch-if-missing, resolved brainstorming decision):**

```go
// EnsureAndResolve resolves ref to a full commit SHA. It clones the
// mirror on first use, tries to resolve locally first, and only
// fetches (once) if that fails or the mirror was just created. If ref
// itself never resolves, it tries each of fallbackVersions in order as
// a tag, with the same fetch-if-missing policy. resolved is false if
// nothing resolved at all.
func (m *Mirror) EnsureAndResolve(ctx context.Context, ref string, fallbackVersions []string) (commit string, resolved bool, err error)
```

Resolution always uses
`git rev-parse --verify --end-of-options <ref>^{commit}` (never a bare
`<ref>` passed to a git subcommand as a positional argument that could
be read as an option — this is the Week 1 carry-forward item, folded
in here since this is the first stage that shells out to git with a
ref argument).

**File access, plumbing only:**

```go
// FileExists reports whether path exists as a blob at commit.
func (m *Mirror) FileExists(ctx context.Context, commit, path string) (bool, error)

// ReadFile returns the blob content at commit:path. ok is false if the
// path doesn't exist (not an error).
func (m *Mirror) ReadFile(ctx context.Context, commit, path string) (content []byte, ok bool, err error)

// ListGoFiles returns every ".go" file path at commit, via a single
// `git ls-tree -r --name-only`, filtered client-side.
func (m *Mirror) ListGoFiles(ctx context.Context, commit string) ([]string, error)
```

`FileExists`/`ReadFile` use `git cat-file -e <commit>:<path>` and
`git show <commit>:<path>` respectively.

**Path validation (new hardening surface).** Deterministic extraction's
file-path regex (`[A-Za-z0-9_][A-Za-z0-9_./-]{0,200}\.go`) allows `.`
and `/`, so a claim value like `a/../../../etc/foo.go` is a legal
regex match even though it's a path-traversal shape. Grounding is the
first stage to feed a claim value into a real git command argument, so
every file-claim path is validated before use:

```go
// ValidateClaimPath rejects any path with a ".." component, mirroring
// report.ValidateRef's defensive posture for refs, applied to paths.
func ValidateClaimPath(path string) error
```

A path that fails validation is treated as a grounding failure for
that claim (`Verified: no`, `Evidence: "invalid path"`) — not a panic,
not a silently-skipped claim, and never passed to `git`.

### 3.2 Claim grounding

```go
// Ground checks r's claimed ref (with fallback to any ClaimVersion
// values already in claims) and grounds every file/function/line claim
// against the resolved commit. It returns the same claims with
// Verified and Evidence updated in place, plus whether a ref resolved
// at all and which commit it resolved to.
func Ground(ctx context.Context, m *Mirror, r report.Report, claims []report.Claim) (grounded []report.Claim, refResolved bool, resolvedCommit string, err error)
```

Per-kind behavior:

- **`file`**: `FileExists` at the resolved commit. `Verified: yes/no`,
  `Evidence`: `"file exists at <short-sha>"` /
  `"not found at <short-sha>"`.
- **`function`**: repo-wide search. Parse every `.go` file
  (`ListGoFiles` + `ReadFile` + `go/parser.ParseFile`) at the resolved
  commit; walk top-level `*ast.FuncDecl`s. A claim shaped `pkg.Func`
  matches on the `Func` part only (no import/package resolution — out
  of scope without `go/packages`); `(*Type).Method`/`Type.Method`
  match on receiver type name (pointer or value) plus method name. On
  no match, compute the closest declared name by edit distance for the
  evidence string, e.g.
  `"not declared in the repository at a3f9c1e; closest match: parseHeaders (internal/http2/frame.go:412)"`.
  This is honest about what was actually checked (syntax-level
  declaration, not full type-checked resolution) — it never claims
  "package" identity it didn't verify.

  **Amendment (Task 8b, after the first real-corpus run).** "No
  matching `FuncDecl`" is not by itself proof a claim is false: 13/20
  real reports hit `GROUNDING_FAILED` on claims like
  `protowire.ConsumeVarint` (a dependency's function the repo calls),
  `sync.Pool`, `URL.Scheme` (a field), `ChunkSize` (a struct field),
  `MaxBitLen` (a const) and `paddingLength` (a local). So a function
  claim that matches no declaration is `Verified: no` only when its
  absence is provable, and otherwise `unknown` with the reason in
  `Evidence`. Provable means the scan covered the whole tree, the name
  appears nowhere in the repo's source as an identifier (scanned with
  `go/scanner`, so unparseable files still count), and the claim is
  one of: `(*T).M` where `T` is a repo type with a closed method set
  (no embedding, not an alias, not defined from another named type);
  `pkg.name` with an unexported `name`, `pkg` a package declared in
  the repo, and no out-of-module import bound to `pkg`; or a bare
  unexported `name`. Qualified exported names and bare exported names
  are never disproved. A bare name also matches a method declaration.
  A `file` claim missing at its exact path is `unknown`, not `no`, if
  some file in the tree has that path as a suffix (`frame.go` for
  `http2/frame.go`).

  **Review round 1 additions.** A claim that passes every rule above is
  still only `no` if (1) its name is not a Go keyword or predeclared
  identifier (`token.IsKeyword`, `types.Universe`) and (2) the name is
  absent as a whole word from *all* tracked text at the commit
  (`git grep -q -w -F`: exit 1 is the only "absent"; any other result
  is treated as "can't prove"), so names that live only in string
  literals, struct tags, templates or JS files aren't disproved.
  `pkg.name` also stays `unknown` if any file uses `pkg.X` without an
  import that certainly binds `pkg` (an unaliased import whose last
  path element isn't exactly `pkg`, or a variable), and unaliased
  imports register every plausible package-name variant
  (`go-yaml` → `yaml`). A tree containing a submodule (gitlink, mode
  160000) counts as an incomplete scan. A missing `file` claim with a
  directory component is `unknown` unless that directory exists in the
  tree (`net/http/server.go`, module-cache stack-trace paths). Known
  accepted residual: a repo's own closed type sharing a name with
  another package's type (`(*Server).ServeTLS`).
- **`line`** (soft): checked when the claim's file exists and the
  parsed file's line count covers it; if a same-report `function`
  claim's declaration position is known, also checks the line falls
  inside that function's `FuncDecl` span. Never contributes to
  `GROUNDING_FAILED` regardless of its own `Verified` value.
- **`version`**, **`vuln_class`**, **`sink`**: not actively re-verified
  in Week 3 (per CLAUDE.md, `version` already did its job resolving
  the ref; `vuln_class`/`sink` are "recorded only" until later
  milestones). `Verified` stays whatever it already was
  (`unknown`, from extraction).

## 4. Wiring changes

### 4.1 `verdict.StageResults` (additive, per Week 2's design)

```go
type StageResults struct {
    Claims      []report.Claim
    RefResolved bool   // Week 3: did the claimed ref (or a fallback tag) resolve?
    ResolvedRef string // Week 3: the commit it resolved to, if RefResolved
    LLMUnavailable bool // Week 2, unchanged
}
```

### 4.2 `verdict.Compose` precedence

```
no ClaimedRef                              → NEEDS_INFO   (unchanged)
ClaimedRef given but !RefResolved          → NEEDS_INFO   (new)
any hard claim (file/function) Verified=no → GROUNDING_FAILED  (new)
otherwise                                  → INCONCLUSIVE (unchanged reason: dedupe/sandbox not implemented)
```

Every branch still **appends** to `Notes` (the Week 2 final-review fix
already made this an append, not an overwrite — Week 3 must not
regress that: an `LLMUnavailable` note and a grounding note can both
be present on the same verdict).

### 4.3 `pipeline.Run`

New sequence: save report → deterministic extract → LLM extract
(if configured) → merge → **ground** (open the repo's mirror, resolve
the ref, ground every claim) → `Compose(r, StageResults{...})` → save
verdict. Grounding runs unconditionally (no config gate) — it's pure
git/stdlib, nothing to opt in or out of. A grounding error (e.g. the
repo can't be cloned at all — network failure, private repo without
credentials) must not crash the pipeline: it degrades to
`RefResolved: false` and a note, same as "ref never resolved."

### 4.4 CLI / config

No new flags. `data_dir` (already configurable) is where
`git-mirrors/` lives.

## 5. Testing strategy

- **`Mirror`**: build a tiny real git repo in a `t.TempDir()` (a few
  commits, a tag, a couple of `.go` files) and mirror-clone from it —
  no network, no dependency on a real GitHub repo. Cover: first-use
  clone, cache hit (resolve without fetching — assert via a fetch
  counter or by making the "upstream" unreachable after the first
  clone and confirming a cache-hit resolve still works), fetch-on-miss
  (add a commit to the "upstream" after the mirror exists, confirm a
  second `EnsureAndResolve` for the new commit fetches and finds it),
  fallback-to-tag resolution, and "nothing resolves" (`resolved ==
  false`, no error).
- **Path validation**: table-driven, covering `..` in a middle
  component, a leading `../`, a trailing `/..`, and legitimate paths
  that must NOT be rejected (`internal/../internal/x.go` component-wise
  is still a `..` component and should be rejected even though it's
  "harmless" here — reject on shape, not on resolved intent).
- **Function/method grounding**: fixture `.go` files covering a plain
  function, a pointer-receiver method, a value-receiver method, a
  claim that doesn't exist (closest-match evidence produced), and a
  claim whose only match is in a different file than any `file` claim
  in the same report (proving the search is genuinely repo-wide, not
  restricted to claimed files).
- **Line grounding**: a claim whose line is inside/outside a known
  function's span; a claim whose file doesn't exist at all (line claim
  simply stays unverified, not an error).
- **`Compose`**: extend the existing table tests with the two new
  branches (`!RefResolved` → `NEEDS_INFO`; a hard claim `Verified: no`
  → `GROUNDING_FAILED`), and a regression test that a `line`-only
  failure with everything else fine does NOT produce
  `GROUNDING_FAILED`.
- **`pipeline.Run`**: a grounding error (mirror can't be reached)
  degrades to a verdict, not a pipeline failure.
- **Eval corpus — the real acceptance test.** `make eval` after this
  milestone needs real network access to actually clone the 20 real
  corpus repos (`golang/net`, `graph-gophers/graphql-go`, etc.) — this
  wasn't true before Week 3, since nothing shelled out to a real
  remote. Confirm `make eval` still runs in CI (the runner has network
  egress) and note in the plan that a fully offline dev environment
  will see grounding degrade to `NEEDS_INFO` for every case (not
  `GROUNDING_FAILED` — the fail-safe direction), never a hard failure.

## 6. Out of scope for Week 3

- Dedupe, OSV mirror, sandbox — untouched.
- Full type-checked / import-aware function resolution
  (`go/packages`) — explicitly out of the dependency budget; the
  syntax-level search here is honest about its limits in evidence text.
- `ValidateRef`'s other Week 1 carry-forward tightening (rejecting any
  path component starting with `.`, `.lock` on any component) — **in
  scope**, since this is exactly the milestone that starts shelling
  out to git with ref arguments for real.
- Any change to the jobs/worker queue — grounding runs synchronously
  inside `pipeline.Run`, same as every other stage so far; no
  concurrency model exists yet for mirrors to race over.

## 7. Acceptance

- `make eval`: **zero** real cases wrongly marked `GROUNDING_FAILED`
  (hard gate, unchanged from CLAUDE.md's stated v1 target).
- ≥80% of the 15 fabricated fake-code cases (fab-001 through fab-014,
  fab-020) now correctly reach `GROUNDING_FAILED`.
- `fab-018`/`fab-019` (no ref, no PoC) still reach `NEEDS_INFO`.
- `fab-015`/`016`/`017` (near-duplicates) are unaffected by grounding
  (dedupe is Week 4) — they should ground cleanly (real files/functions
  referenced) and land on `INCONCLUSIVE`, same as before.
- No claim value ever reaches a `git` subprocess argument without
  passing through ref/path validation first.
- `make ci` green; no new third-party dependencies.

## 8. Repo-specific execution notes

Same as Week 2: this repo commits directly to `main`
(`kritolith-global-rules-override` memory), GitHub Actions CI stays,
every commit is DCO-signed (`git commit -s`) with a conventional
subject, and the quality-gate hook runs on every commit
(never `SKIP_GATE`). Every subagent dispatch must carry the repo
exemption line explicitly, since subagents default to the global
no-main-commit rule otherwise.
