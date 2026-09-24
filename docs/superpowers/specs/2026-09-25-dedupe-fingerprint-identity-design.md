# Dedupe: Fingerprint on Resolved Declaration Identity (G-DEDUPE1)

Written: 2026-09-25
Status: approved by maintainer in conversation; implementing next.

## 0. Context

Milestone 4 (dedupe) is formally incomplete per `CLAUDE.md`'s own targets:
duplicate top-1 accuracy is 67% (2/3) against a ≥80% requirement. Full
background: `kritolith-personal-docs-never-to-push/2026-09-25_0009-IST_dedupe-fingerprint-hardening_handoff.md`
(§4, gap G-DEDUPE1) and the Week 4 dedupe design spec
(`docs/superpowers/specs/2026-09-24-week4-dedupe-design.md`).

**Root cause.** `internal/dedupe/fingerprint.go`'s `claimFingerprints`
keys a fingerprint on the *literal qualifier text* a reporter wrote
(`pkg.Func` → `qualifier="pkg"`), not on what grounding actually
resolved. This is simultaneously:

- **Too loose:** a claim naming a real stdlib/dependency function this
  repo doesn't declare still gets `Verified: yes` (`findDeclaration` in
  `internal/ground/ast.go` verifies a `pkg.Func`-shaped claim if *any*
  top-level function of that name exists anywhere in the repo, without
  checking `pkg` actually names the declaring package) and produces a
  fingerprint with that literal qualifier — two unrelated reports
  loosely mentioning the same qualified name with the same vuln_class
  could coincidentally fingerprint-match.
- **Too strict:** a genuinely unique, correctly-verified *bare*-name
  claim (e.g. `fab-017-near-duplicate`'s `isOriginAllowed`) is excluded
  entirely, because `claimFingerprints` drops any claim with an empty
  qualifier to avoid exactly the stdlib-collision risk above.

**The fix.** Fingerprint on the resolved declaration's own identity —
where grounding actually found it — gated by a uniqueness check: only
fingerprint when that identity is unambiguous in the repo. This fixes
both directions of the asymmetry with one change, and makes Gap G1's
same-named-type collision *visible* as "claim can't fingerprint" in the
dedupe path specifically (not a fix for G1 itself, which remains an
accepted residual risk for v1 per the `kritolith-g1-risk-accepted`
memory).

**Non-negotiable, symmetric across the whole pipeline** (`CLAUDE.md`
principle #2 and its Week 4 mirror): a false `LIKELY_DUPLICATE` is
exactly as bad as a false `GROUNDING_FAILED`. Every decision below is
biased toward "don't fingerprint" over "fingerprint on a guess."

## 1. Decisions carried in from maintainer sign-off (this conversation)

- Resolved-declaration identity is persisted via **new columns on the
  `claims` table** (a migration), not encoded into the free-text
  `Evidence` field and not re-derived by re-grounding prior reports at
  query time. Matches the data model's own "keep types boring and
  explicit" principle; additive migration, low risk.
- Identity tuple: **(repo, package dir, receiver, name, vuln_class)**.
  `package dir` is `path.Dir(declaration.file)`, repo-relative — never
  a resolved import path, since grounding has no import resolution
  (same disclosed limitation as G1).
- Uniqueness rule: a resolved declaration is **ambiguous iff its
  `(receiver, name)` pair matches more than one declaration anywhere in
  the repo**, regardless of which file/directory. Exactly one match
  anywhere means the identity is trusted, even for a bare/loosely
  qualified claim.
- `Grounder.Ground` gets a `GroundResult` struct now instead of a 6th
  positional return value, since every call site is already being
  touched for this change.
- G-DEDUPE2's scoreboard top-1-identity check is bundled into this same
  plan — it is the instrument that validates this fix; without it, a
  wrong-but-lucky duplicate match would still show green.
- G-DEDUPE2's `EmbeddingsByRepo` missing-exclusions fix is bundled in
  (same file, same pattern as `ClaimsByRepo`, already open for this
  change). Every other G-DEDUPE2 item (extractor keyword robustness,
  `osv sync` robustness, stale doc comments) stays out of scope — filed
  as follow-up, does not touch fingerprint/grounding code.

## 2. Grounding changes

### 2.1 `internal/ground/service.go`

`Grounder.Ground` returns a struct instead of 5 positional values:

```go
type GroundResult struct {
    Claims      []report.Claim
    RefResolved bool
    ResolvedRef string
    ViaFallback bool
    Module      string
}

type Grounder interface {
    Ground(ctx context.Context, r report.Report, claims []report.Claim) GroundResult
}
```

Every call site (`internal/pipeline/pipeline.go`, tests, `cmd/kritolith`)
switches from positional destructuring to field access. No behavior
change — this is a mechanical follow-through of the struct
introduction, done now specifically because the alternative (a 6th
positional return) would mean touching every call site a second time
later.

### 2.2 `internal/report/report.go`

`Claim` grows three fields, populated only for a `ClaimFunction` claim
that resolves to a declaration *and* that declaration is unique in the
repo:

```go
type Claim struct {
    Kind         ClaimKind
    Value        string
    Source       string
    Verified     Tri
    Evidence     string
    DeclPkgDir   string // path.Dir(declaration.file), repo-relative; empty if unresolved or ambiguous
    DeclReceiver string // resolved receiver type name; empty for a plain function (not ambiguity — legitimately no receiver)
    DeclName     string // resolved declaration name
}
```

### 2.3 `internal/ground/ast.go`

New function:

```go
// resolveUnique resolves value exactly as findDeclaration does (same
// precedence rules, so Verified/Evidence behavior is unchanged), then
// reports whether the resolved declaration's (name, receiver) pair is
// ambiguous: shared by more than one declaration anywhere in the repo.
func resolveUnique(decls []declaration, value string) (d *declaration, ambiguous bool) {
    d = findDeclaration(decls, value)
    if d == nil {
        return nil, false
    }
    count := 0
    for i := range decls {
        if decls[i].name == d.name && decls[i].receiver == d.receiver {
            count++
        }
    }
    return d, count > 1
}
```

`groundFunctionClaim` (in `ground.go`) calls `resolveUnique` instead of
`findDeclaration` directly. On a unique match: fill the three new
`Claim` fields (unchanged `Verified`/`Evidence` behavior otherwise). On
an ambiguous match: leave the three fields empty (claim stays
`Verified: yes` — ambiguity affects fingerprint eligibility only, never
groundedness) and append `" (ambiguous name, cannot fingerprint)"` to
`Evidence`, matching the existing convention of recording evidence for
every check.

### 2.4 Disclosed residual limitation

A `pkg.Func`-shaped claim can still resolve to *either* a plain
function *or* a method with receiver `pkg` — `findDeclaration` returns
the first match in slice order, which is arbitrary. This qualifier-
meaning ambiguity is pre-existing (same shape as G1) and this fix does
not add a check for it: the uniqueness check catches "two declarations
share the exact same resolved `(receiver, name)`", not "the claim could
plausibly have meant a different receiver". Out of scope for this pass;
not silently dropped — recorded here the way G1 itself is recorded.

## 3. Dedupe & storage changes

### 3.1 Migration

New file under `internal/store/migrations/`, additive only:

```sql
ALTER TABLE claims ADD COLUMN decl_pkg_dir  TEXT NOT NULL DEFAULT '';
ALTER TABLE claims ADD COLUMN decl_receiver TEXT NOT NULL DEFAULT '';
ALTER TABLE claims ADD COLUMN decl_name     TEXT NOT NULL DEFAULT '';
```

`store.go`'s claim-persistence path (wherever a verdict's claims are
inserted) and `ClaimsByRepo`'s `SELECT` both grow to carry the three new
columns alongside the existing `kind, value, source, verified,
evidence`.

### 3.2 `internal/dedupe/fingerprint.go`

```go
type fingerprint struct {
    repo, pkgDir, receiver, name, vulnClass string
}
```

`matches()` requires `repo`, `pkgDir`, `name`, `vulnClass` all
non-empty and equal; `receiver` must be equal too, but empty-vs-empty is
a legitimate match (both plain functions), not an exclusion —
unlike the old `qualifier` field, an empty `receiver` here means "no
receiver", never "unknown/ambiguous".

`claimFingerprints` reads `c.DeclPkgDir`/`c.DeclReceiver`/`c.DeclName`
directly instead of calling `ground.SplitFunctionClaim` on `c.Value`. A
claim only contributes a fingerprint when `DeclPkgDir != "" &&
DeclName != ""` — i.e. grounding resolved it uniquely. The current
bare-name exclusion (`qualifier == ""` → skip) is removed, replaced
entirely by the uniqueness check: a bare name that resolves to one
unambiguous declaration is now exactly as trustworthy as a qualified
one. Verify against `fingerprint_test.go` during implementation that
nothing else depended on that exclusion before deleting it.

### 3.3 `internal/store/store.go` — `EmbeddingsByRepo`

Gets the same two exclusions `ClaimsByRepo` already has: exclude the
report's own `SourceRef`, and exclude prior reports whose verdict
outcome was `GROUNDING_FAILED`/`NEEDS_INFO`/`LIKELY_DUPLICATE`.
Confirmed display-only today (cannot affect `Outcome` or eval's hard
gates) — this closes the gap for consistency, same file already open
for this change.

## 4. Scoreboard instrumentation (G-DEDUPE2)

Grounded in the actual `internal/eval` package as it exists today:
`eval.Meta` decodes with `DisallowUnknownFields`, but an *optional* new
field is safe (existing `meta.json` files without it decode to the zero
value). `eval.CheckFunc` currently discards everything except
`Outcome`. `Case.ID` (corpus directory name, e.g. `go-2024-2604`) is
distinct from the runtime `report.Report.ID` (a fresh ULID each run)
that actually shows up in a `DupMatch.ReportID`.

- `Meta` grows `ExpectedDuplicateOf string
  \`json:"expected_duplicate_of,omitempty"\`` — another case's corpus
  `ID`. `fab-015`, `fab-016`, `fab-017`'s `meta.json` each set this to
  their real near-duplicate target's case ID.
- `CheckFunc` returns a struct instead of a bare `report.Outcome` — same
  "avoid positional bloat" reasoning as `GroundResult`:
  ```go
  type CheckResult struct {
      Outcome    report.Outcome
      ReportID   string
      Duplicates []report.DupMatch
  }
  type CheckFunc func(ctx context.Context, c Case) (CheckResult, error)
  ```
- `eval.Run` keeps a `map[caseID]reportID` as it processes cases in
  order (`real/` before `fabricated/`, so a target case's `ReportID` is
  always already recorded by the time a case naming it as
  `ExpectedDuplicateOf` runs).
- New `Scoreboard.DuplicateTop1Accuracy() (correct, total int)`: for
  every result whose `Meta.ExpectedDuplicateOf != ""`, count it correct
  iff `len(Duplicates) > 0 && Duplicates[0].ReportID ==
  <recorded ReportID for that target case>`. New summary line in
  `Write`, same style as the existing ones.

## 5. Testing plan

1. **Unit tests:** `ast_test.go` for `resolveUnique` (unique match,
   ambiguous match across two files/packages, no match);
   `fingerprint_test.go` rewritten around the new identity fields;
   `score_test.go` for `DuplicateTop1Accuracy`; a migration round-trip
   test against real local SQLite (`t.TempDir()`).
2. **Live corpus (real acceptance test):**
   `go run ./cmd/kritolith eval --data-dir <persistent-dir>` — confirm
   `fab-017` reaches `LIKELY_DUPLICATE` (duplicate top-1 accuracy
   3/3 = 100%, comfortably above the 80% target). **Zero regressions**
   on all three existing hard gates: `real wrongly GROUNDING_FAILED = 0`,
   `real wrongly LIKELY_DUPLICATE = 0`, `fabricated wrongly
   LIKELY_DUPLICATE = 0`.
3. **Adversarial probe** (throwaway, scratchpad only, `git archive` +
   never touching the reviewed checkout, per the handoff's own
   methodology): two reports in the same repo both loosely citing an
   ambiguous/multiply-declared name, same vuln_class — confirm this
   does **not** fingerprint-match once uniqueness-gating is live. This
   is the scenario the pre-fix code is silently vulnerable to and the
   checked-in corpus doesn't cover.
4. `make ci` (`fmt-check vet test build eval`) before every commit;
   `test` target already uses `-timeout 20m`.

## 6. Out of scope

- Import resolution / Gap G1 itself (accepted for v1, unchanged).
- Gap G2 (fabricated-catch rate 73%, accepted for v1, unchanged — do
  not chase by weakening grounding's disprove rules).
- The `pkg.Func` plain-function-vs-method resolution ambiguity (§2.4) —
  disclosed, not fixed.
- G-DEDUPE2 items other than `EmbeddingsByRepo` and the scoreboard
  top-1 check: extractor vuln_class keyword robustness, `osv sync`
  robustness (timeout, ecosystem filter, multi-package advisories,
  abort-on-malformed-entry), stale doc comments, no OSV-populated
  corpus fixture.
- Sandbox, verdict signing/delivery, `.eml` intake — untouched,
  Milestone 5+.

## 7. Repo-specific execution notes

Same as Weeks 2–4: commits go straight to `main`
(`kritolith-global-rules-override` memory — explicit repo-level
exemption from the global worktree/branch convention), every commit is
DCO-signed (`git commit -s`), `git push origin main` after every
commit, GitHub Actions CI stays (repo-level exception to the global
"never GitHub Actions" rule), the quality-gate hook runs on every commit
(never `SKIP_GATE` except a genuine emergency). Every subagent dispatch
must state the repo exemptions explicitly.
