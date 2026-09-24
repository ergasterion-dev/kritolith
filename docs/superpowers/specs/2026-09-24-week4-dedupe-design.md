# Week 4 — Dedupe: Design

Written: 2026-09-24
Status: approved by maintainer in conversation; implementing next.

## 0. Context

Per `CLAUDE.md`'s pipeline (`intake → extract → ground → dedupe → sandbox → verdict`),
Weeks 1–3 built intake/extract/ground. This spec covers **dedupe**: flag
a report as a likely duplicate of a prior report or a published OSV
advisory, without ever wrongly flagging a genuinely new report — the
same "never wrongly reject a real report" discipline Week 3 applied to
`GROUNDING_FAILED` now applies symmetrically to `LIKELY_DUPLICATE`.

Full background: `kritolith-personal-docs-never-to-push/2026-09-24_1520-IST_week4-dedupe_handoff.md`.

## 1. Decisions carried in from maintainer sign-off

- **Gap G1** (grounding's same-named-type collision, no import resolution)
  is **accepted as a residual risk for v1**. Dedupe must not attempt to
  solve import resolution either — it reuses the same syntactic-qualifier
  limitation grounding already has, disclosed, not fixed.
- **Match confidence is tiered, not a single weighted score.** An exact
  fingerprint match (repo, qualifier, function name, vuln_class all
  equal) is sufficient on its own to set `Outcome = LIKELY_DUPLICATE` —
  deterministic, no LLM required. Embedding cosine similarity is a
  separate, weaker signal: it is recorded in `Duplicates` for maintainer
  visibility but never on its own changes `Outcome`.

## 2. Package layout & pipeline wiring

New `internal/dedupe` package, mirroring `internal/ground`'s shape:

- `dedupe.go` — fingerprint normalization, candidate scoring, tiering.
- `service.go` — `Deduper` interface + `Service`, same nil-able,
  never-errors contract as `ground.Grounder`.

```go
// internal/dedupe/service.go
type Deduper interface {
    Dedupe(ctx context.Context, r report.Report, claims []report.Claim) (matches []report.DupMatch, ran bool)
}
```

`internal/pipeline/pipeline.go` gets `WithDedupe(d dedupe.Deduper) *Pipeline`,
called after grounding, before `verdict.Compose`. A nil `Deduper` (the
default) skips the stage entirely — `Run` behaves exactly as it does
today for any caller that doesn't wire one in, same convention as
`WithGround`.

`verdict.StageResults` grows two additive fields:

```go
DedupeRan  bool
Duplicates []report.DupMatch // top 3 by score, regardless of tier; empty if none found
```

## 3. Fingerprint normalization

Derived from claims `ground` already produced — never re-derived from
raw report text.

- **repo** — `r.Repo` (already validated on intake).
- **function** — from a `ClaimFunction` claim with `Verified: yes`
  only (an unverified or disproved claim is not fingerprint material).
  Split via `ast.go`'s existing `splitFunctionClaim` into
  `(qualifier, name)`.
- **qualifier** — the literal `pkg`/`T` text the reporter wrote (or
  `""` for a bare name claim). This is **not** a resolved import path —
  grounding has no import resolution (G1, accepted) — so two reports
  naming `(*Decoder).Read` in genuinely different packages can share a
  fingerprint. This is an accepted, disclosed narrowing of the same
  shape as G1: fingerprint match additionally requires the repo to
  match too, which makes a spurious cross-package collision within the
  *same* repository the only realistic false-positive shape, and it
  requires the same function name, same written qualifier, and same
  vuln_class all at once.
- **vuln_class** — from a `ClaimVulnClass` claim, lowercased and
  trimmed. A report with no vuln_class claim cannot produce an
  exact-tier fingerprint at all — it falls through to embedding-only
  matching or no match.

```go
type fingerprint struct {
    repo, qualifier, name, vulnClass string
}
```

Exact-tier match: both fingerprints have all four fields non-empty and
equal.

## 4. Storage & candidate retrieval

Three independent sources feed one ranked candidate list per report:

1. **Past reports.** New `store` query, e.g.
   `FindClaimsByRepo(ctx, repo string, excludeReportID string) ([]storedClaim, error)`,
   grouped by report, over the existing `claims`/`reports` tables — no
   schema change. Only claims from previously **saved verdicts** are
   candidates (a report currently being processed is obviously not yet
   a "prior" report).
2. **Embeddings.** The `embeddings` table (already scaffolded in the
   Week 1 migration) gets one row per processed report: title+body text
   embedded via the router's `embed` task, when a router is configured.
   Dedupe reads all rows for the same repo and brute-force cosines
   against them in Go (`[]float32` unmarshaled from the BLOB) — no
   vector-search dependency, per the dependency policy.
3. **OSV mirror.** The `osv_entries` table (already scaffolded) is
   matched the same way as the fingerprint path — module + symbol
   equality against the stored advisory JSON — producing a
   `DupMatch{AdvisoryID: ...}` instead of `ReportID`.

All three are scored and merged; the top 3 by score go into
`Duplicates` regardless of tier. Only an exact fingerprint hit (against
a past report or an OSV entry) is exact-tier and can set `Outcome`.

## 5. OSV mirror sync

No job queue exists yet (Milestone 1's "in-process job queue" is not
built), and building one is out of scope for Week 4.

- New `kritolith osv sync` CLI command (`cmd/kritolith/osv.go`):
  fetches the public Go OSV bulk export over HTTPS, filters to the Go
  ecosystem, upserts into `osv_entries` keyed by advisory ID, using
  each entry's `modified` timestamp to skip unchanged entries on
  re-sync.
- "Refreshed daily" is satisfied by the command being correct and
  idempotent; actual scheduling (e.g., a GitHub Actions cron workflow
  calling `kritolith osv sync` — allowed in this repo per
  `kritolith-global-rules-override`) is a deploy-time concern, not
  Week 4 code.
- `make eval` and the corpus never require a populated OSV mirror —
  the near-duplicate corpus cases (`fab-015/016/017`) are satisfied
  entirely by the past-reports fingerprint path, since
  `eval.LoadCorpus` processes `real/` before `fabricated/` through one
  shared pipeline and store, and those three fabricated cases'
  near-duplicate targets (`GO-2022-0603`, `GO-2024-3205`,
  `GO-2024-2604`) are themselves real corpus entries processed first in
  the same run. OSV matching gets its own separate test with a
  fixture-seeded `osv_entries` table — no real network sync in tests.

## 6. Verdict precedence

New branch in `verdict.Compose`, inserted where the old bare
`default → INCONCLUSIVE` was, never overriding `NEEDS_INFO` or
`GROUNDING_FAILED`:

```
no ClaimedRef                                → NEEDS_INFO        (unchanged)
ref given but !RefResolved                    → NEEDS_INFO        (unchanged)
resolved via fallback + hard claim failed     → INCONCLUSIVE      (unchanged)
resolved directly + hard claim failed         → GROUNDING_FAILED  (unchanged)
DedupeRan && an exact-tier match exists       → LIKELY_DUPLICATE  (NEW)
otherwise                                     → INCONCLUSIVE      (fallback note updated)
```

`GROUNDING_FAILED` still wins over a dedupe match — confirmed correct
by the corpus: `fab-013`/`fab-014` ("wrong-package") expect
`GROUNDING_FAILED`, not `LIKELY_DUPLICATE`, even though they cite a
real function.

An exact-tier dedupe match found underneath the "resolved via fallback
+ hard claim failed" branch does **not** get upgraded to
`LIKELY_DUPLICATE` — that branch already means grounding checked
claims against a commit that isn't the one the reporter actually named,
and duplicate detection built on that same shaky resolution inherits
the same unreliability. It stays `INCONCLUSIVE`; any dedupe lead still
appears in `Duplicates`.

The `default` branch's note changes from "dedupe and sandbox stages are
not implemented yet" to "sandbox stage is not implemented yet" (dedupe
now genuinely ran).

## 7. Testing & threshold-tuning methodology

- Fingerprint/embedding/OSV-match logic: table-driven unit tests
  against real local SQLite (`t.TempDir()`), no mocks of the store.
- `pipeline.Run` regression: a dedupe stage error (store failure)
  degrades to `DedupeRan: false`, never fails the pipeline — same
  contract as `Grounder`.
- **Live corpus is the real acceptance test.** `go run ./cmd/kritolith eval`
  must reach `LIKELY_DUPLICATE` on `fab-015/016/017` and must **not**
  flip any of the 20 real cases or the other 17 fabricated cases to
  `LIKELY_DUPLICATE`. New scoreboard lines: `real wrongly
  LIKELY_DUPLICATE` (hard gate, must be 0) and `fabricated wrongly
  LIKELY_DUPLICATE` (should also be 0 — a coincidental fingerprint
  collision between two unrelated fabricated cases would itself be a
  bug worth knowing about).
- The embedding-similarity tier is only reachable with `--config` (a
  router configured) and no case in the current corpus depends on it.
  It gets unit-level cosine tests with synthetic vectors, not a
  corpus-tuned threshold. **Known limitation, explicitly carried
  forward**: revisit once real embedding-only near-duplicate fixtures
  (same vulnerability, different function/package, worded so no
  fingerprint field lines up) exist in the corpus.
- Apply Week 3's probe-testing discipline (`git archive` + throwaway
  scratchpad repro, never touching the reviewed checkout) to any
  fingerprint-collision scenario surfaced during review.

## 8. Out of scope for Week 4

- Import resolution / fixing Gap G1 (explicitly accepted, see §1).
- A job queue or any scheduling mechanism for `kritolith osv sync`.
- Sandbox, verdict signing, delivery — untouched.
- Tuning the embedding-similarity threshold against real fixtures (no
  such fixtures exist yet in the corpus).

## 9. Repo-specific execution notes

Same as Weeks 2/3: commits go straight to `main`
(`kritolith-global-rules-override` memory), every commit is DCO-signed
(`git commit -s`), `git push origin main` after every commit, GitHub
Actions CI stays, the quality-gate hook runs on every commit (never
`SKIP_GATE`). Every subagent dispatch must carry the repo exemption
line explicitly.
