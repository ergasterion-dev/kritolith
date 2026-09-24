# Week 4 — Dedupe Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a dedupe stage to Kritolith's pipeline that flags a report `LIKELY_DUPLICATE` when its grounded claims exactly match a prior report or a published OSV advisory, records weaker embedding-similarity leads without changing the outcome, and ships `kritolith osv sync` to populate the local OSV mirror.

**Architecture:** New `internal/dedupe` package, nil-able and wired into `internal/pipeline` exactly like `internal/ground`'s `Grounder` — `WithDedupe(d dedupe.Deduper) *Pipeline`, never errors, degrades on any failure. Matching has three independent signal sources merged into one ranked list: exact fingerprint match against prior reports' grounded claims (deterministic, no LLM), exact symbol match against the local OSV mirror, and embedding cosine similarity (only when an `embed` LLM task is configured) as a non-authoritative lead. Only an exact match (fingerprint or OSV) sets `Outcome = LIKELY_DUPLICATE`; `GROUNDING_FAILED` still wins over it.

**Tech Stack:** Go standard library + `modernc.org/sqlite` (already a dependency). No new third-party dependency.

**Spec:** `docs/superpowers/specs/2026-09-24-week4-dedupe-design.md`

## Global Constraints

- Commits go straight to `main` — no branches, worktrees, or PRs (repo exemption from the user's global rule, see `kritolith-global-rules-override` memory).
- Every commit is DCO-signed: `git commit -s`.
- `git push origin main` after every commit — never batch pushes.
- GitHub Actions CI is allowed in this repo (repo exemption from the global "never GitHub Actions" rule).
- The quality-gate hook runs gofmt/vet/lint/build/test on every commit — never `SKIP_GATE`.
- Standard library + `modernc.org/sqlite` only. No new third-party dependency for embeddings or vector search — brute-force cosine in plain Go.
- Kritolith must run fully with no LLM configured — the exact-tier matches (fingerprint, OSV) must never depend on an embed provider being available.
- A false `LIKELY_DUPLICATE` is exactly as bad as a false `GROUNDING_FAILED` — when in doubt, a dedupe signal must fall through to "recorded lead, no outcome change," never force the verdict.
- Table-driven tests, real local SQLite via `t.TempDir()` — no store mocks, matching `internal/ground`'s test conventions.
- Every subagent dispatch must state explicitly that this repo is exempt from the global no-main-commit rule.

## Review Focus

1. **A verified function claim with no accompanying `vuln_class` claim.** Fingerprinting must produce zero fingerprints for that report (no crash, no partial/loose match) — exercised in Task 1.
2. **Two reports about the same repo whose only shared claim is a bare function name with no qualifier** (e.g. both cite `Read`). Fingerprinting must never treat this as a match — bare names are excluded entirely, not just deprioritized — exercised in Task 1 and Task 6.
3. **The very first report ever processed for a repo** (empty store, no prior claims/embeddings/OSV rows). Dedupe must return zero matches and still set `DedupeRan = true`, never error — exercised in Task 6.
4. **A store or embed-provider failure mid-dedupe** (closed DB handle, provider timeout/error). Must degrade to no matches for the affected signal and never fail or panic `pipeline.Run`, mirroring `Grounder`'s degrade-on-failure contract — exercised in Task 6 and Task 7.
5. **Re-running `kritolith osv sync` when nothing changed upstream.** Must be idempotent — no duplicate rows, no unnecessary writes — keyed on advisory ID and the advisory's own `modified` timestamp — exercised in Task 4 and Task 8.

---

### Task 1: Fingerprint normalization

**Files:**
- Modify: `internal/ground/ast.go` (add an exported wrapper at the end of the file)
- Create: `internal/dedupe/fingerprint.go`
- Create: `internal/dedupe/fingerprint_test.go`

**Interfaces:**
- Consumes: `report.Claim`, `report.ClaimFunction`, `report.ClaimVulnClass`, `report.TriYes` (existing, `internal/report`); the existing unexported `splitFunctionClaim` in `internal/ground/ast.go`.
- Produces: `ground.SplitFunctionClaim(value string) (qualifier, name string)` (exported); `dedupe.claimFingerprints(repo string, claims []report.Claim) []fingerprint` and `fingerprint.matches(other fingerprint) bool`, consumed by Task 6.

- [ ] **Step 1: Export grounding's function-claim parser**

Append to `internal/ground/ast.go`:

```go
// SplitFunctionClaim exposes splitFunctionClaim to other packages
// (dedupe's fingerprinting) that need the same (qualifier, name) parse
// grounding already does for a function claim value, so there is one
// source of truth for how "(*T).M" / "pkg.Func" / "Func" are split.
func SplitFunctionClaim(value string) (qualifier, name string) {
	return splitFunctionClaim(value)
}
```

- [ ] **Step 2: Write the failing fingerprint tests**

Create `internal/dedupe/fingerprint_test.go`:

```go
package dedupe

import (
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/ground"
	"github.com/ergasterion-dev/kritolith/internal/report"
)

func TestClaimFingerprints(t *testing.T) {
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*parser).peek", Verified: report.TriYes},
		{Kind: report.ClaimFunction, Value: "unverified.Func", Verified: report.TriUnknown},
		{Kind: report.ClaimFunction, Value: "Read", Verified: report.TriYes}, // bare name: no qualifier
		{Kind: report.ClaimVulnClass, Value: "  Out-Of-Bounds Read  "},
	}
	got := claimFingerprints("go-yaml/yaml", claims)
	if len(got) != 1 {
		t.Fatalf("claimFingerprints = %+v, want exactly 1", got)
	}
	want := fingerprint{repo: "go-yaml/yaml", qualifier: "parser", name: "peek", vulnClass: "out-of-bounds read"}
	if got[0] != want {
		t.Errorf("claimFingerprints[0] = %+v, want %+v", got[0], want)
	}
}

func TestClaimFingerprintsNoVulnClass(t *testing.T) {
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*parser).peek", Verified: report.TriYes},
	}
	if got := claimFingerprints("go-yaml/yaml", claims); len(got) != 0 {
		t.Errorf("claimFingerprints = %+v, want none without a vuln_class claim", got)
	}
}

func TestClaimFingerprintsBareNameExcluded(t *testing.T) {
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "Read", Verified: report.TriYes},
		{Kind: report.ClaimVulnClass, Value: "race"},
	}
	if got := claimFingerprints("owner/repo", claims); len(got) != 0 {
		t.Errorf("claimFingerprints = %+v, want none for a bare-name function claim", got)
	}
}

func TestFingerprintMatches(t *testing.T) {
	a := fingerprint{repo: "r", qualifier: "q", name: "n", vulnClass: "v"}
	tests := []struct {
		name string
		b    fingerprint
		want bool
	}{
		{"identical", a, true},
		{"different repo", fingerprint{repo: "other", qualifier: "q", name: "n", vulnClass: "v"}, false},
		{"different qualifier", fingerprint{repo: "r", qualifier: "other", name: "n", vulnClass: "v"}, false},
		{"different vuln class", fingerprint{repo: "r", qualifier: "q", name: "n", vulnClass: "other"}, false},
		{"both empty qualifier never matches", fingerprint{repo: "r", qualifier: "", name: "n", vulnClass: "v"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := a.matches(tt.b); got != tt.want {
				t.Errorf("matches = %v, want %v", got, tt.want)
			}
		})
	}
	empty := fingerprint{repo: "r", qualifier: "", name: "n", vulnClass: "v"}
	if empty.matches(empty) {
		t.Error("two fingerprints both with an empty qualifier must never match each other")
	}
}

func TestSplitFunctionClaimExported(t *testing.T) {
	if q, n := ground.SplitFunctionClaim("(*T).M"); q != "T" || n != "M" {
		t.Errorf("SplitFunctionClaim((*T).M) = %q, %q, want T, M", q, n)
	}
	if q, n := ground.SplitFunctionClaim("pkg.Func"); q != "pkg" || n != "Func" {
		t.Errorf("SplitFunctionClaim(pkg.Func) = %q, %q, want pkg, Func", q, n)
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./internal/dedupe/... ./internal/ground/... -run 'Fingerprint|SplitFunctionClaim' -v`
Expected: FAIL — `internal/dedupe` package doesn't exist yet, `ground.SplitFunctionClaim` undefined.

- [ ] **Step 4: Implement fingerprint normalization**

Create `internal/dedupe/fingerprint.go`:

```go
// Package dedupe flags likely-duplicate reports by matching grounded
// claims against prior reports and the local OSV mirror, and by
// embedding similarity when an LLM provider is configured. Only an
// exact match (fingerprint or OSV) is strong enough to set a report's
// outcome to LIKELY_DUPLICATE — a false one is exactly as bad as a
// false GROUNDING_FAILED. Weaker signals are recorded as leads only.
package dedupe

import (
	"strings"

	"github.com/ergasterion-dev/kritolith/internal/ground"
	"github.com/ergasterion-dev/kritolith/internal/report"
)

// fingerprint is a normalized, exact-match-only identity for one
// (verified function claim, vuln_class claim) pair. qualifier is the
// literal "pkg"/"T" text the reporter wrote — never resolved to an
// import path, since grounding itself has no import resolution (see
// the design spec's Gap G1 discussion). All four fields must be
// non-empty for two fingerprints to match; this, plus requiring the
// same repo, is what keeps a same-named-symbol coincidence in a
// different package from producing a false duplicate.
type fingerprint struct {
	repo      string
	qualifier string
	name      string
	vulnClass string
}

// matches reports whether a and b identify the same claimed
// vulnerability.
func (a fingerprint) matches(b fingerprint) bool {
	return a.repo != "" && a.repo == b.repo &&
		a.qualifier != "" && a.qualifier == b.qualifier &&
		a.name != "" && a.name == b.name &&
		a.vulnClass != "" && a.vulnClass == b.vulnClass
}

// claimFingerprints returns every exact-tier-eligible fingerprint
// derivable from claims: the cross product of every verified
// (Verified: yes) function claim with a non-empty qualifier, and every
// vuln_class claim. A function claim with an empty qualifier (a bare
// name like "Read") never contributes — the same reasoning grounding
// itself uses for refusing to disprove bare names applies here: a bare
// name is too easily a stdlib or dependency symbol to anchor an
// identity claim on.
func claimFingerprints(repo string, claims []report.Claim) []fingerprint {
	type funcName struct{ qualifier, name string }
	var funcs []funcName
	var vulnClasses []string
	for _, c := range claims {
		switch c.Kind {
		case report.ClaimFunction:
			if c.Verified != report.TriYes {
				continue
			}
			qualifier, name := ground.SplitFunctionClaim(c.Value)
			if qualifier == "" || name == "" {
				continue
			}
			funcs = append(funcs, funcName{qualifier: qualifier, name: name})
		case report.ClaimVulnClass:
			if v := strings.ToLower(strings.TrimSpace(c.Value)); v != "" {
				vulnClasses = append(vulnClasses, v)
			}
		}
	}
	var out []fingerprint
	for _, f := range funcs {
		for _, vc := range vulnClasses {
			out = append(out, fingerprint{repo: repo, qualifier: f.qualifier, name: f.name, vulnClass: vc})
		}
	}
	return out
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/dedupe/... ./internal/ground/... -run 'Fingerprint|SplitFunctionClaim' -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/ground/ast.go internal/dedupe/fingerprint.go internal/dedupe/fingerprint_test.go
git commit -s -m "feat(dedupe): add fingerprint normalization for grounded claims"
git push origin main
```

---

### Task 2: Expose the resolved module path from grounding

**Files:**
- Modify: `internal/ground/ground.go:22-64` (`groundClaims` signature and return)
- Modify: `internal/ground/service.go:11-58` (`Grounder` interface and `Service.Ground`)
- Modify: `internal/ground/service_test.go` (update existing calls to the new 5-return signature)
- Modify: `internal/pipeline/pipeline.go:70-77` (`Run`'s grounding block)
- Modify: `internal/verdict/verdict.go:11-43` (`StageResults`)

**Interfaces:**
- Consumes: `Mirror.ReadFile`, `modulePath` (existing, unexported, in `internal/ground`).
- Produces: `Grounder.Ground(...) (grounded []report.Claim, refResolved bool, resolvedRef string, viaFallback bool, module string)`; `verdict.StageResults.Module string`, consumed by Task 7 (`res.Module` passed into `Deduper.Dedupe`).

- [ ] **Step 1: Find every existing caller of the 4-return `Ground`/`groundClaims` signature**

Run: `grep -rn 'groundClaims(\|\.Ground(ctx' internal/ cmd/`
Expected output includes at least: `internal/ground/ground.go` (the definition and `service.go`'s call into it), `internal/ground/service.go` (the `Grounder` interface and `Service.Ground`), `internal/ground/service_test.go` (`TestServiceGroundSuccess`, `TestServiceGroundDegradesOnCloneFailure`), and `internal/pipeline/pipeline.go` (`Run`). Note every file for the steps below — any other match found must also be updated the same way.

- [ ] **Step 2: Update `groundClaims` to also return the resolved commit's module path**

In `internal/ground/ground.go`, change the `groundClaims` signature and its two early returns:

```go
func groundClaims(ctx context.Context, m *Mirror, r report.Report, claims []report.Claim) (grounded []report.Claim, refResolved bool, resolvedCommit string, viaFallback bool, module string, err error) {
	var versions []string
	for _, c := range claims {
		if c.Kind == report.ClaimVersion {
			versions = append(versions, c.Value)
			if len(versions) >= maxFallbackRefs {
				break
			}
		}
	}
	commit, resolved, viaFallback, err := m.EnsureAndResolve(ctx, r.ClaimedRef, versions)
	if err != nil {
		return claims, false, "", false, "", err
	}
	if !resolved {
		return claims, false, "", false, "", nil
	}

	idx := newLazyIndex(ctx, m, commit)
	out := make([]report.Claim, len(claims))
	copy(out, claims)
	for i := range out {
		switch out[i].Kind {
		case report.ClaimFile:
			groundFileClaim(ctx, m, commit, &out[i], idx)
		case report.ClaimFunction:
			groundFunctionClaim(&out[i], idx)
		case report.ClaimLine:
			groundLineClaim(ctx, m, commit, &out[i], idx.get().decls)
		}
	}
	// Read go.mod directly here rather than through idx.get(): forcing
	// the full lazy index (a whole-tree file listing and read) just to
	// learn the module path would be wasteful for a report whose claims
	// never triggered it otherwise (e.g. version/vuln_class/sink only).
	var mod string
	if gomod, ok, err := m.ReadFile(ctx, commit, "go.mod"); err == nil && ok {
		mod = modulePath(gomod)
	}
	return out, true, commit, viaFallback, mod, nil
}
```

- [ ] **Step 3: Update `Grounder` and `Service.Ground` in `internal/ground/service.go`**

```go
// Grounder is what pipeline.Run needs from this package. It never
// returns an error: a grounding failure (unreachable repo, a
// clone/fetch error, a git error) degrades to refResolved=false, the
// same signal as a ref that simply never resolved — Compose already
// treats that as NEEDS_INFO, never a rejection. viaFallback is true
// when the claimed ref itself didn't resolve and resolvedRef came from
// a version mentioned in the report instead; Compose then never lets a
// hard-claim failure become GROUNDING_FAILED. module is the resolved
// commit's go.mod module path, empty when ungrounded or the repo has
// no go.mod — dedupe uses it to match against the local OSV mirror.
type Grounder interface {
	Ground(ctx context.Context, r report.Report, claims []report.Claim) (grounded []report.Claim, refResolved bool, resolvedRef string, viaFallback bool, module string)
}
```

```go
// Ground implements Grounder. Any failure (a bad data dir, a
// clone/fetch error, a git error) is logged at Warn — with the report
// ID and repo, never claim content — and degrades to
// (claims unchanged, false, "", false, "") rather than surfacing as an error.
func (s *Service) Ground(ctx context.Context, r report.Report, claims []report.Claim) ([]report.Claim, bool, string, bool, string) {
	m, err := OpenMirror(s.dataDir, r.Repo, s.originURL(r.Repo))
	if err != nil {
		slog.Default().Warn("grounding: could not open mirror, degrading to ungrounded claims",
			"report_id", r.ID, "repo", r.Repo, "error", err)
		return claims, false, "", false, ""
	}
	grounded, resolved, commit, viaFallback, module, err := groundClaims(ctx, m, r, claims)
	if err != nil {
		slog.Default().Warn("grounding failed, degrading to ungrounded claims",
			"report_id", r.ID, "repo", r.Repo, "error", err)
		return claims, false, "", false, ""
	}
	if viaFallback {
		slog.Default().Warn("grounding: claimed ref did not resolve; grounded against a fallback version instead",
			"report_id", r.ID, "repo", r.Repo, "commit", commit)
	}
	return grounded, resolved, commit, viaFallback, module
}
```

- [ ] **Step 4: Fix the now-broken calls in `internal/ground/service_test.go`**

Update both `TestServiceGroundSuccess` and `TestServiceGroundDegradesOnCloneFailure` to capture the 5th return value:

```go
	grounded, resolved, resolvedRef, _, _ := s.Ground(context.Background(), r, claims)
```

(one `_` for `viaFallback`, one for the new `module` — apply this in both test functions where `s.Ground(...)` is called).

- [ ] **Step 5: Add `Module` to `verdict.StageResults` in `internal/verdict/verdict.go`**

Add this field to the `StageResults` struct, after `ResolvedViaFallback`:

```go
	// Module is the resolved commit's go.mod module path, populated by
	// grounding; empty when ungrounded or the repo has no go.mod. Week
	// 4's dedupe uses it to match a report's own code against the local
	// OSV mirror, which is keyed by Go module path, not GitHub repo.
	Module string
```

- [ ] **Step 6: Update `pipeline.Run`'s grounding block in `internal/pipeline/pipeline.go`**

```go
	if p.grounder != nil {
		grounded, resolved, resolvedRef, viaFallback, module := p.grounder.Ground(ctx, r, claims)
		res.Claims = grounded
		res.GroundingRan = true
		res.RefResolved = resolved
		res.ResolvedRef = resolvedRef
		res.ResolvedViaFallback = viaFallback
		res.Module = module
	}
```

- [ ] **Step 7: Build and run the ground/pipeline/verdict test suites**

Run: `go build ./... && go test ./internal/ground/... ./internal/pipeline/... ./internal/verdict/... -v`
Expected: PASS. If `go build` reports any other broken call site from Step 1's grep that wasn't listed above, fix it the same way (add the 5th return value) before proceeding.

- [ ] **Step 8: Commit**

```bash
git add internal/ground/ground.go internal/ground/service.go internal/ground/service_test.go internal/pipeline/pipeline.go internal/verdict/verdict.go
git commit -s -m "feat(ground): expose the resolved commit's go.mod module path"
git push origin main
```

---

### Task 3: Store queries for past-report claims and embeddings

**Files:**
- Modify: `internal/store/store.go` (add imports `encoding/binary`, `math`; append new methods)
- Modify: `internal/store/store_test.go` (add tests)

**Interfaces:**
- Consumes: `report.Claim`, `report.ClaimFunction`, `report.ClaimVulnClass` (existing); the `claims`/`reports`/`embeddings` tables (existing schema, `0001_init.sql`).
- Produces: `Store.ClaimsByRepo(ctx, repo, excludeReportID string) (map[string][]report.Claim, error)`; `Store.SaveEmbedding(ctx, reportID, model string, vector []float32) error`; `Store.EmbeddingsByRepo(ctx, repo, excludeReportID string) (map[string]Embedding, error)`; `Embedding{Model string, Vector []float32}`. Consumed by Task 6.

- [ ] **Step 1: Write the failing tests**

Append to `internal/store/store_test.go`:

```go
func TestClaimsByRepo(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	r1 := report.Report{ID: "r1", Repo: "owner/repo", ReceivedAt: time.Now()}
	r2 := report.Report{ID: "r2", Repo: "owner/repo", ReceivedAt: time.Now()}
	r3 := report.Report{ID: "r3", Repo: "other/repo", ReceivedAt: time.Now()}
	for _, r := range []report.Report{r1, r2, r3} {
		if err := s.SaveReport(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SaveVerdict(ctx, report.Verdict{
		ReportID: "r1", Outcome: report.OutcomeInconclusive,
		Claims: []report.Claim{
			{Kind: report.ClaimFunction, Value: "(*T).M", Verified: report.TriYes},
			{Kind: report.ClaimFile, Value: "a.go"}, // not function/vuln_class: excluded
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveVerdict(ctx, report.Verdict{
		ReportID: "r3", Outcome: report.OutcomeInconclusive,
		Claims: []report.Claim{{Kind: report.ClaimFunction, Value: "(*Other).N", Verified: report.TriYes}},
	}); err != nil {
		t.Fatal(err)
	}

	got, err := s.ClaimsByRepo(ctx, "owner/repo", "r2")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got["r1"]) != 1 || got["r1"][0].Value != "(*T).M" {
		t.Fatalf("ClaimsByRepo = %+v, want exactly r1's function claim", got)
	}
	if _, ok := got["r3"]; ok {
		t.Error("ClaimsByRepo returned a claim from a different repo")
	}
}

func TestSaveAndFindEmbeddingsByRepo(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	for _, id := range []string{"r1", "r2"} {
		if err := s.SaveReport(ctx, report.Report{ID: id, Repo: "owner/repo", ReceivedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	vec := []float32{0.1, 0.2, 0.3}
	if err := s.SaveEmbedding(ctx, "r1", "local-embed", vec); err != nil {
		t.Fatal(err)
	}

	got, err := s.EmbeddingsByRepo(ctx, "owner/repo", "r2")
	if err != nil {
		t.Fatal(err)
	}
	e, ok := got["r1"]
	if !ok || e.Model != "local-embed" || len(e.Vector) != 3 {
		t.Fatalf("EmbeddingsByRepo = %+v, want r1's embedding", got)
	}
	for i := range vec {
		if e.Vector[i] != vec[i] {
			t.Errorf("Vector[%d] = %v, want %v", i, e.Vector[i], vec[i])
		}
	}

	// Overwrite: SaveEmbedding replaces, not appends.
	if err := s.SaveEmbedding(ctx, "r1", "local-embed", []float32{0.9}); err != nil {
		t.Fatal(err)
	}
	got, err = s.EmbeddingsByRepo(ctx, "owner/repo", "r2")
	if err != nil {
		t.Fatal(err)
	}
	if len(got["r1"].Vector) != 1 {
		t.Fatalf("EmbeddingsByRepo after overwrite = %+v, want a single-element vector", got)
	}
}
```

Add `"time"` to the test file's imports if not already present (`SaveReport` requires `ReceivedAt`).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/store/... -run 'ClaimsByRepo|Embeddings' -v`
Expected: FAIL — methods don't exist yet.

- [ ] **Step 3: Implement the store methods**

Add `"encoding/binary"` and `"math"` to `internal/store/store.go`'s import block, then append:

```go
// ClaimsByRepo returns every function and vuln_class claim from
// reports in repo other than excludeReportID, grouped by report ID.
// Dedupe uses this to fingerprint-match a report against every prior
// report already saved for the same repository.
func (s *Store) ClaimsByRepo(ctx context.Context, repo, excludeReportID string) (map[string][]report.Claim, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT c.report_id, c.kind, c.value, c.source, c.verified, c.evidence
		FROM claims c
		JOIN reports r ON r.id = c.report_id
		WHERE r.repo = ? AND c.report_id != ? AND c.kind IN (?, ?)`,
		repo, excludeReportID, string(report.ClaimFunction), string(report.ClaimVulnClass))
	if err != nil {
		return nil, fmt.Errorf("store: claims by repo %s: %w", repo, err)
	}
	defer rows.Close()
	out := map[string][]report.Claim{}
	for rows.Next() {
		var reportID, kind, verified string
		var c report.Claim
		if err := rows.Scan(&reportID, &kind, &c.Value, &c.Source, &verified, &c.Evidence); err != nil {
			return nil, fmt.Errorf("store: scan claim by repo %s: %w", repo, err)
		}
		c.Kind, c.Verified = report.ClaimKind(kind), report.Tri(verified)
		out[reportID] = append(out[reportID], c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read claims by repo %s: %w", repo, err)
	}
	return out, nil
}

// Embedding is one stored report's title+body embedding vector.
type Embedding struct {
	Model  string
	Vector []float32
}

// SaveEmbedding inserts or replaces reportID's embedding.
func (s *Store) SaveEmbedding(ctx context.Context, reportID, model string, vector []float32) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO embeddings (report_id, model, dims, vector)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(report_id) DO UPDATE SET
			model = excluded.model, dims = excluded.dims, vector = excluded.vector`,
		reportID, model, len(vector), encodeVector(vector))
	if err != nil {
		return fmt.Errorf("store: save embedding for %s: %w", reportID, err)
	}
	return nil
}

// EmbeddingsByRepo returns every stored embedding for reports in repo
// other than excludeReportID, keyed by report ID.
func (s *Store) EmbeddingsByRepo(ctx context.Context, repo, excludeReportID string) (map[string]Embedding, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT e.report_id, e.model, e.dims, e.vector
		FROM embeddings e
		JOIN reports r ON r.id = e.report_id
		WHERE r.repo = ? AND e.report_id != ?`, repo, excludeReportID)
	if err != nil {
		return nil, fmt.Errorf("store: embeddings by repo %s: %w", repo, err)
	}
	defer rows.Close()
	out := map[string]Embedding{}
	for rows.Next() {
		var reportID, model string
		var dims int
		var raw []byte
		if err := rows.Scan(&reportID, &model, &dims, &raw); err != nil {
			return nil, fmt.Errorf("store: scan embedding by repo %s: %w", repo, err)
		}
		vec, err := decodeVector(raw, dims)
		if err != nil {
			return nil, fmt.Errorf("store: decode embedding for %s: %w", reportID, err)
		}
		out[reportID] = Embedding{Model: model, Vector: vec}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read embeddings by repo %s: %w", repo, err)
	}
	return out, nil
}

// encodeVector packs a []float32 into a little-endian byte slice for
// the embeddings.vector BLOB column.
func encodeVector(v []float32) []byte {
	buf := make([]byte, 4*len(v))
	for i, f := range v {
		binary.LittleEndian.PutUint32(buf[i*4:], math.Float32bits(f))
	}
	return buf
}

// decodeVector is encodeVector's inverse. A byte length that doesn't
// match 4*dims means the row is corrupt, reported as an error rather
// than silently truncated or padded.
func decodeVector(raw []byte, dims int) ([]float32, error) {
	if len(raw) != 4*dims {
		return nil, fmt.Errorf("store: embedding has %d bytes, want %d for dims=%d", len(raw), 4*dims, dims)
	}
	out := make([]float32, dims)
	for i := range out {
		out[i] = math.Float32frombits(binary.LittleEndian.Uint32(raw[i*4:]))
	}
	return out, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/store/... -run 'ClaimsByRepo|Embeddings' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/store/store.go internal/store/store_test.go
git commit -s -m "feat(store): add queries for past-report claims and embeddings"
git push origin main
```

---

### Task 4: Store read/write for the OSV mirror

**Files:**
- Modify: `internal/store/store.go` (append new methods and `OSVEntry` type)
- Modify: `internal/store/store_test.go` (add tests)

**Interfaces:**
- Consumes: the `osv_entries` table (existing schema, `0001_init.sql`).
- Produces: `store.OSVEntry{ID, Module, Modified string, Raw []byte}`; `Store.UpsertOSVEntry(ctx, id, module, modified string, raw []byte) (changed bool, err error)`; `Store.OSVEntriesByModule(ctx, module string) ([]OSVEntry, error)`. Consumed by Task 6 (`OSVEntriesByModule`) and Task 8 (`UpsertOSVEntry`).

- [ ] **Step 1: Write the failing tests**

Append to `internal/store/store_test.go`:

```go
func TestUpsertAndFindOSVEntriesByModule(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	changed, err := s.UpsertOSVEntry(ctx, "GO-2022-0603", "gopkg.in/yaml.v3", "2022-01-01T00:00:00Z", []byte(`{"id":"GO-2022-0603"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("first upsert of a new entry should report changed = true")
	}

	// Re-upsert with the same modified timestamp: no-op.
	changed, err = s.UpsertOSVEntry(ctx, "GO-2022-0603", "gopkg.in/yaml.v3", "2022-01-01T00:00:00Z", []byte(`{"id":"GO-2022-0603"}`))
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("re-upserting an unchanged entry should report changed = false")
	}

	// Re-upsert with a newer modified timestamp: writes.
	changed, err = s.UpsertOSVEntry(ctx, "GO-2022-0603", "gopkg.in/yaml.v3", "2022-02-01T00:00:00Z", []byte(`{"id":"GO-2022-0603","modified":"2022-02-01T00:00:00Z"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("re-upserting with a newer modified timestamp should report changed = true")
	}

	entries, err := s.OSVEntriesByModule(ctx, "gopkg.in/yaml.v3")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != "GO-2022-0603" || entries[0].Modified != "2022-02-01T00:00:00Z" {
		t.Fatalf("OSVEntriesByModule = %+v, want one entry with the latest modified value", entries)
	}

	if none, err := s.OSVEntriesByModule(ctx, "no/such/module"); err != nil || len(none) != 0 {
		t.Fatalf("OSVEntriesByModule for an unknown module = %+v, %v, want empty, nil", none, err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/store/... -run OSV -v`
Expected: FAIL — methods don't exist yet.

- [ ] **Step 3: Implement the store methods**

Append to `internal/store/store.go`:

```go
// OSVEntry is one stored OSV advisory.
type OSVEntry struct {
	ID       string
	Module   string
	Modified string
	Raw      []byte
}

// UpsertOSVEntry inserts id if it's new, or updates it if the stored
// entry's Modified differs from modified. It reports whether the row
// was written: false means the entry already existed with the same
// Modified value, so the caller (kritolith osv sync) can report it as
// unchanged rather than re-synced.
func (s *Store) UpsertOSVEntry(ctx context.Context, id, module, modified string, raw []byte) (bool, error) {
	var existing string
	err := s.db.QueryRowContext(ctx, `SELECT modified FROM osv_entries WHERE id = ?`, id).Scan(&existing)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// New entry: fall through to insert.
	case err != nil:
		return false, fmt.Errorf("store: check osv entry %s: %w", id, err)
	case existing == modified:
		return false, nil
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO osv_entries (id, module, modified, raw)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			module = excluded.module, modified = excluded.modified, raw = excluded.raw`,
		id, module, modified, raw)
	if err != nil {
		return false, fmt.Errorf("store: save osv entry %s: %w", id, err)
	}
	return true, nil
}

// OSVEntriesByModule returns every stored OSV entry for module.
func (s *Store) OSVEntriesByModule(ctx context.Context, module string) ([]OSVEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, module, modified, raw FROM osv_entries WHERE module = ?`, module)
	if err != nil {
		return nil, fmt.Errorf("store: osv entries by module %s: %w", module, err)
	}
	defer rows.Close()
	var out []OSVEntry
	for rows.Next() {
		var e OSVEntry
		if err := rows.Scan(&e.ID, &e.Module, &e.Modified, &e.Raw); err != nil {
			return nil, fmt.Errorf("store: scan osv entry by module %s: %w", module, err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read osv entries by module %s: %w", module, err)
	}
	return out, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/store/... -run OSV -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/store/store.go internal/store/store_test.go
git commit -s -m "feat(store): add OSV mirror read/write"
git push origin main
```

---

### Task 5: OSV symbol matching

**Files:**
- Create: `internal/dedupe/osv.go`
- Create: `internal/dedupe/osv_test.go`

**Interfaces:**
- Consumes: nothing beyond the standard library (`encoding/json`) — operates on the `Raw` bytes from a `store.OSVEntry`.
- Produces: `dedupe.matchesOSVSymbol(raw []byte, qualifier, name string) bool`, consumed by Task 6.

- [ ] **Step 1: Write the failing tests**

Create `internal/dedupe/osv_test.go`:

```go
package dedupe

import "testing"

const yamlAdvisoryFixture = `{
  "id": "GO-2022-0603",
  "affected": [
    {
      "package": {"ecosystem": "Go", "name": "gopkg.in/yaml.v3"},
      "ecosystem_specific": {
        "imports": [
          {"path": "gopkg.in/yaml.v3", "symbols": ["parser.peek", "Unmarshal"]}
        ]
      }
    }
  ]
}`

func TestMatchesOSVSymbol(t *testing.T) {
	tests := []struct {
		name             string
		qualifier, fname string
		want             bool
	}{
		{"method form matches qualifier.name", "parser", "peek", true},
		{"bare function name matches", "yaml", "Unmarshal", true},
		{"unrelated symbol does not match", "parser", "advance", false},
		{"unrelated qualifier does not match the bare-name symbol", "otherpkg", "Unmarshal", true}, // Unmarshal alone still matches: same ambiguity ground.findDeclaration accepts
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesOSVSymbol([]byte(yamlAdvisoryFixture), tt.qualifier, tt.fname); got != tt.want {
				t.Errorf("matchesOSVSymbol(%q, %q) = %v, want %v", tt.qualifier, tt.fname, got, tt.want)
			}
		})
	}
}

func TestMatchesOSVSymbolMalformedJSON(t *testing.T) {
	if matchesOSVSymbol([]byte("not json"), "parser", "peek") {
		t.Error("malformed advisory JSON must never match")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/dedupe/... -run MatchesOSVSymbol -v`
Expected: FAIL — `matchesOSVSymbol` doesn't exist yet.

- [ ] **Step 3: Implement OSV symbol matching**

Create `internal/dedupe/osv.go`. Before finalizing, verify this field shape (`affected[].ecosystem_specific.imports[].symbols`) against OSV's current published schema (https://ossf.github.io/osv-schema/) or a real downloaded Go advisory — the shape below is drawn from OSV's documented `ecosystem_specific` convention for Go, but this is external, third-party data whose schema can change, so confirm before trusting it in production, the same discipline the sandbox spec applies to `runsc` flags.

```go
package dedupe

import "encoding/json"

// osvAdvisory is the subset of one OSV advisory's JSON that dedupe
// needs: which Go symbols it lists as affected, per import.
type osvAdvisory struct {
	Affected []struct {
		EcosystemSpecific struct {
			Imports []struct {
				Symbols []string `json:"symbols"`
			} `json:"imports"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
}

// matchesOSVSymbol reports whether raw (one OSV advisory's stored
// JSON) lists a symbol matching a claim's (qualifier, name). OSV's Go
// ecosystem_specific.imports[].symbols lists a method as "Type.Method"
// and a plain function as its bare name. Without import resolution, a
// package qualifier and a type name are syntactically indistinguishable
// — the exact ambiguity ground.findDeclaration already accepts for the
// same reason — so both the bare and qualified forms are checked.
func matchesOSVSymbol(raw []byte, qualifier, name string) bool {
	var adv osvAdvisory
	if err := json.Unmarshal(raw, &adv); err != nil {
		return false
	}
	qualified := qualifier + "." + name
	for _, a := range adv.Affected {
		for _, im := range a.EcosystemSpecific.Imports {
			for _, sym := range im.Symbols {
				if sym == name || sym == qualified {
					return true
				}
			}
		}
	}
	return false
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/dedupe/... -run MatchesOSVSymbol -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/dedupe/osv.go internal/dedupe/osv_test.go
git commit -s -m "feat(dedupe): match verified function claims against OSV symbols"
git push origin main
```

---

### Task 6: Deduper interface and Service

**Files:**
- Create: `internal/dedupe/service.go`
- Create: `internal/dedupe/service_test.go`

**Interfaces:**
- Consumes: `store.Store.ClaimsByRepo`, `store.Store.SaveEmbedding`, `store.Store.EmbeddingsByRepo`, `store.Store.OSVEntriesByModule`, `store.Embedding`, `store.OSVEntry` (Tasks 3–4); `dedupe.claimFingerprints`, `fingerprint.matches` (Task 1); `dedupe.matchesOSVSymbol` (Task 5); `llm.Router.Chain`, `llm.Provider.Embed`, `llm.Provider.Name` (existing); `ground.SplitFunctionClaim` (Task 1); `report.Claim`, `report.DupMatch`, `report.ClaimFunction`, `report.TriYes` (existing).
- Produces: `dedupe.Deduper` interface; `dedupe.NewService(st *store.Store, router *llm.Router) *Service`; `Service.Dedupe(ctx, r, claims, module) ([]report.DupMatch, bool)`. Consumed by Task 7.

- [ ] **Step 1: Write the failing tests**

Create `internal/dedupe/service_test.go`:

```go
package dedupe

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/llm"
	"github.com/ergasterion-dev/kritolith/internal/report"
	"github.com/ergasterion-dev/kritolith/internal/store"
)

func saveReportWithClaims(t *testing.T, s *store.Store, id, repo string, claims []report.Claim) {
	t.Helper()
	ctx := context.Background()
	if err := s.SaveReport(ctx, report.Report{ID: id, Repo: repo, ReceivedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveVerdict(ctx, report.Verdict{ReportID: id, Outcome: report.OutcomeInconclusive, Claims: claims}); err != nil {
		t.Fatal(err)
	}
}

func TestServiceDedupeExactFingerprintMatch(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*parser).peek", Verified: report.TriYes},
		{Kind: report.ClaimVulnClass, Value: "out-of-bounds read"},
	}
	saveReportWithClaims(t, s, "prior", "go-yaml/yaml", claims)

	svc := NewService(s, nil)
	matches, exact := svc.Dedupe(ctx, report.Report{ID: "new", Repo: "go-yaml/yaml"}, claims, "")
	if !exact {
		t.Fatal("want exact = true for an identical fingerprint")
	}
	if len(matches) != 1 || matches[0].ReportID != "prior" || matches[0].Score != 1.0 {
		t.Fatalf("matches = %+v, want a single exact match on report \"prior\"", matches)
	}
}

func TestServiceDedupeEmptyStoreNoMatch(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	svc := NewService(s, nil)
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*T).M", Verified: report.TriYes},
		{Kind: report.ClaimVulnClass, Value: "race"},
	}
	matches, exact := svc.Dedupe(ctx, report.Report{ID: "first", Repo: "owner/repo"}, claims, "")
	if exact {
		t.Error("want exact = false when the store has no prior reports")
	}
	if len(matches) != 0 {
		t.Errorf("matches = %+v, want none", matches)
	}
}

func TestServiceDedupeBareNameNeverMatches(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "Read", Verified: report.TriYes},
		{Kind: report.ClaimVulnClass, Value: "race"},
	}
	saveReportWithClaims(t, s, "prior", "owner/repo", claims)

	svc := NewService(s, nil)
	matches, exact := svc.Dedupe(ctx, report.Report{ID: "new", Repo: "owner/repo"}, claims, "")
	if exact || len(matches) != 0 {
		t.Errorf("matches = %+v, exact = %v; two reports sharing only a bare function name must never match", matches, exact)
	}
}

func TestServiceDedupeDegradesOnClosedStore(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.Close() // force every query the Service makes to fail

	svc := NewService(s, nil)
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*T).M", Verified: report.TriYes},
		{Kind: report.ClaimVulnClass, Value: "race"},
	}
	matches, exact := svc.Dedupe(ctx, report.Report{ID: "r", Repo: "owner/repo"}, claims, "")
	if exact || len(matches) != 0 {
		t.Errorf("matches = %+v, exact = %v; a closed store must degrade to no matches, not panic or error out", matches, exact)
	}
}

// fakeEmbedProvider is a test-only llm.Provider that returns a fixed
// vector per input text, so embedding similarity can be tested without
// a real network call.
type fakeEmbedProvider struct {
	vecs map[string][]float32
}

func (f *fakeEmbedProvider) Complete(context.Context, llm.CompleteRequest) (llm.CompleteResponse, error) {
	return llm.CompleteResponse{}, errors.New("fakeEmbedProvider: Complete not implemented")
}

func (f *fakeEmbedProvider) Embed(_ context.Context, texts []string) ([][]float32, error) {
	out := make([][]float32, len(texts))
	for i, t := range texts {
		v, ok := f.vecs[t]
		if !ok {
			return nil, errors.New("fakeEmbedProvider: no fixture vector for text")
		}
		out[i] = v
	}
	return out, nil
}

func (f *fakeEmbedProvider) Name() string  { return "fake-embed" }
func (f *fakeEmbedProvider) IsLocal() bool { return true }

func TestServiceDedupeEmbeddingLeadNeverSetsExact(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.SaveReport(ctx, report.Report{ID: "prior", Repo: "owner/repo", ReceivedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEmbedding(ctx, "prior", "fake-embed", []float32{1, 0, 0}); err != nil {
		t.Fatal(err)
	}

	provider := &fakeEmbedProvider{vecs: map[string][]float32{"title\n\nbody": {1, 0, 0}}}
	router := llm.NewRouter(map[string]llm.Provider{"p": provider}, map[string][]string{"embed": {"p"}}, nil, nil)
	svc := NewService(s, router)

	r := report.Report{ID: "new", Repo: "owner/repo", Title: "title", Body: "body"}
	matches, exact := svc.Dedupe(ctx, r, nil, "")
	if exact {
		t.Error("an embedding-only match must never set exact = true")
	}
	if len(matches) != 1 || matches[0].ReportID != "prior" || matches[0].Score <= 0.99 {
		t.Fatalf("matches = %+v, want one high-similarity lead on \"prior\"", matches)
	}

	// The new report's own embedding must now be stored too.
	stored, err := s.EmbeddingsByRepo(ctx, "owner/repo", "prior")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := stored["new"]; !ok {
		t.Error("Dedupe must save the current report's own embedding for future comparisons")
	}
}

func TestServiceImplementsDeduper(t *testing.T) {
	var _ Deduper = (*Service)(nil)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/dedupe/... -run 'Service' -v`
Expected: FAIL — `Service`/`Deduper`/`NewService` don't exist yet.

- [ ] **Step 3: Implement the Deduper interface and Service**

Create `internal/dedupe/service.go`:

```go
package dedupe

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sort"

	"github.com/ergasterion-dev/kritolith/internal/ground"
	"github.com/ergasterion-dev/kritolith/internal/llm"
	"github.com/ergasterion-dev/kritolith/internal/report"
	"github.com/ergasterion-dev/kritolith/internal/store"
)

// Deduper is what pipeline.Run needs from this package. It never
// returns an error: any failure (a store error, an embed provider
// error) degrades the affected signal to "no matches from it," the
// same never-fail contract as ground.Grounder.
type Deduper interface {
	// Dedupe finds likely duplicates of r among past reports and the
	// local OSV mirror, and — when an embed provider is configured —
	// also records r's own embedding so future reports can match
	// against it. module is grounding's resolved go.mod module path
	// (StageResults.Module), used only for the OSV-mirror signal; pass
	// "" when ungrounded. It returns up to the top 3 candidate matches
	// by score, and whether any of them is an exact-tier match (the
	// only signal strong enough to set Outcome to LIKELY_DUPLICATE).
	Dedupe(ctx context.Context, r report.Report, claims []report.Claim, module string) (matches []report.DupMatch, exactMatch bool)
}

// embeddingMatchThreshold is deliberately conservative: an embedding
// lead is always recorded for maintainer visibility, but it must clear
// a high bar even to appear as a lead, and — per the design spec — it
// never sets Outcome on its own regardless of how high it scores.
const embeddingMatchThreshold = 0.93

// Service finds duplicates using st's claims, embeddings, and OSV
// mirror tables. router is nil-able: with no router, or no "embed"
// task chain configured on it, embedding similarity is simply skipped
// — Kritolith must work with no LLM configured.
type Service struct {
	store  *store.Store
	router *llm.Router
}

// NewService returns a Service backed by st, using router (nil-able)
// for the "embed" task.
func NewService(st *store.Store, router *llm.Router) *Service {
	return &Service{store: st, router: router}
}

// Dedupe implements Deduper.
func (s *Service) Dedupe(ctx context.Context, r report.Report, claims []report.Claim, module string) ([]report.DupMatch, bool) {
	var candidates []report.DupMatch
	exact := false

	if mine := claimFingerprints(r.Repo, claims); len(mine) > 0 {
		if prior, err := s.store.ClaimsByRepo(ctx, r.Repo, r.ID); err != nil {
			slog.Default().Warn("dedupe: could not load prior claims, skipping fingerprint match",
				"report_id", r.ID, "error", err)
		} else {
			for reportID, cs := range prior {
				theirs := claimFingerprints(r.Repo, cs)
				for _, a := range mine {
					for _, b := range theirs {
						if a.matches(b) {
							candidates = append(candidates, report.DupMatch{ReportID: reportID, Score: 1.0})
							exact = true
						}
					}
				}
			}
		}
	}

	if module != "" {
		if entries, err := s.store.OSVEntriesByModule(ctx, module); err != nil {
			slog.Default().Warn("dedupe: could not load OSV entries, skipping OSV match",
				"report_id", r.ID, "module", module, "error", err)
		} else {
			for _, c := range claims {
				if c.Kind != report.ClaimFunction || c.Verified != report.TriYes {
					continue
				}
				qualifier, name := ground.SplitFunctionClaim(c.Value)
				if name == "" {
					continue
				}
				for _, e := range entries {
					if matchesOSVSymbol(e.Raw, qualifier, name) {
						candidates = append(candidates, report.DupMatch{AdvisoryID: e.ID, Score: 1.0})
						exact = true
					}
				}
			}
		}
	}

	if s.router != nil {
		text := r.Title + "\n\n" + r.Body
		vec, model, err := embedText(ctx, s.router, r.ID, r.Repo, text)
		if err != nil {
			slog.Default().Warn("dedupe: embedding failed, skipping embedding match", "report_id", r.ID, "error", err)
		} else {
			if others, err := s.store.EmbeddingsByRepo(ctx, r.Repo, r.ID); err != nil {
				slog.Default().Warn("dedupe: could not load prior embeddings, skipping embedding match",
					"report_id", r.ID, "error", err)
			} else {
				for reportID, other := range others {
					if len(other.Vector) != len(vec) {
						continue // different model/dims: not comparable
					}
					if score := cosineSimilarity(vec, other.Vector); score >= embeddingMatchThreshold {
						candidates = append(candidates, report.DupMatch{ReportID: reportID, Score: score})
					}
				}
			}
			if err := s.store.SaveEmbedding(ctx, r.ID, model, vec); err != nil {
				slog.Default().Warn("dedupe: could not save embedding", "report_id", r.ID, "error", err)
			}
		}
	}

	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Score > candidates[j].Score })
	if len(candidates) > 3 {
		candidates = candidates[:3]
	}
	return candidates, exact
}

// embedText tries each provider in router's "embed" chain in order,
// returning the first success's vector and the provider name it came
// from — recorded alongside the vector so a later comparison can skip
// vectors from an incomparable model (see router.Chain's own doc
// comment on why callers needing this iterate the chain themselves).
func embedText(ctx context.Context, router *llm.Router, reportID, repo, text string) ([]float32, string, error) {
	var lastErr error
	for _, p := range router.Chain("embed", reportID, repo) {
		vecs, err := p.Embed(ctx, []string{text})
		if err != nil {
			lastErr = err
			continue
		}
		if len(vecs) == 0 {
			lastErr = fmt.Errorf("dedupe: %s: embed returned no vectors", p.Name())
			continue
		}
		return vecs[0], p.Name(), nil
	}
	if lastErr == nil {
		lastErr = llm.ErrNoProvider
	}
	return nil, "", lastErr
}

// cosineSimilarity returns the cosine similarity of a and b, or 0 if
// either is a zero vector.
func cosineSimilarity(a, b []float32) float64 {
	var dot, magA, magB float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		magA += float64(a[i]) * float64(a[i])
		magB += float64(b[i]) * float64(b[i])
	}
	if magA == 0 || magB == 0 {
		return 0
	}
	return dot / (math.Sqrt(magA) * math.Sqrt(magB))
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/dedupe/... -v`
Expected: PASS (all of Tasks 1, 5, and 6's tests)

- [ ] **Step 5: Commit**

```bash
git add internal/dedupe/service.go internal/dedupe/service_test.go
git commit -s -m "feat(dedupe): add Deduper interface and Service combining fingerprint, OSV, and embedding signals"
git push origin main
```

---

### Task 7: Pipeline wiring and verdict precedence

**Files:**
- Modify: `internal/pipeline/pipeline.go` (add `deduper` field, `WithDedupe`, wire into `Run`)
- Modify: `internal/pipeline/pipeline_test.go` (add tests)
- Modify: `internal/verdict/verdict.go` (add `DedupeRan`/`DedupeExactMatch`/`Duplicates` to `StageResults`; new `Compose` branch)
- Modify: `internal/verdict/verdict_test.go` (add tests)

**Interfaces:**
- Consumes: `dedupe.Deduper`, `dedupe.NewService` (Task 6); existing `verdict.StageResults`, `verdict.Compose`, `report.OutcomeLikelyDuplicate`, `report.DupMatch`.
- Produces: `Pipeline.WithDedupe(d dedupe.Deduper) *Pipeline`; `StageResults.DedupeRan bool`, `StageResults.DedupeExactMatch bool`, `StageResults.Duplicates []report.DupMatch`. Consumed by Task 9 (CLI wiring).

- [ ] **Step 1: Write the failing verdict tests**

Add to `internal/verdict/verdict_test.go` (create the file with this content plus a `package verdict` header and needed imports if it doesn't already exist; otherwise append these functions):

```go
func TestComposeLikelyDuplicate(t *testing.T) {
	r := report.Report{ID: "r1", ClaimedRef: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
	res := StageResults{
		GroundingRan: true, RefResolved: true,
		DedupeRan: true, DedupeExactMatch: true,
		Duplicates: []report.DupMatch{{ReportID: "prior", Score: 1.0}},
	}
	v := Compose(r, res)
	if v.Outcome != report.OutcomeLikelyDuplicate {
		t.Errorf("Outcome = %s, want LIKELY_DUPLICATE", v.Outcome)
	}
	if len(v.Duplicates) != 1 || v.Duplicates[0].ReportID != "prior" {
		t.Errorf("Duplicates = %+v, want the dedupe match carried through", v.Duplicates)
	}
}

func TestComposeGroundingFailedWinsOverDedupe(t *testing.T) {
	r := report.Report{ID: "r1", ClaimedRef: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
	res := StageResults{
		GroundingRan: true, RefResolved: true,
		Claims:           []report.Claim{{Kind: report.ClaimFunction, Verified: report.TriNo}},
		DedupeRan:        true,
		DedupeExactMatch: true,
	}
	v := Compose(r, res)
	if v.Outcome != report.OutcomeGroundingFailed {
		t.Errorf("Outcome = %s, want GROUNDING_FAILED even though dedupe also found an exact match", v.Outcome)
	}
}

func TestComposeFallbackResolutionNeverUpgradesToDuplicate(t *testing.T) {
	r := report.Report{ID: "r1", ClaimedRef: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
	res := StageResults{
		GroundingRan: true, RefResolved: true, ResolvedViaFallback: true,
		Claims:           []report.Claim{{Kind: report.ClaimFunction, Verified: report.TriNo}},
		DedupeRan:        true,
		DedupeExactMatch: true,
	}
	v := Compose(r, res)
	if v.Outcome != report.OutcomeInconclusive {
		t.Errorf("Outcome = %s, want INCONCLUSIVE: a fallback-resolved hard-claim failure must not be upgraded by dedupe", v.Outcome)
	}
}

func TestComposeDedupeRanButNoExactMatch(t *testing.T) {
	r := report.Report{ID: "r1", ClaimedRef: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
	res := StageResults{
		GroundingRan: true, RefResolved: true,
		DedupeRan:  true,
		Duplicates: []report.DupMatch{{ReportID: "lead-only", Score: 0.95}},
	}
	v := Compose(r, res)
	if v.Outcome != report.OutcomeInconclusive {
		t.Errorf("Outcome = %s, want INCONCLUSIVE: an embedding-only lead must never set the outcome", v.Outcome)
	}
	if len(v.Duplicates) != 1 {
		t.Errorf("Duplicates = %+v, want the lead still recorded for visibility", v.Duplicates)
	}
}
```

(If `internal/verdict/verdict_test.go` already exists with a different structure, add these four functions to it rather than replacing the file, and add `"github.com/ergasterion-dev/kritolith/internal/report"` and `"testing"` to its imports if not already present.)

- [ ] **Step 2: Run the verdict tests to verify they fail**

Run: `go test ./internal/verdict/... -run Compose -v`
Expected: FAIL — `StageResults` has no `DedupeRan`/`DedupeExactMatch` fields yet, and `Compose` doesn't produce `LIKELY_DUPLICATE`.

- [ ] **Step 3: Add the new `StageResults` fields**

In `internal/verdict/verdict.go`, add to `StageResults` (after the `Module` field added in Task 2):

```go
	// DedupeRan is true when a Deduper was configured and called. Only
	// meaningful together with DedupeExactMatch and Duplicates.
	DedupeRan bool
	// DedupeExactMatch is true when dedupe found an exact fingerprint or
	// OSV match — the only dedupe signal strong enough to set Outcome.
	DedupeExactMatch bool
	// Duplicates holds up to the top 3 candidate matches dedupe found,
	// by score, regardless of tier — including embedding-only leads
	// that never change Outcome, kept here for maintainer visibility.
	Duplicates []report.DupMatch
```

- [ ] **Step 4: Add the new `Compose` branch**

Replace `Compose`'s body in `internal/verdict/verdict.go` with:

```go
func Compose(r report.Report, res StageResults) report.Verdict {
	v := report.Verdict{ReportID: r.ID, Claims: res.Claims, Duplicates: res.Duplicates}
	switch {
	case r.ClaimedRef == "":
		v.Outcome = report.OutcomeNeedsInfo
		v.Notes = append(v.Notes, "no commit or tag given; can't check claims against the code")
	case res.GroundingRan && !res.RefResolved:
		v.Outcome = report.OutcomeNeedsInfo
		v.Notes = append(v.Notes, "claimed ref did not resolve to a commit in the repository")
	case res.GroundingRan && hardClaimFailed(res.Claims) && res.ResolvedViaFallback:
		v.Outcome = report.OutcomeInconclusive
		v.Notes = append(v.Notes, "grounded via a fallback version, not the claimed commit — treating a hard-claim failure as inconclusive rather than a rejection")
	case res.GroundingRan && hardClaimFailed(res.Claims):
		v.Outcome = report.OutcomeGroundingFailed
		v.Notes = append(v.Notes, "a claimed file or function does not exist at the resolved commit")
	case res.DedupeRan && res.DedupeExactMatch:
		v.Outcome = report.OutcomeLikelyDuplicate
		v.Notes = append(v.Notes, "an exact claim match was found against a prior report or a published advisory")
	default:
		v.Outcome = report.OutcomeInconclusive
		v.Notes = append(v.Notes, "sandbox stage is not implemented yet")
	}
	if res.LLMUnavailable {
		v.Notes = append(v.Notes, "LLM extraction unavailable; deterministic claims only")
	}
	return v
}
```

Also update `Compose`'s doc comment to mention the new branch (dedupe's exact match sits below the existing grounding branches, above the fallback `INCONCLUSIVE`).

- [ ] **Step 5: Run the verdict tests to verify they pass**

Run: `go test ./internal/verdict/... -v`
Expected: PASS

- [ ] **Step 6: Write the failing pipeline test**

Add to `internal/pipeline/pipeline_test.go`:

```go
type fakeDeduper struct {
	matches []report.DupMatch
	exact   bool
	called  bool
}

func (f *fakeDeduper) Dedupe(_ context.Context, _ report.Report, _ []report.Claim, _ string) ([]report.DupMatch, bool) {
	f.called = true
	return f.matches, f.exact
}

func TestPipelineRunWithDedupe(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t) // reuse this test file's existing store test-helper; if none exists, use: s, err := store.Open(ctx, t.TempDir()); if err != nil { t.Fatal(err) }
	fd := &fakeDeduper{matches: []report.DupMatch{{ReportID: "prior", Score: 1.0}}, exact: true}
	p := New(st).WithDedupe(fd)

	v, err := p.Run(ctx, report.Report{ID: "r1", Repo: "owner/repo", ClaimedRef: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", Body: "no claims here"})
	if err != nil {
		t.Fatal(err)
	}
	if !fd.called {
		t.Error("a configured Deduper must be called")
	}
	if v.Outcome != report.OutcomeLikelyDuplicate {
		t.Errorf("Outcome = %s, want LIKELY_DUPLICATE", v.Outcome)
	}
}

func TestPipelineRunWithoutDedupeUnchanged(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	p := New(st) // no WithDedupe: must behave exactly as before Week 4

	v, err := p.Run(ctx, report.Report{ID: "r1", Repo: "owner/repo", Body: "no claims here"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Outcome != report.OutcomeNeedsInfo {
		t.Errorf("Outcome = %s, want NEEDS_INFO (no ClaimedRef), unaffected by the new dedupe stage", v.Outcome)
	}
}
```

Check `internal/pipeline/pipeline_test.go` for an existing store-construction test helper (e.g. a function that opens a `store.Store` in `t.TempDir()`) and reuse its exact name instead of `newTestStore` if one already exists; otherwise inline `store.Open(ctx, t.TempDir())` directly in both new tests and add `"github.com/ergasterion-dev/kritolith/internal/store"` to the imports.

- [ ] **Step 7: Run the pipeline tests to verify they fail**

Run: `go test ./internal/pipeline/... -run Dedupe -v`
Expected: FAIL — `WithDedupe` doesn't exist yet.

- [ ] **Step 8: Wire `WithDedupe` into `Pipeline`**

In `internal/pipeline/pipeline.go`, add the import `"github.com/ergasterion-dev/kritolith/internal/dedupe"`, add a field to `Pipeline`:

```go
type Pipeline struct {
	store    Store
	llmChain llmextract.Chain // nil when no LLM is configured
	grounder ground.Grounder  // nil when no Grounder is configured
	deduper  dedupe.Deduper   // nil when no Deduper is configured
}
```

add the builder method after `WithGround`:

```go
// WithDedupe returns p configured to also check claims for duplicates
// through d. A nil deduper (New's default) skips the dedupe stage
// entirely — Run behaves exactly as it did before Week 4 for any
// caller that doesn't wire one in.
func (p *Pipeline) WithDedupe(d dedupe.Deduper) *Pipeline {
	p.deduper = d
	return p
}
```

and extend `Run` (after the grounding block, before `Compose`):

```go
	if p.deduper != nil {
		matches, exactMatch := p.deduper.Dedupe(ctx, r, res.Claims, res.Module)
		res.DedupeRan = true
		res.Duplicates = matches
		res.DedupeExactMatch = exactMatch
	}
```

- [ ] **Step 9: Run the pipeline tests to verify they pass**

Run: `go test ./internal/pipeline/... -v`
Expected: PASS

- [ ] **Step 10: Commit**

```bash
git add internal/pipeline/pipeline.go internal/pipeline/pipeline_test.go internal/verdict/verdict.go internal/verdict/verdict_test.go
git commit -s -m "feat(pipeline,verdict): wire dedupe into the pipeline and verdict precedence"
git push origin main
```

---

### Task 8: `kritolith osv sync` CLI command

**Files:**
- Create: `cmd/kritolith/osv.go`
- Create: `cmd/kritolith/osv_test.go`
- Modify: `cmd/kritolith/main.go:17-52` (usage text and command dispatch)

**Interfaces:**
- Consumes: `store.Store.UpsertOSVEntry` (Task 4); `config.Load`, `resolveDataDir` (existing, `cmd/kritolith/flags.go`); `parseInterspersed` (existing, `cmd/kritolith/flags.go`).
- Produces: `runOSV(ctx, args, stdout, stderr) int`; the `kritolith osv sync` command. Nothing later in this plan consumes this task's symbols directly — it's a leaf.

- [ ] **Step 1: Write the failing CLI test**

Create `cmd/kritolith/osv_test.go`:

```go
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/store"
)

func buildFixtureZip(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestSyncOSV(t *testing.T) {
	fixture := buildFixtureZip(t, map[string]string{
		"GO-2022-0603.json": `{"id":"GO-2022-0603","modified":"2022-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"Go","name":"gopkg.in/yaml.v3"},"ecosystem_specific":{"imports":[{"symbols":["parser.peek"]}]}}]}`,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixture)
	}))
	defer srv.Close()

	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	written, skipped, err := syncOSV(ctx, st, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if written != 1 || skipped != 0 {
		t.Fatalf("first sync: written = %d, skipped = %d, want 1, 0", written, skipped)
	}

	written, skipped, err = syncOSV(ctx, st, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if written != 0 || skipped != 1 {
		t.Fatalf("re-sync with unchanged data: written = %d, skipped = %d, want 0, 1", written, skipped)
	}

	entries, err := st.OSVEntriesByModule(ctx, "gopkg.in/yaml.v3")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != "GO-2022-0603" {
		t.Fatalf("entries = %+v, want one GO-2022-0603 entry", entries)
	}
}

func TestSyncOSVSkipsEntryWithoutAffected(t *testing.T) {
	fixture := buildFixtureZip(t, map[string]string{
		"GO-2022-0603.json": `{"id":"GO-2022-0603","modified":"2022-01-01T00:00:00Z","affected":[]}`,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixture)
	}))
	defer srv.Close()

	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	written, skipped, err := syncOSV(ctx, st, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if written != 0 || skipped != 0 {
		t.Errorf("written = %d, skipped = %d, want 0, 0 for an entry with no affected packages", written, skipped)
	}
}

func TestRunOSVUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"osv"}, &out, &errOut)
	if code != 2 {
		t.Errorf("code = %d, want 2 for a missing subcommand", code)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./cmd/kritolith/... -run 'SyncOSV|RunOSVUsage' -v`
Expected: FAIL — `syncOSV`/`runOSV`/the `osv` dispatch case don't exist yet.

- [ ] **Step 3: Implement `kritolith osv sync`**

Create `cmd/kritolith/osv.go`:

```go
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"

	"github.com/ergasterion-dev/kritolith/internal/config"
	"github.com/ergasterion-dev/kritolith/internal/store"
)

// osvBulkExportURL is OSV's documented per-ecosystem bulk export
// (see https://google.github.io/osv.dev/data/#data-dumps). Verify this
// URL and the archive/JSON layout syncOSV assumes against OSV's current
// documentation before relying on this in production — it's external,
// third-party infrastructure that can change independently of this
// codebase.
const osvBulkExportURL = "https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip"

func runOSV(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "sync" {
		fmt.Fprintln(stderr, "Usage: kritolith osv sync [--data-dir dir] [--config file] [--url url]")
		return 2
	}
	fs := flag.NewFlagSet("osv sync", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data-dir", "", "data directory (overrides config)")
	cfgPath := fs.String("config", "", "path to kritolith.json")
	url := fs.String("url", osvBulkExportURL, "OSV bulk export URL to sync from")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: kritolith osv sync [--data-dir dir] [--config file] [--url url]")
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args[1:])
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		return 2
	}
	if len(pos) != 0 {
		fs.Usage()
		return 2
	}

	var cfg *config.Config
	if *cfgPath != "" {
		c, err := config.Load(*cfgPath)
		if err != nil {
			return fail(stderr, err)
		}
		cfg = &c
	}
	dir, err := resolveDataDir(*dataDir, cfg)
	if err != nil {
		return fail(stderr, err)
	}
	st, err := store.Open(ctx, dir)
	if err != nil {
		return fail(stderr, err)
	}
	defer st.Close()

	written, skipped, err := syncOSV(ctx, st, *url)
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "kritolith: synced %d OSV entries (%d unchanged, skipped)\n", written, skipped)
	return 0
}

// syncOSV fetches url — an OSV per-ecosystem bulk export zip, one JSON
// file per advisory — and upserts every entry that lists at least one
// affected package into st. It returns how many entries were written
// and how many were already current (same id, same modified value) and
// skipped.
func syncOSV(ctx context.Context, st *store.Store, url string) (written, skipped int, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("osv sync: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("osv sync: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("osv sync: fetch %s: status %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512<<20)) // 512MB cap: a bulk export is large but bounded
	if err != nil {
		return 0, 0, fmt.Errorf("osv sync: read %s: %w", url, err)
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return 0, 0, fmt.Errorf("osv sync: %s is not a valid zip: %w", url, err)
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return written, skipped, fmt.Errorf("osv sync: open %s: %w", f.Name, err)
		}
		raw, err := io.ReadAll(io.LimitReader(rc, 16<<20))
		rc.Close()
		if err != nil {
			return written, skipped, fmt.Errorf("osv sync: read %s: %w", f.Name, err)
		}
		var entry struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
			Affected []struct {
				Package struct {
					Ecosystem string `json:"ecosystem"`
					Name      string `json:"name"`
				} `json:"package"`
			} `json:"affected"`
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			return written, skipped, fmt.Errorf("osv sync: parse %s: %w", f.Name, err)
		}
		if entry.ID == "" || len(entry.Affected) == 0 {
			continue
		}
		changed, err := st.UpsertOSVEntry(ctx, entry.ID, entry.Affected[0].Package.Name, entry.Modified, raw)
		if err != nil {
			return written, skipped, fmt.Errorf("osv sync: save %s: %w", entry.ID, err)
		}
		if changed {
			written++
		} else {
			skipped++
		}
	}
	return written, skipped, nil
}
```

- [ ] **Step 4: Wire `osv` into command dispatch in `cmd/kritolith/main.go`**

Update the `usage` constant:

```go
const usage = `Usage: kritolith <command> [flags]

Commands:
  check     verify a single report file
  eval      run the eval corpus and print the scoreboard
  osv       manage the local OSV mirror (run "kritolith osv sync -h")
  version   print the version

Run "kritolith <command> -h" for command flags.
`
```

Add a case to the switch in `run`:

```go
	case "osv":
		return runOSV(ctx, args[1:], stdout, stderr)
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./cmd/kritolith/... -run 'SyncOSV|RunOSVUsage' -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add cmd/kritolith/osv.go cmd/kritolith/osv_test.go cmd/kritolith/main.go
git commit -s -m "feat(cli): add kritolith osv sync"
git push origin main
```

---

### Task 9: Wire dedupe into `check`/`eval` and extend the scoreboard

**Files:**
- Modify: `cmd/kritolith/check.go:74-83`
- Modify: `cmd/kritolith/eval.go` (the equivalent pipeline-construction block)
- Modify: `internal/eval/score.go`
- Modify: `internal/eval/score_test.go`

**Interfaces:**
- Consumes: `dedupe.NewService`, `dedupe.Deduper` (Task 6); existing `pipeline.Pipeline`, `llm.Router`, `buildRouter`.
- Produces: `Scoreboard.RealLikelyDuplicates() int`, `Scoreboard.FabricatedLikelyDuplicates() int`, updated `Scoreboard.Failed()`. Consumed by Task 10 (reading `make eval` output).

- [ ] **Step 1: Write the failing scoreboard tests**

Append to `internal/eval/score_test.go`:

```go
func TestRealLikelyDuplicates(t *testing.T) {
	sb := Scoreboard{Results: []Result{
		{Case: Case{ID: "r1", Kind: KindReal, Meta: Meta{Expected: report.OutcomeReproduced}}, Got: report.OutcomeLikelyDuplicate},
		{Case: Case{ID: "r2", Kind: KindReal, Meta: Meta{Expected: report.OutcomeInconclusive}}, Got: report.OutcomeInconclusive},
	}}
	if n := sb.RealLikelyDuplicates(); n != 1 {
		t.Errorf("RealLikelyDuplicates = %d, want 1", n)
	}
	if !sb.Failed() {
		t.Error("a real report wrongly marked LIKELY_DUPLICATE must fail the run")
	}
}

func TestFabricatedLikelyDuplicates(t *testing.T) {
	sb := Scoreboard{Results: []Result{
		{Case: Case{ID: "f1", Kind: KindFabricated, Meta: Meta{Expected: report.OutcomeGroundingFailed}}, Got: report.OutcomeLikelyDuplicate},
		{Case: Case{ID: "f2", Kind: KindFabricated, Meta: Meta{Expected: report.OutcomeLikelyDuplicate}}, Got: report.OutcomeLikelyDuplicate},
	}}
	if n := sb.FabricatedLikelyDuplicates(); n != 1 {
		t.Errorf("FabricatedLikelyDuplicates = %d, want 1 (f2 expected it, so it doesn't count)", n)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/eval/... -run LikelyDuplicates -v`
Expected: FAIL — the two methods don't exist yet.

- [ ] **Step 3: Add the scoreboard methods and update `Failed`/`Write`**

In `internal/eval/score.go`, add after `RealGroundingFailures`:

```go
// RealLikelyDuplicates counts real reports wrongly marked
// LIKELY_DUPLICATE. The v1 requirement is zero, same discipline as
// RealGroundingFailures: a false duplicate flag is exactly as bad as a
// false grounding rejection.
func (s Scoreboard) RealLikelyDuplicates() int {
	n := 0
	for _, r := range s.Results {
		if r.Case.Kind == KindReal && r.Got == report.OutcomeLikelyDuplicate {
			n++
		}
	}
	return n
}

// FabricatedLikelyDuplicates counts fabricated cases that were NOT
// expecting LIKELY_DUPLICATE but got it anyway — a coincidental
// fingerprint or OSV collision between two unrelated fabricated cases,
// which would itself be a bug worth knowing about.
func (s Scoreboard) FabricatedLikelyDuplicates() int {
	n := 0
	for _, r := range s.Results {
		if r.Case.Kind == KindFabricated && r.Case.Meta.Expected != report.OutcomeLikelyDuplicate && r.Got == report.OutcomeLikelyDuplicate {
			n++
		}
	}
	return n
}
```

Update `Failed`:

```go
func (s Scoreboard) Failed() bool {
	return s.RealGroundingFailures() > 0 || s.RealLikelyDuplicates() > 0 || s.Errors() > 0
}
```

Update the summary block in `Write`:

```go
	caught, total := s.FabricatedCaught()
	_, err := fmt.Fprintf(w, `
Summary
  cases:                                 %d
  exact matches:                         %d/%d
  real wrongly GROUNDING_FAILED:         %d (must be 0)
  real wrongly LIKELY_DUPLICATE:         %d (must be 0)
  fabricated caught by grounding:        %d/%d
  fabricated wrongly LIKELY_DUPLICATE:   %d
  errors:                                %d
`, len(s.Results), s.Matches(), len(s.Results), s.RealGroundingFailures(), s.RealLikelyDuplicates(), caught, total, s.FabricatedLikelyDuplicates(), s.Errors())
	return err
```

- [ ] **Step 4: Run the eval tests to verify they pass**

Run: `go test ./internal/eval/... -v`
Expected: PASS

- [ ] **Step 5: Wire `WithDedupe` into `cmd/kritolith/check.go`**

Replace lines 74–83 of `cmd/kritolith/check.go` with:

```go
	var router *llm.Router
	if cfg != nil {
		router, err = buildRouter(*cfg, nil)
		if err != nil {
			return fail(stderr, err)
		}
	}
	p := pipeline.New(st).WithGround(ground.NewService(dir)).WithDedupe(dedupe.NewService(st, router))
	if router != nil {
		p = p.WithLLM(router)
	}
```

Add `"github.com/ergasterion-dev/kritolith/internal/dedupe"` and `"github.com/ergasterion-dev/kritolith/internal/llm"` to its import block.

- [ ] **Step 6: Wire `WithDedupe` into `cmd/kritolith/eval.go`**

Replace this block in `cmd/kritolith/eval.go`:

```go
	p := pipeline.New(st).WithGround(ground.NewService(dir))
	if cfg != nil {
		router, err := buildRouter(*cfg, nil)
		if err != nil {
			return fail(stderr, err)
		}
		if router != nil {
			p = p.WithLLM(router)
		}
	}
```

with:

```go
	var router *llm.Router
	if cfg != nil {
		router, err = buildRouter(*cfg, nil)
		if err != nil {
			return fail(stderr, err)
		}
	}
	p := pipeline.New(st).WithGround(ground.NewService(dir)).WithDedupe(dedupe.NewService(st, router))
	if router != nil {
		p = p.WithLLM(router)
	}
```

(`err` is already declared earlier in `runEval` via `cases, err := eval.LoadCorpus(*corpus)`, so `router, err = buildRouter(...)` reuses it — do not redeclare with `:=`.)

Then update the failure message to also report duplicate false positives:

```go
	if sb.Failed() {
		fmt.Fprintf(stderr, "kritolith: eval failed: %d real reports marked GROUNDING_FAILED, %d real reports marked LIKELY_DUPLICATE, %d errors\n",
			sb.RealGroundingFailures(), sb.RealLikelyDuplicates(), sb.Errors())
		return 1
	}
```

Add `"github.com/ergasterion-dev/kritolith/internal/dedupe"` and `"github.com/ergasterion-dev/kritolith/internal/llm"` to `eval.go`'s import block.

- [ ] **Step 7: Build and run the full cmd/kritolith test suite**

Run: `go build ./... && go test ./cmd/kritolith/... -v`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add cmd/kritolith/check.go cmd/kritolith/eval.go internal/eval/score.go internal/eval/score_test.go
git commit -s -m "feat(cli,eval): wire dedupe into check/eval and extend the scoreboard"
git push origin main
```

---

### Task 10: Full corpus verification and wrap-up

**Files:**
- No new files. This task runs the full suite and fixes anything the live corpus surfaces; any fix lands in whichever existing file needs it (most likely `internal/dedupe/fingerprint.go` if a normalization edge case is wrong, or `internal/dedupe/osv.go` if the OSV schema assumption from Task 5 needs correcting per its own verification note).

**Interfaces:**
- Consumes: everything from Tasks 1–9.
- Produces: nothing new — this is the acceptance gate for the whole plan.

- [ ] **Step 1: Run the full test suite with race detection**

Run: `go test -race ./... 2>&1 | tail -100`
Expected: PASS across every package.

- [ ] **Step 2: Run the live corpus and inspect the scoreboard**

Run: `go run ./cmd/kritolith eval --corpus testdata/corpus --data-dir /tmp/kritolith-eval-week4 2>&1 | tail -60`

(Use a persistent `--data-dir` outside the repo, gitignored — the corpus clones ~20 real GitHub repos and re-cloning every run is slow.)

Expected in the summary:
- `real wrongly GROUNDING_FAILED: 0 (must be 0)`
- `real wrongly LIKELY_DUPLICATE: 0 (must be 0)`
- `fab-015`, `fab-016`, `fab-017` show `LIKELY_DUPLICATE` in the GOT column with a ✓ mark
- `fabricated wrongly LIKELY_DUPLICATE: 0` (a non-zero value here means investigate before proceeding — it means two unrelated fabricated cases collided on an exact fingerprint or OSV match, which Step 3 must diagnose and fix)

- [ ] **Step 3: If the corpus run doesn't match expectations, diagnose with a real probe, not a guess**

If `fab-015/016/017` do NOT reach `LIKELY_DUPLICATE`: confirm the corresponding real case (`go-2022-0603`, `go-2024-3205`, or `go-2024-2604`) actually ran before it in the same eval invocation (real cases sort before fabricated ones, per `eval.LoadCorpus` — this should already hold), then compare the real case's grounded `ClaimFunction`/`ClaimVulnClass` claim values against the fabricated case's, using `kritolith check --json` on each individually against the shared `--data-dir` to inspect the exact claim values grounding produced. A mismatch in qualifier/name/vuln_class wording between the two reports (not a bug — the fabricated cases are deliberately "reworded") means `claimFingerprints`' extraction is too strict, and needs a fix in `internal/dedupe/fingerprint.go` (e.g. the reworded report doesn't produce a `ClaimVulnClass` claim the same way) — do not weaken the exact-match requirement in `fingerprint.matches` to fix this; fix the claim extraction/normalization instead, preserving the "all four fields must be non-empty and equal" invariant Task 1 tested.

If any real case is wrongly `LIKELY_DUPLICATE` or `GROUNDING_FAILED`: this is the hard gate from `CLAUDE.md` — stop and treat it as a blocking correctness bug, following the project's probe-testing methodology (§6 of the design spec): export the real commit tree with `git archive`, reproduce the exact fingerprint collision in a throwaway scratchpad script, fix the root cause, never the symptom.

- [ ] **Step 4: Run the full CI gate**

Run: `make ci`
Expected: PASS (`fmt-check vet test build eval`).

- [ ] **Step 5: Update the Week 1 carry-forward memory note**

The `kritolith-week4-dedupe-tuning` note in memory (`fab-013 resembles GO-2022-0322`) referred to a hypothesis that didn't hold up (`fab-013`/`fab-014` expect `GROUNDING_FAILED`, confirmed unaffected by dedupe per Task 7's precedence test) — no code action needed, but mention this in the final commit message so it's not silently forgotten.

- [ ] **Step 6: Final commit**

```bash
git add -A
git commit -s -m "$(cat <<'EOF'
chore(dedupe): verify Week 4 corpus targets and close out the milestone

fab-015/016/017 now reach LIKELY_DUPLICATE via the past-reports
fingerprint path with no LLM configured, matching eval's real-before-
fabricated corpus ordering. real wrongly GROUNDING_FAILED and real
wrongly LIKELY_DUPLICATE both stay at 0.
EOF
)"
git push origin main
```

(If Step 1–4 required no code changes beyond what Tasks 1–9 already produced, this step may have nothing to add — skip an empty commit and just confirm `git status` is clean and pushed.)
