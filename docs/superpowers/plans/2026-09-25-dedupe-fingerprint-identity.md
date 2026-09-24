# Dedupe: Fingerprint on Resolved Declaration Identity — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix Milestone 4's duplicate top-1 accuracy gap (67%, target ≥80%) by fingerprinting dedupe matches on the resolved declaration's identity instead of a claim's literal written qualifier, gated by a repo-wide uniqueness check, and instrument the scoreboard so this metric is actually measured.

**Architecture:** Grounding already resolves a function claim to a specific `declaration` (file, line, receiver, name) when it verifies one. Add a uniqueness check in `internal/ground` that only trusts that resolution as a stable identity when no other declaration in the repo shares the same `(name, receiver)`; plumb the resolved `(pkgDir, receiver, name)` onto `report.Claim` (persisted via a new migration); rewrite `internal/dedupe`'s fingerprinting to key off that resolved identity instead of `ground.SplitFunctionClaim(c.Value)`; add a scoreboard metric that checks the *matched* prior report is the *correct* one, not just that `Outcome == LIKELY_DUPLICATE`.

**Tech Stack:** Go standard library, `modernc.org/sqlite` (already the only third-party dependency), SQLite migrations under `internal/store/migrations/`.

**Spec:** `docs/superpowers/specs/2026-09-25-dedupe-fingerprint-identity-design.md`

## Global Constraints

- Standard library first; no new third-party dependency (none needed here).
- Commits go straight to `main` — no branches, no worktrees, no PRs (`kritolith-global-rules-override` memory, explicit repo exemption from the global convention).
- Every commit is DCO-signed: `git commit -s`.
- `git push origin main` after every commit — never batch pushes.
- Quality gate hook (`~/.claude/hooks/quality-gate.sh`) runs gofmt/vet/lint/build/test on every commit — fix failures, never `SKIP_GATE` except a genuine emergency.
- `go test ./...` on `cmd/kritolith` needs `-timeout 20m` (the real-network corpus test). Always use `make test` or `make ci`, never raw `go test ./...`.
- Never wrongly set `LIKELY_DUPLICATE` or `GROUNDING_FAILED` on a real report — both are hard requirements enforced by `eval.Scoreboard.Failed()`; every task below must keep `real wrongly GROUNDING_FAILED = 0` and `real wrongly LIKELY_DUPLICATE = 0`.
- Grounding has no import resolution (Gap G1, accepted for v1): a "package" is only ever a directory on disk (`path.Dir` of a declaration's file), never a resolved import path.
- Conventional commit messages (`feat(ground): …`, `test(dedupe): …`), matching this repo's existing log.

## Review Focus

- **Cross-report false positive from an ambiguous name.** Two different reports in the same repo, both loosely citing a name declared in two different files/packages with the same vuln_class wording, must never fingerprint-match once uniqueness-gating is live — this is the exact failure the pre-fix code is silently open to. Covered by Task 7's adversarial probe (the checked-in corpus has no such fixture).
- **Migration safety on an existing database.** A data dir created by a pre-fix binary already has rows in `claims` with no `decl_*` columns; the `ALTER TABLE ... DEFAULT ''` migration must backfill those rows to empty strings without breaking `GetVerdict`/`ClaimsByRepo` reads on old data. Covered by a dedicated test in Task 3.
- **Same-package (not just cross-package) ambiguity.** Two files in the *same* directory both declaring a same-named, same-receiver function (e.g. `GOOS`-tagged variants this parser's per-file scan can't tell are mutually exclusive) must also be treated as ambiguous — "ambiguous" means "shared anywhere in the repo", not "shared across different directories". Covered by a dedicated `resolveUnique` test in Task 2.
- **`expected_duplicate_of` typos in the corpus.** A `meta.json` naming a target case ID that doesn't exist in the loaded corpus must fail `LoadCorpus` loudly, not silently make `DuplicateTop1Accuracy` under-count forever. Covered by cross-case validation in Task 6.
- **`EmbeddingsByRepo`'s new verdict-outcome join must never accidentally exclude the current report's own freshly-saved embedding** — `Dedupe` saves the current report's embedding *before* its own verdict exists, but every `EmbeddingsByRepo` call already excludes the current report by ID regardless, so this can't regress; a comment in Task 5's code says so explicitly, and the existing `TestServiceDedupeEmbeddingLeadNeverSetsExact` test (updated to still pass) is the regression guard.

---

### Task 1: `GroundResult` struct replaces `Grounder.Ground`'s positional returns

**Files:**
- Modify: `internal/ground/service.go`
- Modify: `internal/ground/service_test.go`
- Modify: `internal/pipeline/pipeline.go`
- Modify: `internal/pipeline/pipeline_test.go`

**Interfaces:**
- Produces: `ground.GroundResult{Claims []report.Claim, RefResolved bool, ResolvedRef string, ViaFallback bool, Module string}` and `Grounder.Ground(ctx, r, claims) GroundResult` — every later task that touches grounding call sites uses this shape.

This is a pure refactor (no behavior change): the unexported `groundClaims` in `ground.go` keeps its existing positional signature untouched.

- [ ] **Step 1: Update the `Grounder` interface and `Service.Ground` in `internal/ground/service.go`**

Replace the whole file's `Grounder` interface, `Ground` method, and update the doc comment:

```go
package ground

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// GroundResult is what one call to Grounder.Ground produced.
// RefResolved is true when the claimed ref (or a fallback version
// mentioned in the report) resolved to a commit. ViaFallback is true
// when the claimed ref itself didn't resolve and ResolvedRef came from
// a version mentioned in the report instead; Compose then never lets a
// hard-claim failure become GROUNDING_FAILED. Module is the resolved
// commit's go.mod module path, empty when ungrounded or the repo has
// no go.mod — dedupe uses it to match against the local OSV mirror.
type GroundResult struct {
	Claims      []report.Claim
	RefResolved bool
	ResolvedRef string
	ViaFallback bool
	Module      string
}

// Grounder is what pipeline.Run needs from this package. It never
// returns an error: a grounding failure (unreachable repo, a
// clone/fetch error, a git error) degrades to RefResolved=false, the
// same signal as a ref that simply never resolved — Compose already
// treats that as NEEDS_INFO, never a rejection.
type Grounder interface {
	Ground(ctx context.Context, r report.Report, claims []report.Claim) GroundResult
}

// Service grounds reports against git mirrors rooted at dataDir,
// cloned from GitHub over HTTPS by default.
type Service struct {
	dataDir   string
	originURL func(repo string) string // overridable in tests; defaults to githubOriginURL
}

// NewService returns a Service that keeps its git mirrors under
// dataDir.
func NewService(dataDir string) *Service {
	return &Service{dataDir: dataDir, originURL: githubOriginURL}
}

// Ground implements Grounder. Any failure (a bad data dir, a
// clone/fetch error, a git error) is logged at Warn — with the report
// ID and repo, never claim content — and degrades to
// GroundResult{Claims: claims} rather than surfacing as an error.
func (s *Service) Ground(ctx context.Context, r report.Report, claims []report.Claim) GroundResult {
	m, err := OpenMirror(s.dataDir, r.Repo, s.originURL(r.Repo))
	if err != nil {
		slog.Default().Warn("grounding: could not open mirror, degrading to ungrounded claims",
			"report_id", r.ID, "repo", r.Repo, "error", err)
		return GroundResult{Claims: claims}
	}
	grounded, resolved, commit, viaFallback, module, err := groundClaims(ctx, m, r, claims)
	if err != nil {
		slog.Default().Warn("grounding failed, degrading to ungrounded claims",
			"report_id", r.ID, "repo", r.Repo, "error", err)
		return GroundResult{Claims: claims}
	}
	if viaFallback {
		slog.Default().Warn("grounding: claimed ref did not resolve; grounded against a fallback version instead",
			"report_id", r.ID, "repo", r.Repo, "commit", commit)
	}
	return GroundResult{Claims: grounded, RefResolved: resolved, ResolvedRef: commit, ViaFallback: viaFallback, Module: module}
}

func githubOriginURL(repo string) string {
	return fmt.Sprintf("https://github.com/%s.git", repo)
}
```

- [ ] **Step 2: Update the two direct `s.Ground(...)` calls in `internal/ground/service_test.go`**

In `TestServiceGroundSuccess`, replace:

```go
	grounded, resolved, resolvedRef, _, _ := s.Ground(context.Background(), r, claims)
	if !resolved || resolvedRef != commit {
		t.Fatalf("resolved = %v, resolvedRef = %q, want true, %q", resolved, resolvedRef, commit)
	}
	if grounded[0].Verified != report.TriYes {
		t.Errorf("claim = %+v, want Verified: yes", grounded[0])
	}
```

with:

```go
	gr := s.Ground(context.Background(), r, claims)
	if !gr.RefResolved || gr.ResolvedRef != commit {
		t.Fatalf("RefResolved = %v, ResolvedRef = %q, want true, %q", gr.RefResolved, gr.ResolvedRef, commit)
	}
	if gr.Claims[0].Verified != report.TriYes {
		t.Errorf("claim = %+v, want Verified: yes", gr.Claims[0])
	}
```

In `TestServiceGroundDegradesOnCloneFailure`, replace:

```go
	grounded, resolved, resolvedRef, _, _ := s.Ground(context.Background(), r, claims)
	if resolved {
		t.Error("want resolved = false for an unreachable origin")
	}
	if resolvedRef != "" {
		t.Errorf("resolvedRef = %q, want empty", resolvedRef)
	}
	if len(grounded) != 1 || grounded[0].Value != "a.go" {
		t.Errorf("grounded = %+v, want the original claims returned unchanged", grounded)
	}
```

with:

```go
	gr := s.Ground(context.Background(), r, claims)
	if gr.RefResolved {
		t.Error("want RefResolved = false for an unreachable origin")
	}
	if gr.ResolvedRef != "" {
		t.Errorf("ResolvedRef = %q, want empty", gr.ResolvedRef)
	}
	if len(gr.Claims) != 1 || gr.Claims[0].Value != "a.go" {
		t.Errorf("Claims = %+v, want the original claims returned unchanged", gr.Claims)
	}
```

- [ ] **Step 3: Update `internal/pipeline/pipeline.go`'s `Run`**

Replace:

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

with:

```go
	if p.grounder != nil {
		gr := p.grounder.Ground(ctx, r, claims)
		res.Claims = gr.Claims
		res.GroundingRan = true
		res.RefResolved = gr.RefResolved
		res.ResolvedRef = gr.ResolvedRef
		res.ResolvedViaFallback = gr.ViaFallback
		res.Module = gr.Module
	}
```

- [ ] **Step 4: Update `fakeGrounder` in `internal/pipeline/pipeline_test.go`**

Add `"github.com/ergasterion-dev/kritolith/internal/ground"` to the import block, then replace:

```go
type fakeGrounder struct {
	claims      []report.Claim // if non-nil, returned as-is instead of the input claims
	resolved    bool
	resolvedRef string
	viaFallback bool
	module      string
}

func (g fakeGrounder) Ground(ctx context.Context, r report.Report, claims []report.Claim) ([]report.Claim, bool, string, bool, string) {
	out := claims
	if g.claims != nil {
		out = g.claims
	}
	return out, g.resolved, g.resolvedRef, g.viaFallback, g.module
}
```

with:

```go
type fakeGrounder struct {
	claims      []report.Claim // if non-nil, returned as-is instead of the input claims
	resolved    bool
	resolvedRef string
	viaFallback bool
	module      string
}

func (g fakeGrounder) Ground(ctx context.Context, r report.Report, claims []report.Claim) ground.GroundResult {
	out := claims
	if g.claims != nil {
		out = g.claims
	}
	return ground.GroundResult{Claims: out, RefResolved: g.resolved, ResolvedRef: g.resolvedRef, ViaFallback: g.viaFallback, Module: g.module}
}
```

- [ ] **Step 5: Run the affected tests**

Run: `go test ./internal/ground/... ./internal/pipeline/...`
Expected: PASS, no other changes needed — every other `fakeGrounder{...}` literal in `pipeline_test.go` only sets its unexported fields, not the return shape, so they're unaffected.

- [ ] **Step 6: Commit**

```bash
git add internal/ground/service.go internal/ground/service_test.go internal/pipeline/pipeline.go internal/pipeline/pipeline_test.go
git commit -s -m "refactor(ground): return a GroundResult struct instead of 5 positional values"
git push origin main
```

---

### Task 2: Resolved declaration identity on `report.Claim`, gated by a uniqueness check

**Files:**
- Modify: `internal/report/report.go`
- Modify: `internal/ground/ast.go`
- Modify: `internal/ground/ast_test.go`
- Modify: `internal/ground/ground.go`
- Modify: `internal/ground/ground_test.go`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `report.Claim.DeclPkgDir/DeclReceiver/DeclName string` fields, and `ground.resolveUnique(decls []declaration, value string) (d *declaration, ambiguous bool)` — Task 3 (storage) and Task 4 (fingerprinting) both read the three new `Claim` fields.

- [ ] **Step 1: Add the three new fields to `report.Claim` in `internal/report/report.go`**

Replace:

```go
// Claim is one checkable statement extracted from a report.
type Claim struct {
	Kind     ClaimKind `json:"kind"`
	Value    string    `json:"value"`
	Source   string    `json:"source"` // "deterministic" or "llm:<model>"
	Verified Tri       `json:"verified"`
	Evidence string    `json:"evidence"`
}
```

with:

```go
// Claim is one checkable statement extracted from a report.
//
// DeclPkgDir, DeclReceiver, and DeclName identify the resolved
// declaration a ClaimFunction claim was grounded against — never the
// claim's own literal written text — and are set only when that
// declaration is unique in the repo (see ground.resolveUnique):
// grounding found a match either way, but an ambiguous one (the same
// name declared more than once) leaves these empty, since fingerprint
// identity built on a guess would be worse than no identity at all.
// DeclPkgDir is the directory the declaration's file lives in,
// relative to the repo root — never a resolved import path, since
// grounding has no import resolution. DeclReceiver is empty for a
// plain function; that is not ambiguity, just the absence of a
// receiver.
type Claim struct {
	Kind         ClaimKind `json:"kind"`
	Value        string    `json:"value"`
	Source       string    `json:"source"` // "deterministic" or "llm:<model>"
	Verified     Tri       `json:"verified"`
	Evidence     string    `json:"evidence"`
	DeclPkgDir   string    `json:"decl_pkg_dir,omitempty"`
	DeclReceiver string    `json:"decl_receiver,omitempty"`
	DeclName     string    `json:"decl_name,omitempty"`
}
```

- [ ] **Step 2: Write failing tests for `resolveUnique` in `internal/ground/ast_test.go`**

Append to the end of the file:

```go
func TestResolveUniqueSingleMatch(t *testing.T) {
	decls := []declaration{{name: "peek", receiver: "parser", file: "decode.go", line: 10}}
	d, ambiguous := resolveUnique(decls, "(*parser).peek")
	if d == nil || d.name != "peek" {
		t.Fatalf("resolveUnique = %v, %v, want a match on peek", d, ambiguous)
	}
	if ambiguous {
		t.Error("a single matching declaration must not be ambiguous")
	}
}

func TestResolveUniqueAmbiguousAcrossPackages(t *testing.T) {
	// Two different packages each declare a type T with a method M — the
	// exact G1 same-named-type collision. A claim naming "T.M" resolves
	// to *a* declaration (findDeclaration's existing behavior, unchanged)
	// but must now be reported ambiguous: grounding can't be sure which
	// T the reporter meant.
	decls := []declaration{
		{name: "M", receiver: "T", file: "pkg1/a.go", line: 5},
		{name: "M", receiver: "T", file: "pkg2/b.go", line: 9},
	}
	d, ambiguous := resolveUnique(decls, "(*T).M")
	if d == nil {
		t.Fatal("resolveUnique = nil, want a match (findDeclaration still finds one)")
	}
	if !ambiguous {
		t.Error("two declarations sharing (name, receiver) must be reported ambiguous")
	}
}

func TestResolveUniqueAmbiguousSamePackage(t *testing.T) {
	// Two files in the same directory both declaring a plain function
	// named Foo (e.g. GOOS-tagged variants this per-file scan can't tell
	// are mutually exclusive) must also be ambiguous — the rule is
	// "shared anywhere in the repo", not "shared across directories".
	decls := []declaration{
		{name: "Foo", file: "pkg/a_linux.go", line: 3},
		{name: "Foo", file: "pkg/a_darwin.go", line: 3},
	}
	d, ambiguous := resolveUnique(decls, "Foo")
	if d == nil {
		t.Fatal("resolveUnique = nil, want a match")
	}
	if !ambiguous {
		t.Error("two declarations with the same (name, receiver) in the same directory must still be ambiguous")
	}
}

func TestResolveUniqueNoMatch(t *testing.T) {
	d, ambiguous := resolveUnique(nil, "pkg.Func")
	if d != nil || ambiguous {
		t.Errorf("resolveUnique(nil, ...) = %v, %v, want nil, false", d, ambiguous)
	}
}

func TestResolveUniqueBareNameUniquelyResolved(t *testing.T) {
	// fab-017's exact scenario: a bare name with no written qualifier at
	// all, but only one declaration in the whole repo has that name —
	// it must resolve unambiguously.
	decls := []declaration{
		{name: "isOriginAllowed", file: "rest/internal/cors/handlers.go", line: 40},
	}
	d, ambiguous := resolveUnique(decls, "isOriginAllowed")
	if d == nil || ambiguous {
		t.Errorf("resolveUnique = %v, %v, want a unique match", d, ambiguous)
	}
}
```

- [ ] **Step 3: Run the new tests to verify they fail to compile (resolveUnique doesn't exist yet)**

Run: `go test ./internal/ground/... -run TestResolveUnique`
Expected: FAIL with `undefined: resolveUnique`

- [ ] **Step 4: Implement `resolveUnique` in `internal/ground/ast.go`**

Add immediately after `findDeclaration` (after its closing brace, before `closestDeclaration`):

```go
// resolveUnique resolves value using the same matching rules as
// findDeclaration (unchanged Verified/Evidence behavior for callers),
// then reports whether the resolved declaration's (name, receiver)
// pair is shared by any other declaration anywhere in decls. An
// ambiguous resolution means grounding cannot be sure which
// declaration the claim actually names — dedupe must not fingerprint
// on it, even though the claim is still grounded normally (see
// groundFunctionClaim in ground.go).
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

- [ ] **Step 5: Run the new tests to verify they pass**

Run: `go test ./internal/ground/... -run TestResolveUnique -v`
Expected: PASS for all five.

- [ ] **Step 6: Wire `resolveUnique` into `groundFunctionClaim` in `internal/ground/ground.go`**

Replace:

```go
func groundFunctionClaim(c *report.Claim, l *lazyIndex) {
	idx := l.get()
	if d := findDeclaration(idx.decls, c.Value); d != nil {
		c.Verified = report.TriYes
		c.Evidence = fmt.Sprintf("declared at %s:%d", report.Printable(d.file), d.line)
		return
	}
```

with:

```go
func groundFunctionClaim(c *report.Claim, l *lazyIndex) {
	idx := l.get()
	if d, ambiguous := resolveUnique(idx.decls, c.Value); d != nil {
		c.Verified = report.TriYes
		c.Evidence = fmt.Sprintf("declared at %s:%d", report.Printable(d.file), d.line)
		if ambiguous {
			c.Evidence += " (ambiguous name, cannot fingerprint)"
			return
		}
		c.DeclPkgDir = path.Dir(d.file)
		c.DeclReceiver = d.receiver
		c.DeclName = d.name
		return
	}
```

(`path` is already imported in `ground.go`.)

- [ ] **Step 7: Extend `TestGroundClaimsFileAndFunction` in `internal/ground/ground_test.go` to assert the new fields**

After the existing block that checks `invented`, append:

```go
	parsed := byValue["http2.parseHeaders"]
	if parsed.DeclPkgDir != "internal/http2" || parsed.DeclReceiver != "" || parsed.DeclName != "parseHeaders" {
		t.Errorf("existing function claim = %+v, want resolved declaration identity (internal/http2, \"\", parseHeaders)", parsed)
	}
	if invented.DeclPkgDir != "" || invented.DeclName != "" {
		t.Errorf("invented function claim = %+v, want no declaration identity", invented)
	}
```

- [ ] **Step 8: Add a new test for the ambiguous-claim path in `internal/ground/ground_test.go`**

Append to the end of the file:

```go
func TestGroundClaimsAmbiguousFunctionClaimNeverGetsDeclIdentity(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) string {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q", "-b", "main")
	run("config", "user.email", "test@test.example")
	run("config", "user.name", "test")
	files := map[string]string{
		"pkg1/a.go": "package pkg1\n\ntype T struct{}\n\nfunc (t *T) M() {}\n",
		"pkg2/b.go": "package pkg2\n\ntype T struct{}\n\nfunc (t *T) M() {}\n",
	}
	for name, content := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("add", ".")
	run("commit", "-q", "-m", "init")
	commit := run("rev-parse", "HEAD")

	m, err := OpenMirror(t.TempDir(), "owner/name", dir)
	if err != nil {
		t.Fatal(err)
	}
	r := report.Report{ID: "R1", Repo: "owner/name", ClaimedRef: commit}
	claims := []report.Claim{{Kind: report.ClaimFunction, Value: "(*T).M"}}
	grounded, resolved, _, _, _, err := groundClaims(context.Background(), m, r, claims)
	if err != nil {
		t.Fatal(err)
	}
	if !resolved {
		t.Fatal("want resolved = true")
	}
	c := grounded[0]
	if c.Verified != report.TriYes {
		t.Fatalf("claim = %+v, want Verified: yes (findDeclaration still finds a match)", c)
	}
	if c.DeclPkgDir != "" || c.DeclReceiver != "" || c.DeclName != "" {
		t.Errorf("claim = %+v, want no declaration identity for an ambiguous (name, receiver)", c)
	}
	if !strings.Contains(c.Evidence, "ambiguous") {
		t.Errorf("Evidence = %q, want it to mention the ambiguity", c.Evidence)
	}
}
```

- [ ] **Step 9: Run the full ground package test suite**

Run: `go test ./internal/ground/... -v`
Expected: PASS for everything, including the new and extended tests.

- [ ] **Step 10: Commit**

```bash
git add internal/report/report.go internal/ground/ast.go internal/ground/ast_test.go internal/ground/ground.go internal/ground/ground_test.go
git commit -s -m "feat(ground): resolve claims to a unique declaration identity, not literal claim text"
git push origin main
```

---

### Task 3: Migration + claims persistence (`SaveVerdict`, `GetVerdict`, `ClaimsByRepo`)

**Files:**
- Create: `internal/store/migrations/0002_dedupe_decl_identity.sql`
- Modify: `internal/store/store.go`
- Modify: `internal/store/store_test.go`

**Interfaces:**
- Consumes: `report.Claim.DeclPkgDir/DeclReceiver/DeclName` (Task 2).
- Produces: `claims.decl_pkg_dir/decl_receiver/decl_name` columns, round-tripped by `SaveVerdict`/`GetVerdict`/`ClaimsByRepo` — Task 4/5 read these via the in-memory `report.Claim` values these functions return.

- [ ] **Step 1: Write the migration**

Create `internal/store/migrations/0002_dedupe_decl_identity.sql`:

```sql
ALTER TABLE claims ADD COLUMN decl_pkg_dir  TEXT NOT NULL DEFAULT '';
ALTER TABLE claims ADD COLUMN decl_receiver TEXT NOT NULL DEFAULT '';
ALTER TABLE claims ADD COLUMN decl_name     TEXT NOT NULL DEFAULT '';
```

- [ ] **Step 2: Write a failing test for migration-safety on an existing database**

Add to `internal/store/store_test.go`, near `TestOpenPragmasAndMigrations`:

```go
func TestMigrationBackfillsExistingClaimsRows(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(ctx, filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	r := sampleReport()
	if err := s.SaveReport(ctx, r); err != nil {
		t.Fatal(err)
	}
	// Simulate a claim saved before this migration existed by inserting
	// directly with only the pre-migration columns present in the
	// INSERT — the new columns must still default to '' via the
	// migration's DEFAULT '', not NULL or an error.
	if err := s.SaveVerdict(ctx, report.Verdict{
		ReportID: r.ID, Outcome: report.OutcomeInconclusive,
		Claims: []report.Claim{{Kind: report.ClaimFunction, Value: "pkg.Old", Verified: report.TriYes}},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetVerdict(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Claims) != 1 || got.Claims[0].DeclPkgDir != "" || got.Claims[0].DeclReceiver != "" || got.Claims[0].DeclName != "" {
		t.Fatalf("claim = %+v, want empty decl_* fields for a claim saved with none set", got.Claims[0])
	}
}
```

(This test exercises the migration through the normal `Open`/`SaveVerdict`/`GetVerdict` path rather than hand-crafting a pre-migration schema file, since `modernc.org/sqlite`'s `ALTER TABLE ... ADD COLUMN ... DEFAULT ''` is exactly what every fresh `Open` already applies — the real regression risk this guards is a future migration author breaking the round-trip, not the migration mechanism itself.)

- [ ] **Step 3: Run the test to verify it fails (columns don't exist / claim doesn't round-trip the new fields)**

Run: `go test ./internal/store/... -run TestMigrationBackfillsExistingClaimsRows -v`
Expected: FAIL (compile error or a claim comparison mismatch, since `SaveVerdict`/`GetVerdict` don't yet touch the new columns).

- [ ] **Step 4: Update `SaveVerdict`'s claims INSERT in `internal/store/store.go`**

Replace:

```go
	for i, c := range v.Claims {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO claims (report_id, kind, value, source, verified, evidence)
			VALUES (?, ?, ?, ?, ?, ?)`,
			v.ReportID, string(c.Kind), c.Value, c.Source, string(c.Verified), c.Evidence); err != nil {
			return fmt.Errorf("store: save claim %d for %s: %w", i, v.ReportID, err)
		}
	}
```

with:

```go
	for i, c := range v.Claims {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO claims (report_id, kind, value, source, verified, evidence, decl_pkg_dir, decl_receiver, decl_name)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			v.ReportID, string(c.Kind), c.Value, c.Source, string(c.Verified), c.Evidence, c.DeclPkgDir, c.DeclReceiver, c.DeclName); err != nil {
			return fmt.Errorf("store: save claim %d for %s: %w", i, v.ReportID, err)
		}
	}
```

- [ ] **Step 5: Update `GetVerdict`'s claims SELECT in `internal/store/store.go`**

Replace:

```go
	rows, err := s.db.QueryContext(ctx, `
		SELECT kind, value, source, verified, evidence
		FROM claims WHERE report_id = ? ORDER BY id`, reportID)
	if err != nil {
		return report.Verdict{}, fmt.Errorf("store: get claims for %s: %w", reportID, err)
	}
	defer rows.Close()
	for rows.Next() {
		var c report.Claim
		var kind, verified string
		if err := rows.Scan(&kind, &c.Value, &c.Source, &verified, &c.Evidence); err != nil {
			return report.Verdict{}, fmt.Errorf("store: scan claim for %s: %w", reportID, err)
		}
		c.Kind, c.Verified = report.ClaimKind(kind), report.Tri(verified)
		v.Claims = append(v.Claims, c)
	}
```

with:

```go
	rows, err := s.db.QueryContext(ctx, `
		SELECT kind, value, source, verified, evidence, decl_pkg_dir, decl_receiver, decl_name
		FROM claims WHERE report_id = ? ORDER BY id`, reportID)
	if err != nil {
		return report.Verdict{}, fmt.Errorf("store: get claims for %s: %w", reportID, err)
	}
	defer rows.Close()
	for rows.Next() {
		var c report.Claim
		var kind, verified string
		if err := rows.Scan(&kind, &c.Value, &c.Source, &verified, &c.Evidence, &c.DeclPkgDir, &c.DeclReceiver, &c.DeclName); err != nil {
			return report.Verdict{}, fmt.Errorf("store: scan claim for %s: %w", reportID, err)
		}
		c.Kind, c.Verified = report.ClaimKind(kind), report.Tri(verified)
		v.Claims = append(v.Claims, c)
	}
```

- [ ] **Step 6: Update `ClaimsByRepo`'s SELECT in `internal/store/store.go`**

Replace:

```go
func (s *Store) ClaimsByRepo(ctx context.Context, repo, excludeReportID, excludeSourceRef string) (map[string][]report.Claim, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT c.report_id, c.kind, c.value, c.source, c.verified, c.evidence
		FROM claims c
		JOIN reports r ON r.id = c.report_id
		JOIN verdicts v ON v.report_id = c.report_id
		WHERE r.repo = ? AND c.report_id != ? AND c.kind IN (?, ?)
			AND (? = '' OR r.source_ref != ?)
			AND v.outcome NOT IN (?, ?, ?)`,
		repo, excludeReportID, string(report.ClaimFunction), string(report.ClaimVulnClass),
		excludeSourceRef, excludeSourceRef,
		string(report.OutcomeGroundingFailed), string(report.OutcomeNeedsInfo), string(report.OutcomeLikelyDuplicate))
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
```

with:

```go
func (s *Store) ClaimsByRepo(ctx context.Context, repo, excludeReportID, excludeSourceRef string) (map[string][]report.Claim, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT c.report_id, c.kind, c.value, c.source, c.verified, c.evidence, c.decl_pkg_dir, c.decl_receiver, c.decl_name
		FROM claims c
		JOIN reports r ON r.id = c.report_id
		JOIN verdicts v ON v.report_id = c.report_id
		WHERE r.repo = ? AND c.report_id != ? AND c.kind IN (?, ?)
			AND (? = '' OR r.source_ref != ?)
			AND v.outcome NOT IN (?, ?, ?)`,
		repo, excludeReportID, string(report.ClaimFunction), string(report.ClaimVulnClass),
		excludeSourceRef, excludeSourceRef,
		string(report.OutcomeGroundingFailed), string(report.OutcomeNeedsInfo), string(report.OutcomeLikelyDuplicate))
	if err != nil {
		return nil, fmt.Errorf("store: claims by repo %s: %w", repo, err)
	}
	defer rows.Close()
	out := map[string][]report.Claim{}
	for rows.Next() {
		var reportID, kind, verified string
		var c report.Claim
		if err := rows.Scan(&reportID, &kind, &c.Value, &c.Source, &verified, &c.Evidence, &c.DeclPkgDir, &c.DeclReceiver, &c.DeclName); err != nil {
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
```

- [ ] **Step 7: Extend `TestVerdictRoundTrip` and `TestClaimsByRepo` in `internal/store/store_test.go`**

In `TestVerdictRoundTrip`, change the first claim literal from:

```go
			{Kind: report.ClaimFunction, Value: "http2.parseHeader", Source: "deterministic", Verified: report.TriNo, Evidence: "not declared"},
```

to:

```go
			{Kind: report.ClaimFunction, Value: "http2.parseHeader", Source: "deterministic", Verified: report.TriNo, Evidence: "not declared", DeclPkgDir: "internal/http2", DeclReceiver: "", DeclName: "parseHeader"},
```

(This proves the new columns round-trip through the existing `reflect.DeepEqual` check — no other change to that test is needed.)

In `TestClaimsByRepo`, change:

```go
	if err := s.SaveVerdict(ctx, report.Verdict{
		ReportID: "r1", Outcome: report.OutcomeInconclusive,
		Claims: []report.Claim{
			{Kind: report.ClaimFunction, Value: "(*T).M", Verified: report.TriYes},
			{Kind: report.ClaimFile, Value: "a.go", Verified: report.TriUnknown}, // not function/vuln_class: excluded
		},
	}); err != nil {
		t.Fatal(err)
	}
```

to:

```go
	if err := s.SaveVerdict(ctx, report.Verdict{
		ReportID: "r1", Outcome: report.OutcomeInconclusive,
		Claims: []report.Claim{
			{Kind: report.ClaimFunction, Value: "(*T).M", Verified: report.TriYes, DeclPkgDir: "pkg", DeclReceiver: "T", DeclName: "M"},
			{Kind: report.ClaimFile, Value: "a.go", Verified: report.TriUnknown}, // not function/vuln_class: excluded
		},
	}); err != nil {
		t.Fatal(err)
	}
```

and after the existing assertion block, append:

```go
	if got["r1"][0].DeclPkgDir != "pkg" || got["r1"][0].DeclReceiver != "T" || got["r1"][0].DeclName != "M" {
		t.Errorf("ClaimsByRepo = %+v, want the decl_* columns round-tripped", got["r1"][0])
	}
```

- [ ] **Step 8: Run the full store package test suite**

Run: `go test ./internal/store/... -v`
Expected: PASS for everything.

- [ ] **Step 9: Commit**

```bash
git add internal/store/migrations/0002_dedupe_decl_identity.sql internal/store/store.go internal/store/store_test.go
git commit -s -m "feat(store): persist resolved declaration identity on claims"
git push origin main
```

---

### Task 4: `internal/dedupe/fingerprint.go` — fingerprint on resolved identity

**Files:**
- Modify: `internal/dedupe/fingerprint.go`
- Modify: `internal/dedupe/fingerprint_test.go`

**Interfaces:**
- Consumes: `report.Claim.DeclPkgDir/DeclReceiver/DeclName` (Task 2).
- Produces: `fingerprint{repo, pkgDir, receiver, name, vulnClass string}` and `claimFingerprints(repo string, claims []report.Claim) []fingerprint` — Task 5's `dedupe.Service.Dedupe` (already calls `claimFingerprints`; only its evidence-string formatting needs to change, in Task 5) and its tests read `fingerprint.pkgDir`/`.receiver`/`.name` field names.

- [ ] **Step 1: Write the failing tests in `internal/dedupe/fingerprint_test.go`**

Replace the entire file:

```go
package dedupe

import (
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/ground"
	"github.com/ergasterion-dev/kritolith/internal/report"
)

func TestClaimFingerprints(t *testing.T) {
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*parser).peek", Verified: report.TriYes, DeclPkgDir: "yaml", DeclReceiver: "parser", DeclName: "peek"},
		{Kind: report.ClaimFunction, Value: "unverified.Func", Verified: report.TriUnknown, DeclPkgDir: "yaml", DeclName: "Func"},
		{Kind: report.ClaimFunction, Value: "Ambiguous", Verified: report.TriYes}, // resolved but ambiguous: no Decl* fields set
		{Kind: report.ClaimVulnClass, Value: "  Out-Of-Bounds Read  "},
	}
	got := claimFingerprints("go-yaml/yaml", claims)
	if len(got) != 1 {
		t.Fatalf("claimFingerprints = %+v, want exactly 1", got)
	}
	want := fingerprint{repo: "go-yaml/yaml", pkgDir: "yaml", receiver: "parser", name: "peek", vulnClass: "out-of-bounds read"}
	if got[0] != want {
		t.Errorf("claimFingerprints[0] = %+v, want %+v", got[0], want)
	}
}

func TestClaimFingerprintsNoVulnClass(t *testing.T) {
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*parser).peek", Verified: report.TriYes, DeclPkgDir: "yaml", DeclReceiver: "parser", DeclName: "peek"},
	}
	if got := claimFingerprints("go-yaml/yaml", claims); len(got) != 0 {
		t.Errorf("claimFingerprints = %+v, want none without a vuln_class claim", got)
	}
}

func TestClaimFingerprintsUnresolvedNeverContributes(t *testing.T) {
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "Read", Verified: report.TriYes}, // Verified but Decl* empty: unresolved or ambiguous
		{Kind: report.ClaimVulnClass, Value: "race"},
	}
	if got := claimFingerprints("owner/repo", claims); len(got) != 0 {
		t.Errorf("claimFingerprints = %+v, want none for a claim with no resolved declaration identity", got)
	}
}

func TestClaimFingerprintsBareNameFingerprintsWhenUniquelyResolved(t *testing.T) {
	// fab-017's own scenario: a bare name (no written qualifier) that
	// grounding resolved to one unambiguous declaration must fingerprint
	// exactly like a qualified claim would.
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "isOriginAllowed", Verified: report.TriYes, DeclPkgDir: "rest/internal/cors", DeclName: "isOriginAllowed"},
		{Kind: report.ClaimVulnClass, Value: "CORS misconfiguration"},
	}
	got := claimFingerprints("zeromicro/go-zero", claims)
	if len(got) != 1 {
		t.Fatalf("claimFingerprints = %+v, want exactly 1", got)
	}
	want := fingerprint{repo: "zeromicro/go-zero", pkgDir: "rest/internal/cors", name: "isOriginAllowed", vulnClass: "cors misconfiguration"}
	if got[0] != want {
		t.Errorf("claimFingerprints[0] = %+v, want %+v", got[0], want)
	}
}

func TestFingerprintMatches(t *testing.T) {
	a := fingerprint{repo: "r", pkgDir: "pkg", receiver: "T", name: "n", vulnClass: "v"}
	tests := []struct {
		name string
		b    fingerprint
		want bool
	}{
		{"identical", a, true},
		{"different repo", fingerprint{repo: "other", pkgDir: "pkg", receiver: "T", name: "n", vulnClass: "v"}, false},
		{"different pkgDir", fingerprint{repo: "r", pkgDir: "other", receiver: "T", name: "n", vulnClass: "v"}, false},
		{"different receiver", fingerprint{repo: "r", pkgDir: "pkg", receiver: "Other", name: "n", vulnClass: "v"}, false},
		{"empty vs non-empty receiver", fingerprint{repo: "r", pkgDir: "pkg", receiver: "", name: "n", vulnClass: "v"}, false},
		{"different vuln class", fingerprint{repo: "r", pkgDir: "pkg", receiver: "T", name: "n", vulnClass: "other"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := a.matches(tt.b); got != tt.want {
				t.Errorf("matches = %v, want %v", got, tt.want)
			}
		})
	}
	plainA := fingerprint{repo: "r", pkgDir: "pkg", name: "n", vulnClass: "v"}
	plainB := fingerprint{repo: "r", pkgDir: "pkg", name: "n", vulnClass: "v"}
	if !plainA.matches(plainB) {
		t.Error("two plain-function fingerprints (both empty receiver) must match each other")
	}
	emptyPkgDir := fingerprint{repo: "r", pkgDir: "", name: "n", vulnClass: "v"}
	if emptyPkgDir.matches(emptyPkgDir) {
		t.Error("two fingerprints both with an empty pkgDir must never match each other")
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

(`TestSplitFunctionClaimExported` stays: `ground.SplitFunctionClaim` is still used by the OSV-matching path in `service.go`, unchanged by this task.)

- [ ] **Step 2: Run the tests to verify they fail to compile (fingerprint's fields don't exist yet)**

Run: `go test ./internal/dedupe/... -run TestClaimFingerprints -v`
Expected: FAIL — `fingerprint` still has `qualifier`, not `pkgDir`/`receiver`.

- [ ] **Step 3: Rewrite `internal/dedupe/fingerprint.go`**

Replace the entire file:

```go
// Package dedupe flags likely-duplicate reports by matching grounded
// claims against prior reports and the local OSV mirror, and by
// embedding similarity when an LLM provider is configured. Only an
// exact fingerprint match against a prior report is strong enough to
// set a report's outcome to LIKELY_DUPLICATE — a false one is exactly
// as bad as a false GROUNDING_FAILED. Weaker signals (OSV symbol
// matches, which don't yet check affected versions or vuln_class, and
// embedding similarity) are recorded as leads only.
package dedupe

import (
	"strings"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// fingerprint is a normalized, exact-match-only identity for one
// (resolved function declaration, vuln_class claim) pair. pkgDir,
// receiver, and name come from where grounding actually found the
// declaration — never from the claim's literal written text — and
// only when that declaration is unique in the repo (see
// ground.resolveUnique, via report.Claim.DeclPkgDir/DeclReceiver/DeclName):
// a claim whose resolution is ambiguous carries no declaration
// identity at all and can never fingerprint. repo, pkgDir, name, and
// vulnClass must all be non-empty for two fingerprints to match;
// receiver may legitimately be empty on both sides (a plain function,
// not an unresolved one).
type fingerprint struct {
	repo      string
	pkgDir    string
	receiver  string
	name      string
	vulnClass string
}

// matches reports whether a and b identify the same claimed
// vulnerability.
func (a fingerprint) matches(b fingerprint) bool {
	return a.repo != "" && a.repo == b.repo &&
		a.pkgDir != "" && a.pkgDir == b.pkgDir &&
		a.receiver == b.receiver &&
		a.name != "" && a.name == b.name &&
		a.vulnClass != "" && a.vulnClass == b.vulnClass
}

// claimFingerprints returns every exact-tier-eligible fingerprint
// derivable from claims: the cross product of every verified
// (Verified: yes) function claim whose declaration grounding resolved
// uniquely (DeclPkgDir and DeclName both set — see
// ground.groundFunctionClaim) with every vuln_class claim. A function
// claim grounding couldn't resolve to one unambiguous declaration
// never contributes, regardless of whether the claim text itself was
// qualified or bare.
func claimFingerprints(repo string, claims []report.Claim) []fingerprint {
	type decl struct{ pkgDir, receiver, name string }
	var funcs []decl
	var vulnClasses []string
	for _, c := range claims {
		switch c.Kind {
		case report.ClaimFunction:
			if c.Verified != report.TriYes {
				continue
			}
			if c.DeclPkgDir == "" || c.DeclName == "" {
				continue
			}
			funcs = append(funcs, decl{pkgDir: c.DeclPkgDir, receiver: c.DeclReceiver, name: c.DeclName})
		case report.ClaimVulnClass:
			if v := strings.ToLower(strings.TrimSpace(c.Value)); v != "" {
				vulnClasses = append(vulnClasses, v)
			}
		}
	}
	var out []fingerprint
	for _, f := range funcs {
		for _, vc := range vulnClasses {
			out = append(out, fingerprint{repo: repo, pkgDir: f.pkgDir, receiver: f.receiver, name: f.name, vulnClass: vc})
		}
	}
	return out
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/dedupe/... -run 'TestClaimFingerprints|TestFingerprintMatches|TestSplitFunctionClaimExported' -v`
Expected: PASS for all.

(`go test ./internal/dedupe/...` as a whole will still fail at this point — `service.go`'s evidence-string formatting and `service_test.go`'s claim literals aren't updated yet. That's Task 5.)

- [ ] **Step 5: Commit**

```bash
git add internal/dedupe/fingerprint.go internal/dedupe/fingerprint_test.go
git commit -s -m "feat(dedupe): fingerprint on resolved declaration identity, not literal claim text"
git push origin main
```

---

### Task 5: `internal/dedupe/service.go` wiring + `EmbeddingsByRepo` exclusions (G-DEDUPE2)

**Files:**
- Modify: `internal/dedupe/service.go`
- Modify: `internal/dedupe/service_test.go`
- Modify: `internal/store/store.go`
- Modify: `internal/store/store_test.go`

**Interfaces:**
- Consumes: `fingerprint{pkgDir, receiver, name, vulnClass}` (Task 4).
- Produces: `Store.EmbeddingsByRepo(ctx, repo, excludeReportID, excludeSourceRef string) (map[string]Embedding, error)` (signature grows one parameter) — no other package calls this besides `dedupe.Service.Dedupe`, updated in this same task.

This task bundles the `EmbeddingsByRepo` fix in because it's the same file (`store.go`) and the same consumer (`service.go`) already being touched here — keeping it in a separate task would mean an intermediate non-compiling state.

- [ ] **Step 1: Mirror `ClaimsByRepo`'s exclusions onto `EmbeddingsByRepo` in `internal/store/store.go`**

Replace:

```go
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
```

with:

```go
// EmbeddingsByRepo returns every stored embedding for reports in repo
// other than excludeReportID, keyed by report ID. It excludes
// excludeSourceRef (mirroring ClaimsByRepo — a re-run of the same
// report under a reused data dir must never show its own earlier run
// as an embedding lead) and reports whose verdict outcome makes them
// untrustworthy anchors (GROUNDING_FAILED, NEEDS_INFO,
// LIKELY_DUPLICATE), same as ClaimsByRepo. This can never change
// dedupe's Outcome — an embedding lead never does — but keeping both
// queries consistent avoids a confusing display-only discrepancy. It
// also can never exclude the current report's own just-saved
// embedding on a later call: every caller already excludes the
// current report by ID regardless of whether its own verdict exists
// yet (Dedupe saves a report's embedding before that report's own
// verdict is saved).
func (s *Store) EmbeddingsByRepo(ctx context.Context, repo, excludeReportID, excludeSourceRef string) (map[string]Embedding, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT e.report_id, e.model, e.dims, e.vector
		FROM embeddings e
		JOIN reports r ON r.id = e.report_id
		JOIN verdicts v ON v.report_id = e.report_id
		WHERE r.repo = ? AND e.report_id != ?
			AND (? = '' OR r.source_ref != ?)
			AND v.outcome NOT IN (?, ?, ?)`,
		repo, excludeReportID, excludeSourceRef, excludeSourceRef,
		string(report.OutcomeGroundingFailed), string(report.OutcomeNeedsInfo), string(report.OutcomeLikelyDuplicate))
	if err != nil {
		return nil, fmt.Errorf("store: embeddings by repo %s: %w", repo, err)
	}
```

- [ ] **Step 2: Update `internal/dedupe/service.go`'s two changes: the `EmbeddingsByRepo` call and the fingerprint evidence string**

Replace:

```go
			if others, err := s.store.EmbeddingsByRepo(ctx, r.Repo, r.ID); err != nil {
```

with:

```go
			if others, err := s.store.EmbeddingsByRepo(ctx, r.Repo, r.ID, r.SourceRef); err != nil {
```

Replace:

```go
	if mine := claimFingerprints(r.Repo, claims); len(mine) > 0 {
		if prior, err := s.store.ClaimsByRepo(ctx, r.Repo, r.ID, r.SourceRef); err != nil {
			slog.Default().Warn("dedupe: could not load prior claims, skipping fingerprint match",
				"report_id", r.ID, "error", err)
		} else {
			for reportID, cs := range prior {
				theirs := claimFingerprints(r.Repo, cs)
				for _, a := range mine {
					for _, b := range theirs {
						if a.matches(b) {
							candidates = append(candidates, candidate{
								match: report.DupMatch{
									ReportID: reportID,
									Score:    1.0,
									Evidence: fmt.Sprintf("fingerprint match: %s.%s (%s)", a.qualifier, a.name, a.vulnClass),
								},
								exact: true,
							})
							exact = true
						}
					}
				}
			}
		}
	}
```

with:

```go
	if mine := claimFingerprints(r.Repo, claims); len(mine) > 0 {
		if prior, err := s.store.ClaimsByRepo(ctx, r.Repo, r.ID, r.SourceRef); err != nil {
			slog.Default().Warn("dedupe: could not load prior claims, skipping fingerprint match",
				"report_id", r.ID, "error", err)
		} else {
			for reportID, cs := range prior {
				theirs := claimFingerprints(r.Repo, cs)
				for _, a := range mine {
					for _, b := range theirs {
						if a.matches(b) {
							name := a.name
							if a.receiver != "" {
								name = a.receiver + "." + a.name
							}
							candidates = append(candidates, candidate{
								match: report.DupMatch{
									ReportID: reportID,
									Score:    1.0,
									Evidence: fmt.Sprintf("fingerprint match: %s (%s) in %s", name, a.vulnClass, a.pkgDir),
								},
								exact: true,
							})
							exact = true
						}
					}
				}
			}
		}
	}
```

- [ ] **Step 3: Update `internal/dedupe/service_test.go`**

Replace the whole file's claim literals and evidence assertions as follows (every other test in the file — the OSV-only and empty-store tests — is unaffected, since neither has a prior report whose fingerprint could match regardless of Decl* fields):

In `TestServiceDedupeExactFingerprintMatch`, replace:

```go
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*parser).peek", Verified: report.TriYes},
		{Kind: report.ClaimVulnClass, Value: "out-of-bounds read", Verified: report.TriUnknown},
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
	if want := "fingerprint match: parser.peek (out-of-bounds read)"; matches[0].Evidence != want {
		t.Errorf("Evidence = %q, want %q", matches[0].Evidence, want)
	}
```

with:

```go
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*parser).peek", Verified: report.TriYes, DeclPkgDir: "yaml", DeclReceiver: "parser", DeclName: "peek"},
		{Kind: report.ClaimVulnClass, Value: "out-of-bounds read", Verified: report.TriUnknown},
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
	if want := "fingerprint match: parser.peek (out-of-bounds read) in yaml"; matches[0].Evidence != want {
		t.Errorf("Evidence = %q, want %q", matches[0].Evidence, want)
	}
```

Replace `TestServiceDedupeBareNameNeverMatches` (rename and change its meaning — a bare name is no longer specially excluded; what still never matches is a claim with no resolved declaration identity) with:

```go
func TestServiceDedupeUnresolvedClaimNeverMatches(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	defer s.Close()

	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "Read", Verified: report.TriYes}, // no Decl* fields: unresolved or ambiguous
		{Kind: report.ClaimVulnClass, Value: "race", Verified: report.TriUnknown},
	}
	saveReportWithClaims(t, s, "prior", "owner/repo", claims)

	svc := NewService(s, nil)
	matches, exact := svc.Dedupe(ctx, report.Report{ID: "new", Repo: "owner/repo"}, claims, "")
	if exact || len(matches) != 0 {
		t.Errorf("matches = %+v, exact = %v; two reports sharing a claim with no resolved declaration identity must never match", matches, exact)
	}
}

func TestServiceDedupeBareNameMatchesWhenUniquelyResolved(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	defer s.Close()

	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "isOriginAllowed", Verified: report.TriYes, DeclPkgDir: "rest/internal/cors", DeclName: "isOriginAllowed"},
		{Kind: report.ClaimVulnClass, Value: "CORS misconfiguration", Verified: report.TriUnknown},
	}
	saveReportWithClaims(t, s, "prior", "owner/repo", claims)

	svc := NewService(s, nil)
	matches, exact := svc.Dedupe(ctx, report.Report{ID: "new", Repo: "owner/repo"}, claims, "")
	if !exact || len(matches) != 1 || matches[0].ReportID != "prior" {
		t.Fatalf("matches = %+v, exact = %v; a bare-name claim resolved to one unambiguous declaration must fingerprint-match", matches, exact)
	}
}
```

In `TestServiceDedupeDegradesOnClosedStore`, `TestServiceDedupeDeterministicOrder`, `TestServiceDedupeSameSourceRefNeverSelfMatches`, and `TestServiceDedupeRejectedPriorNeverAnchors`, replace every occurrence of:

```go
		{Kind: report.ClaimFunction, Value: "(*T).M", Verified: report.TriYes},
```

with:

```go
		{Kind: report.ClaimFunction, Value: "(*T).M", Verified: report.TriYes, DeclPkgDir: "pkg", DeclReceiver: "T", DeclName: "M"},
```

(`TestServiceDedupeEmptyStoreNoMatch` keeps its `(*T).M` claim unchanged — there is no prior report in that test, so no Decl* fields are needed for the assertion to hold, but adding them does no harm; leave as-is to minimize the diff.)

In `TestServiceDedupeFingerprintStillExactAlongsideOSVLead`, replace:

```go
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*parser).peek", Verified: report.TriYes},
		{Kind: report.ClaimVulnClass, Value: "out-of-bounds read", Verified: report.TriUnknown},
	}
```

with:

```go
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*parser).peek", Verified: report.TriYes, DeclPkgDir: "yaml", DeclReceiver: "parser", DeclName: "peek"},
		{Kind: report.ClaimVulnClass, Value: "out-of-bounds read", Verified: report.TriUnknown},
	}
```

In `TestServiceDedupeCollapsesMatchesPerIdentity`, replace:

```go
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*parser).peek", Verified: report.TriYes},
		{Kind: report.ClaimFunction, Value: "parser.peek", Verified: report.TriYes},
		{Kind: report.ClaimFunction, Value: "(*parser).advance", Verified: report.TriYes},
		{Kind: report.ClaimVulnClass, Value: "out-of-bounds read", Verified: report.TriUnknown},
		{Kind: report.ClaimVulnClass, Value: "panic", Verified: report.TriUnknown},
	}
	saveReportWithClaims(t, s, "prior", "go-yaml/yaml", claims)
	saveReportWithClaims(t, s, "other", "go-yaml/yaml", []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*parser).advance", Verified: report.TriYes},
		{Kind: report.ClaimVulnClass, Value: "panic", Verified: report.TriUnknown},
	})
```

with:

```go
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*parser).peek", Verified: report.TriYes, DeclPkgDir: "yaml", DeclReceiver: "parser", DeclName: "peek"},
		{Kind: report.ClaimFunction, Value: "parser.peek", Verified: report.TriYes, DeclPkgDir: "yaml", DeclReceiver: "parser", DeclName: "peek"},
		{Kind: report.ClaimFunction, Value: "(*parser).advance", Verified: report.TriYes, DeclPkgDir: "yaml", DeclReceiver: "parser", DeclName: "advance"},
		{Kind: report.ClaimVulnClass, Value: "out-of-bounds read", Verified: report.TriUnknown},
		{Kind: report.ClaimVulnClass, Value: "panic", Verified: report.TriUnknown},
	}
	saveReportWithClaims(t, s, "prior", "go-yaml/yaml", claims)
	saveReportWithClaims(t, s, "other", "go-yaml/yaml", []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*parser).advance", Verified: report.TriYes, DeclPkgDir: "yaml", DeclReceiver: "parser", DeclName: "advance"},
		{Kind: report.ClaimVulnClass, Value: "panic", Verified: report.TriUnknown},
	})
```

- [ ] **Step 4: Update `TestServiceDedupeEmbeddingLeadNeverSetsExact` in `internal/dedupe/service_test.go` for the new `EmbeddingsByRepo` signature and its verdict requirement**

Replace:

```go
	if err := s.SaveReport(ctx, report.Report{ID: "prior", Repo: "owner/repo", ReceivedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEmbedding(ctx, "prior", "fake-embed", []float32{1, 0, 0}); err != nil {
		t.Fatal(err)
	}
```

with:

```go
	savePrior(t, s, report.Report{ID: "prior", Repo: "owner/repo"}, report.OutcomeInconclusive, nil)
	if err := s.SaveEmbedding(ctx, "prior", "fake-embed", []float32{1, 0, 0}); err != nil {
		t.Fatal(err)
	}
```

and replace:

```go
	stored, err := s.EmbeddingsByRepo(ctx, "owner/repo", "prior")
```

with:

```go
	stored, err := s.EmbeddingsByRepo(ctx, "owner/repo", "prior", "")
```

- [ ] **Step 5: Update `internal/store/store_test.go`'s `TestSaveAndFindEmbeddingsByRepo` and add two new exclusion tests**

Replace:

```go
func TestSaveAndFindEmbeddingsByRepo(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)

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

with:

```go
func TestSaveAndFindEmbeddingsByRepo(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)

	for _, id := range []string{"r1", "r2"} {
		saveAnchor(t, s, id, "", report.OutcomeInconclusive)
	}
	vec := []float32{0.1, 0.2, 0.3}
	if err := s.SaveEmbedding(ctx, "r1", "local-embed", vec); err != nil {
		t.Fatal(err)
	}

	got, err := s.EmbeddingsByRepo(ctx, "owner/repo", "r2", "")
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
	got, err = s.EmbeddingsByRepo(ctx, "owner/repo", "r2", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got["r1"].Vector) != 1 {
		t.Fatalf("EmbeddingsByRepo after overwrite = %+v, want a single-element vector", got)
	}
}

func TestEmbeddingsByRepoExcludesSameSourceRef(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)

	saveAnchor(t, s, "first-run", "/corpus/real/a/report.md", report.OutcomeInconclusive)
	if err := s.SaveEmbedding(ctx, "first-run", "local-embed", []float32{1}); err != nil {
		t.Fatal(err)
	}

	got, err := s.EmbeddingsByRepo(ctx, "owner/repo", "second-run", "/corpus/real/a/report.md")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["first-run"]; ok {
		t.Error("EmbeddingsByRepo must exclude a prior report with the same SourceRef (a re-run of the same report)")
	}
}

func TestEmbeddingsByRepoExcludesRejectedAnchors(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)

	saveAnchor(t, s, "grounding-failed", "", report.OutcomeGroundingFailed)
	if err := s.SaveEmbedding(ctx, "grounding-failed", "local-embed", []float32{1}); err != nil {
		t.Fatal(err)
	}
	saveAnchor(t, s, "inconclusive", "", report.OutcomeInconclusive)
	if err := s.SaveEmbedding(ctx, "inconclusive", "local-embed", []float32{1}); err != nil {
		t.Fatal(err)
	}

	got, err := s.EmbeddingsByRepo(ctx, "owner/repo", "new", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["grounding-failed"]; ok {
		t.Error("EmbeddingsByRepo must exclude a GROUNDING_FAILED prior report")
	}
	if _, ok := got["inconclusive"]; !ok {
		t.Error("EmbeddingsByRepo must keep a normal prior report")
	}
}
```

- [ ] **Step 6: Run the full dedupe and store package test suites**

Run: `go test ./internal/dedupe/... ./internal/store/... -v`
Expected: PASS for everything.

- [ ] **Step 7: Commit**

```bash
git add internal/dedupe/service.go internal/dedupe/service_test.go internal/store/store.go internal/store/store_test.go
git commit -s -m "fix(dedupe,store): wire resolved-identity fingerprinting through service, close EmbeddingsByRepo exclusion gap"
git push origin main
```

---

### Task 6: Scoreboard top-1-identity check (G-DEDUPE2) + corpus wiring

**Files:**
- Modify: `internal/eval/corpus.go`
- Modify: `internal/eval/corpus_test.go`
- Modify: `internal/eval/score.go`
- Modify: `internal/eval/score_test.go`
- Modify: `cmd/kritolith/eval.go`
- Modify: `testdata/corpus/fabricated/fab-015-*/meta.json`
- Modify: `testdata/corpus/fabricated/fab-016-*/meta.json`
- Modify: `testdata/corpus/fabricated/fab-017-near-duplicate/meta.json`

**Interfaces:**
- Consumes: nothing from earlier tasks (independent of grounding/dedupe internals — only `report.Outcome`/`report.DupMatch`, which are unchanged).
- Produces: `eval.CheckResult{Outcome report.Outcome, ReportID string, Duplicates []report.DupMatch}`, `eval.CheckFunc func(ctx, Case) (CheckResult, error)`, `Scoreboard.DuplicateTop1Accuracy() (correct, total int)` — Task 7's live-corpus run reads the new summary line these produce.

- [ ] **Step 1: Add `ExpectedDuplicateOf` to `Meta` and cross-case validation to `LoadCorpus` in `internal/eval/corpus.go`**

Replace:

```go
// Meta is a case's meta.json.
type Meta struct {
	Repo     string         `json:"repo"`
	Ref      string         `json:"ref"`
	Expected report.Outcome `json:"expected_outcome"`
	Source   string         `json:"source"` // GHSA-/GO- id for real, "fabricated" otherwise
	Notes    string         `json:"notes,omitempty"`
}
```

with:

```go
// Meta is a case's meta.json.
type Meta struct {
	Repo     string         `json:"repo"`
	Ref      string         `json:"ref"`
	Expected report.Outcome `json:"expected_outcome"`
	Source   string         `json:"source"` // GHSA-/GO- id for real, "fabricated" otherwise
	// ExpectedDuplicateOf is another case's ID this case is a
	// near-duplicate of: Scoreboard.DuplicateTop1Accuracy checks that
	// the LIKELY_DUPLICATE verdict's top match actually points at that
	// case's report, not merely that the outcome came out right.
	ExpectedDuplicateOf string `json:"expected_duplicate_of,omitempty"`
	Notes                string `json:"notes,omitempty"`
}
```

Then, in `loadCase`, after the existing `switch kind { ... }` block and before `return Case{ID: id, Kind: kind, Dir: dir, Meta: m}, nil`, add:

```go
	if m.ExpectedDuplicateOf != "" {
		if !caseIDRe.MatchString(m.ExpectedDuplicateOf) {
			return fail("expected_duplicate_of must be a valid case id, got %q", m.ExpectedDuplicateOf)
		}
		if m.Expected != report.OutcomeLikelyDuplicate {
			return fail("expected_duplicate_of is only meaningful when expected_outcome is LIKELY_DUPLICATE")
		}
	}
```

Then, in `LoadCorpus`, replace the final `return cases, nil` with cross-case validation that every `ExpectedDuplicateOf` names a case that was actually loaded:

```go
	ids := map[string]bool{}
	for _, c := range cases {
		ids[c.ID] = true
	}
	for _, c := range cases {
		if c.Meta.ExpectedDuplicateOf != "" && !ids[c.Meta.ExpectedDuplicateOf] {
			return nil, fmt.Errorf("eval: %s/%s: expected_duplicate_of %q does not match any loaded case id", c.Kind, c.ID, c.Meta.ExpectedDuplicateOf)
		}
	}
	return cases, nil
```

- [ ] **Step 2: Add tests for the new validation to `internal/eval/corpus_test.go`**

Add two new rows to `TestLoadCorpusRejects`'s `tests` slice:

```go
		{"expected_duplicate_of not LIKELY_DUPLICATE", "fabricated", "f1", `{"repo":"a/b","ref":"` + sha + `","expected_outcome":"INCONCLUSIVE","source":"fabricated","expected_duplicate_of":"go-2024-0001"}`, "only meaningful"},
		{"expected_duplicate_of bad id shape", "fabricated", "f1", `{"repo":"a/b","ref":"` + sha + `","expected_outcome":"LIKELY_DUPLICATE","source":"fabricated","expected_duplicate_of":"Bad_ID"}`, "valid case id"},
```

Add a new test function after `TestLoadCorpusRejects`:

```go
func TestLoadCorpusRejectsUnknownExpectedDuplicateOf(t *testing.T) {
	root := t.TempDir()
	writeCase(t, root, "fabricated", "f1", `{"repo":"a/b","ref":"`+sha+`","expected_outcome":"LIKELY_DUPLICATE","source":"fabricated","expected_duplicate_of":"no-such-case"}`)
	_, err := LoadCorpus(root)
	if err == nil || !strings.Contains(err.Error(), "does not match any loaded case id") {
		t.Fatalf("err = %v, want it to reject an expected_duplicate_of naming no loaded case", err)
	}
}

func TestLoadCorpusAcceptsExpectedDuplicateOf(t *testing.T) {
	root := t.TempDir()
	writeCase(t, root, "real", "go-2024-0001", `{"repo":"golang/net","ref":"`+sha+`","expected_outcome":"REPRODUCED","source":"GO-2024-0001"}`)
	writeCase(t, root, "fabricated", "f1", `{"repo":"golang/net","ref":"`+sha+`","expected_outcome":"LIKELY_DUPLICATE","source":"fabricated","expected_duplicate_of":"go-2024-0001"}`)
	cases, err := LoadCorpus(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 2 || cases[1].Meta.ExpectedDuplicateOf != "go-2024-0001" {
		t.Fatalf("cases = %+v", cases)
	}
}
```

- [ ] **Step 3: Run the corpus tests to verify they pass**

Run: `go test ./internal/eval/... -run TestLoadCorpus -v`
Expected: PASS for all (existing and new).

- [ ] **Step 4: Add `CheckResult`, update `Result`/`CheckFunc`/`Run`, and add `DuplicateTop1Accuracy` in `internal/eval/score.go`**

Replace:

```go
// CheckFunc runs one case through Kritolith and returns its outcome.
type CheckFunc func(ctx context.Context, c Case) (report.Outcome, error)

// Result is one case's outcome.
type Result struct {
	Case Case
	Got  report.Outcome
	Err  error
}

// Scoreboard summarizes an eval run.
type Scoreboard struct {
	Results []Result
}

// Run checks every case. A failing case is recorded, not fatal.
func Run(ctx context.Context, cases []Case, check CheckFunc) Scoreboard {
	var sb Scoreboard
	for _, c := range cases {
		got, err := check(ctx, c)
		sb.Results = append(sb.Results, Result{Case: c, Got: got, Err: err})
	}
	return sb
}
```

with:

```go
// CheckResult is what one case run through Kritolith produced.
type CheckResult struct {
	Outcome    report.Outcome
	ReportID   string
	Duplicates []report.DupMatch
}

// CheckFunc runs one case through Kritolith and returns its result.
type CheckFunc func(ctx context.Context, c Case) (CheckResult, error)

// Result is one case's outcome.
type Result struct {
	Case       Case
	Got        report.Outcome
	ReportID   string
	Duplicates []report.DupMatch
	Err        error
}

// Scoreboard summarizes an eval run.
type Scoreboard struct {
	Results []Result
}

// Run checks every case. A failing case is recorded, not fatal.
func Run(ctx context.Context, cases []Case, check CheckFunc) Scoreboard {
	var sb Scoreboard
	for _, c := range cases {
		res, err := check(ctx, c)
		sb.Results = append(sb.Results, Result{Case: c, Got: res.Outcome, ReportID: res.ReportID, Duplicates: res.Duplicates, Err: err})
	}
	return sb
}
```

Add a new method after `FabricatedLikelyDuplicates`:

```go
// DuplicateTop1Accuracy returns how many cases whose Meta.ExpectedDuplicateOf
// is set had a top-ranked duplicate match pointing at that target case's
// own report, out of how many such cases exist. This is the actual
// instrument behind CLAUDE.md's "duplicate top-1 accuracy >= 80%" target:
// FabricatedLikelyDuplicates only checks the outcome, never whether the
// matched prior report is the *correct* one.
func (s Scoreboard) DuplicateTop1Accuracy() (correct, total int) {
	reportIDs := map[string]string{} // case ID -> its own run's report ID
	for _, r := range s.Results {
		if r.Err == nil && r.ReportID != "" {
			reportIDs[r.Case.ID] = r.ReportID
		}
	}
	for _, r := range s.Results {
		if r.Case.Meta.ExpectedDuplicateOf == "" {
			continue
		}
		total++
		want := reportIDs[r.Case.Meta.ExpectedDuplicateOf]
		if want != "" && len(r.Duplicates) > 0 && r.Duplicates[0].ReportID == want {
			correct++
		}
	}
	return correct, total
}
```

Replace the `Write` method's summary block:

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

with:

```go
	caught, total := s.FabricatedCaught()
	dupCorrect, dupTotal := s.DuplicateTop1Accuracy()
	_, err := fmt.Fprintf(w, `
Summary
  cases:                                 %d
  exact matches:                         %d/%d
  real wrongly GROUNDING_FAILED:         %d (must be 0)
  real wrongly LIKELY_DUPLICATE:         %d (must be 0)
  fabricated caught by grounding:        %d/%d
  fabricated wrongly LIKELY_DUPLICATE:   %d
  duplicate top-1 accuracy:              %d/%d
  errors:                                %d
`, len(s.Results), s.Matches(), len(s.Results), s.RealGroundingFailures(), s.RealLikelyDuplicates(), caught, total, s.FabricatedLikelyDuplicates(), dupCorrect, dupTotal, s.Errors())
	return err
```

- [ ] **Step 5: Update `TestRunAndScore` and add `TestDuplicateTop1Accuracy` in `internal/eval/score_test.go`**

Replace:

```go
	sb := Run(context.Background(), cases, func(_ context.Context, c Case) (report.Outcome, error) {
		if c.ID == "f3" {
			return "", errors.New("boom")
		}
		return got[c.ID], nil
	})
```

with:

```go
	sb := Run(context.Background(), cases, func(_ context.Context, c Case) (CheckResult, error) {
		if c.ID == "f3" {
			return CheckResult{}, errors.New("boom")
		}
		return CheckResult{Outcome: got[c.ID]}, nil
	})
```

Add a new test after `TestFabricatedLikelyDuplicates`:

```go
func TestDuplicateTop1Accuracy(t *testing.T) {
	sb := Scoreboard{Results: []Result{
		{Case: Case{ID: "real-1", Kind: KindReal, Meta: Meta{Expected: report.OutcomeReproduced}}, Got: report.OutcomeReproduced, ReportID: "run-id-real-1"},
		// Correct: points at real-1's actual report ID.
		{Case: Case{ID: "dup-correct", Kind: KindFabricated, Meta: Meta{Expected: report.OutcomeLikelyDuplicate, ExpectedDuplicateOf: "real-1"}},
			Got: report.OutcomeLikelyDuplicate, ReportID: "run-id-dup-correct", Duplicates: []report.DupMatch{{ReportID: "run-id-real-1", Score: 1.0}}},
		// Wrong: outcome is right but the top match points at a
		// different report than the one it's actually a duplicate of.
		{Case: Case{ID: "dup-wrong", Kind: KindFabricated, Meta: Meta{Expected: report.OutcomeLikelyDuplicate, ExpectedDuplicateOf: "real-1"}},
			Got: report.OutcomeLikelyDuplicate, ReportID: "run-id-dup-wrong", Duplicates: []report.DupMatch{{ReportID: "some-other-report", Score: 1.0}}},
		// Not a duplicate case at all: excluded from the denominator.
		{Case: Case{ID: "unrelated", Kind: KindFabricated, Meta: Meta{Expected: report.OutcomeGroundingFailed}}, Got: report.OutcomeGroundingFailed},
	}}
	correct, total := sb.DuplicateTop1Accuracy()
	if correct != 1 || total != 2 {
		t.Errorf("DuplicateTop1Accuracy = %d/%d, want 1/2", correct, total)
	}
}
```

- [ ] **Step 6: Run the eval package tests to verify they pass**

Run: `go test ./internal/eval/... -v`
Expected: PASS for everything (existing and new). `cmd/kritolith` will not compile yet — that's the next step.

- [ ] **Step 7: Update `cmd/kritolith/eval.go`'s `CheckFunc` closure**

Replace:

```go
	sb := eval.Run(ctx, cases, func(ctx context.Context, c eval.Case) (report.Outcome, error) {
		opts := file.Options{Repo: c.Meta.Repo, Ref: c.Meta.Ref, ReportPath: filepath.Join(c.Dir, "report.md")}
		if st, err := os.Stat(filepath.Join(c.Dir, "poc")); err == nil && st.IsDir() {
			opts.PoCDir = filepath.Join(c.Dir, "poc")
		}
		r, err := file.Load(opts)
		if err != nil {
			return "", err
		}
		v, err := p.Run(ctx, r)
		if err != nil {
			return "", err
		}
		return v.Outcome, nil
	})
```

with:

```go
	sb := eval.Run(ctx, cases, func(ctx context.Context, c eval.Case) (eval.CheckResult, error) {
		opts := file.Options{Repo: c.Meta.Repo, Ref: c.Meta.Ref, ReportPath: filepath.Join(c.Dir, "report.md")}
		if st, err := os.Stat(filepath.Join(c.Dir, "poc")); err == nil && st.IsDir() {
			opts.PoCDir = filepath.Join(c.Dir, "poc")
		}
		r, err := file.Load(opts)
		if err != nil {
			return eval.CheckResult{}, err
		}
		v, err := p.Run(ctx, r)
		if err != nil {
			return eval.CheckResult{}, err
		}
		return eval.CheckResult{Outcome: v.Outcome, ReportID: r.ID, Duplicates: v.Duplicates}, nil
	})
```

(The `"github.com/ergasterion-dev/kritolith/internal/report"` import in `cmd/kritolith/eval.go` may now be unused if nothing else in the file references it — check with `goimports`/`go build` in the next step and remove the import line if so.)

- [ ] **Step 8: Set `expected_duplicate_of` on the three near-duplicate corpus cases**

In `testdata/corpus/fabricated/fab-015-*/meta.json`, add `"expected_duplicate_of": "go-2022-0603"`.
In `testdata/corpus/fabricated/fab-016-*/meta.json`, add `"expected_duplicate_of": "go-2024-3205"`.
In `testdata/corpus/fabricated/fab-017-near-duplicate/meta.json`, add `"expected_duplicate_of": "go-2024-2604"`.

Use the exact directory names present in the repo (glob `testdata/corpus/fabricated/fab-015-*` and `fab-016-*` to confirm the exact suffix before editing — `fab-017-near-duplicate`'s full name is already known from Task 0's reading).

- [ ] **Step 9: Build and run the full test suite**

Run: `go build ./... && go vet ./...`
Expected: builds cleanly, no unused imports.

Run: `make test`
Expected: PASS for everything.

- [ ] **Step 10: Commit**

```bash
git add internal/eval/corpus.go internal/eval/corpus_test.go internal/eval/score.go internal/eval/score_test.go cmd/kritolith/eval.go testdata/corpus/fabricated/fab-015-*/meta.json testdata/corpus/fabricated/fab-016-*/meta.json testdata/corpus/fabricated/fab-017-near-duplicate/meta.json
git commit -s -m "feat(eval): instrument duplicate top-1 accuracy, not just outcome match"
git push origin main
```

---

### Task 7: Live corpus verification + adversarial probe

**Files:** none (verification only — no commit).

**Interfaces:**
- Consumes: everything from Tasks 1–6.

- [ ] **Step 1: Run the full CI gate**

Run: `make ci`
Expected: `fmt-check vet test build eval` all pass.

- [ ] **Step 2: Run the live corpus with a persistent data dir and inspect the scoreboard**

Run: `go run ./cmd/kritolith eval --corpus testdata/corpus --data-dir /tmp/kritolith-eval-data`

Expected in the summary block:
```
real wrongly GROUNDING_FAILED:         0 (must be 0)
real wrongly LIKELY_DUPLICATE:         0 (must be 0)
fabricated wrongly LIKELY_DUPLICATE:   0
duplicate top-1 accuracy:              3/3
```
and the per-case table shows `fab-015`, `fab-016`, and `fab-017-near-duplicate` all as `LIKELY_DUPLICATE` with a ✓. If `fabricated caught by grounding` regresses below `11/15`, or either "must be 0" line is non-zero, stop and investigate before proceeding — these are the three pre-existing hard gates this plan must not regress.

- [ ] **Step 3: Construct and run the adversarial probe in the scratchpad**

This is the scenario the pre-fix code was silently open to and the checked-in corpus doesn't cover: two different reports in the same repo, both loosely citing a name declared twice (ambiguous), with the same vuln_class wording — must never fingerprint-match.

`internal/...` packages can only be imported from within the same module tree, so the probe cannot be a bare standalone Go file outside the repo — it must run inside a full copy of the module. Follow the handoff's own probe-testing methodology exactly: export a clean copy of the reviewed tree with `git archive`, drop a throwaway `_test.go` into that copy (never into the actual working checkout), run it there, then delete the whole copy.

```bash
mkdir -p /tmp/kritolith-probe
git archive HEAD | tar -x -C /tmp/kritolith-probe
```

Write `/tmp/kritolith-probe/internal/ground/zz_probe_test.go` — in-package (`package ground`), not an external test package, specifically so it can set the unexported `originURL` field on `*ground.Service` directly, exactly as `internal/ground/service_test.go` already does (an external `_test` package has no access to unexported fields, and `ground.Service` has no exported way to override its origin):

```go
package ground

// zz_probe_test.go is a throwaway adversarial probe, not part of the
// repo — it lives only in a git-archive scratch copy (see Task 7) and
// is never committed. It verifies that two different reports in the
// same repo, both loosely citing a name declared twice (ambiguous),
// with the same vuln_class, never fingerprint-match — the exact
// scenario the pre-fix literal-qualifier fingerprinting was silently
// open to.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/dedupe"
	"github.com/ergasterion-dev/kritolith/internal/report"
	"github.com/ergasterion-dev/kritolith/internal/store"
)

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestProbeAmbiguousNameNeverFingerprintsAcrossReports(t *testing.T) {
	ctx := context.Background()
	origin := t.TempDir()
	runGit(t, origin, "init", "-q", "-b", "main")
	runGit(t, origin, "config", "user.email", "p@p.example")
	runGit(t, origin, "config", "user.name", "p")
	if err := os.MkdirAll(origin+"/pkg1", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(origin+"/pkg2", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(origin+"/pkg1/a.go", []byte("package pkg1\n\nfunc Validate() bool { return true }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(origin+"/pkg2/b.go", []byte("package pkg2\n\nfunc Validate() bool { return true }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, origin, "add", ".")
	runGit(t, origin, "commit", "-q", "-m", "init")

	st, err := store.Open(ctx, t.TempDir()+"/data")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	grounder := NewService(t.TempDir())
	grounder.originURL = func(string) string { return origin } // unexported field, hence package ground not ground_test
	deduper := dedupe.NewService(st, nil)

	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "Validate", Source: "deterministic"},
		{Kind: report.ClaimVulnClass, Value: "auth bypass", Source: "deterministic"},
	}

	r1 := report.Report{ID: "probe-1", Repo: "owner/probe", ClaimedRef: "main"}
	if err := st.SaveReport(ctx, r1); err != nil {
		t.Fatal(err)
	}
	gr1 := grounder.Ground(ctx, r1, claims)
	fmt.Printf("r1 grounded: %+v\n", gr1.Claims)
	matches1, exact1 := deduper.Dedupe(ctx, r1, gr1.Claims, gr1.Module)
	if err := st.SaveVerdict(ctx, report.Verdict{ReportID: r1.ID, Outcome: report.OutcomeInconclusive, Claims: gr1.Claims, Duplicates: matches1}); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("r1: exact=%v matches=%+v\n", exact1, matches1)

	r2 := report.Report{ID: "probe-2", Repo: "owner/probe", ClaimedRef: "main"}
	if err := st.SaveReport(ctx, r2); err != nil {
		t.Fatal(err)
	}
	gr2 := grounder.Ground(ctx, r2, claims)
	fmt.Printf("r2 grounded: %+v\n", gr2.Claims)
	matches2, exact2 := deduper.Dedupe(ctx, r2, gr2.Claims, gr2.Module)
	fmt.Printf("r2: exact=%v matches=%+v\n", exact2, matches2)

	if exact2 || len(matches2) != 0 {
		t.Fatalf("FAIL: an ambiguous same-repo name fingerprint-matched across two reports: exact=%v matches=%+v", exact2, matches2)
	}
}
```

Run it:

```bash
cd /tmp/kritolith-probe && go test ./internal/ground/... -run TestProbeAmbiguousNameNeverFingerprintsAcrossReports -v
```

Expected: PASS, with printed output showing `r1`'s claim resolved with `Verified: yes` but empty `DeclPkgDir`/`DeclName` (ambiguous), and `r2`'s dedupe call producing `exact=false matches=[]`. If it fails, stop — this means the uniqueness check in Task 2 has a gap; do not proceed to declare Milestone 4 complete.

- [ ] **Step 4: Delete the throwaway probe copy**

```bash
rm -rf /tmp/kritolith-probe
```

Nothing from this step is committed to the reviewed checkout — the `git archive` copy in `/tmp` was always separate from it.

- [ ] **Step 5: Final confirmation**

Re-run `go run ./cmd/kritolith eval --corpus testdata/corpus --data-dir /tmp/kritolith-eval-data` once more (fresh temp data dir, or reuse — either is fine) to reconfirm the summary block from Step 2 still holds after all tasks. This is the acceptance test for the whole plan: Milestone 4 is complete when `duplicate top-1 accuracy: 3/3`, both "must be 0" gates hold, and `fabricated caught by grounding` has not regressed below `11/15`.
