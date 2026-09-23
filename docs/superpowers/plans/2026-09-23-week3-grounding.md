# Week 3 — Grounding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Repo-specific exemption — put this in every dispatch prompt:** this repo (`ergasterion-dev/kritolith`) is exempt from the user's global "no GitHub Actions" and "never push to a branch other than main" defaults. GitHub Actions CI stays enabled here, and every task commits directly to `main` with `git commit -s` (DCO sign-off, conventional commit style) followed immediately by `git push origin main`. No branches, no PRs. The global quality-gate hook (gofmt/vet/build/test) must pass on every commit — never `SKIP_GATE`. See the `kritolith-global-rules-override` memory.

**Goal:** Check every extracted claim against the actual code at the reporter's claimed commit, using git and `go/parser` only — no LLM calls, no sandbox. This is the first stage that changes verdict outcomes: a fake file or function claim now reaches `GROUNDING_FAILED`; a real report's claims never do.

**Architecture:** One new package, `internal/ground`, manages a bare git mirror per repo and grounds claims by reading file/function existence straight out of the git object database (no working-tree checkout). It's wired into `pipeline.Run` as an optional stage (`WithGround`, mirroring `WithLLM`'s composability) that production CLI code always configures. `verdict.StageResults` grows three fields; `verdict.Compose` gains the `GROUNDING_FAILED`/`NEEDS_INFO` precedence CLAUDE.md specifies.

**Tech Stack:** Go standard library only (`os/exec` to shell out to git, `go/parser`/`go/ast` for declarations). No new third-party dependencies.

**Spec:** `docs/superpowers/specs/2026-09-23-week3-grounding-design.md`

## Global Constraints

- **Zero false `GROUNDING_FAILED` on real reports is a hard v1 target** (CLAUDE.md principle 2: never wrongly reject a real report). When grounding can't be sure a claim is bad, it stays `Verified: unknown`, not `no`.
- `GROUNDING_FAILED` fires only on a **hard** claim (`file`, `function`) with `Verified: no`. A `line` claim (soft) never contributes to it, regardless of its own `Verified` value.
- Every git operation shells out to `git` via `os/exec` — no `go-git`, no `go/packages`. Function/method grounding is a syntax-level `go/ast` search, not import-aware or type-checked; evidence text is honest about this (it never claims "package" identity it didn't verify).
- File access is plumbing-only: `git cat-file`/`git show`/`git ls-tree` against a bare mirror. Grounding never writes a working-tree checkout to disk.
- Mirror freshness is fetch-if-missing: resolve locally first; only `git fetch` when resolution fails or the mirror was just created.
- Every claim-derived string that reaches a `git` command argument (a claimed file path, a fallback ref candidate) is validated first — `ValidateClaimPath` for paths, `report.ValidateRef` for ref candidates. Nothing claim-derived reaches `git` unvalidated.
- A grounding failure of any kind (unreachable repo, clone/fetch error, git error) degrades to `refResolved: false` — the same signal as "ref never resolved," which `Compose` already treats as `NEEDS_INFO`, never a rejection. It must never propagate as a `pipeline.Run` error or a panic.
- No new third-party dependencies; DCO-signed conventional commits (`git commit -s -m "..."`), never `SKIP_GATE`.

## Review Focus

- **Path traversal via a claimed file path reaching a git command.** Deterministic extraction's file regex allows `.` and `/`, so a claim value like `a/../../../etc/passwd.go` is a legal match. Task 3's `ValidateClaimPath` and its test table (rejecting `..` components in every position) close this.
- **A hostile or malformed fallback ref candidate reaching git unsanitized.** `ClaimVersion` values feed `EnsureAndResolve`'s fallback list and aren't pre-validated the way `Report.ClaimedRef` is at intake. Task 3's `TestEnsureAndResolveSkipsUnsafeRefCandidates` pins that an option-like candidate (`--upload-pack=x`) is skipped, not passed to git, while a legitimate fallback still resolves.
- **A real report wrongly reaching `GROUNDING_FAILED`** — the project's single worst-case bug. Task 9's live corpus run against the hard `real wrongly GROUNDING_FAILED: 0` gate is the actual test; nothing else in this plan can fully substitute for it.
- **A grounding failure crashing the pipeline instead of degrading.** Task 5's `TestServiceGroundDegradesOnCloneFailure` and Task 7's pipeline-level test both pin that an unreachable/broken repo never becomes a `pipeline.Run` error.
- **Unbounded resource use on a large or pathological repo tree.** Task 3 bounds file reads (10MB cap) and Task 4 bounds the file-list scan (`maxGoFiles`) so a huge repo can't blow up memory or time during grounding.

---

### Task 1: `report.ValidateRef` tightening

**Files:**
- Modify: `internal/report/validate.go`
- Modify: `internal/report/validate_test.go`

**Interfaces:**
- Produces: `report.ValidateRef(s string) error` — same signature, tightened behavior. No other task depends on new symbols from this one; every later task that calls git with a ref argument relies on this validation already being in place.

- [ ] **Step 1: Write the failing tests**

Add these cases to the existing `bad` slice in `TestValidateRef` (`internal/report/validate_test.go`), keeping every existing `good`/`bad` entry unchanged:

```go
	bad := []string{
		"", "-x", "--upload-pack=touch /tmp/pwned", "a..b", "a/", "x.lock", "a.", "a b", "a~1", "HEAD@{1}", "a:b", "a//b",
		"refs/.hidden/x", "a/.git/config", "x/y.lock/z", ".", "refs/heads/.x",
	}
```

- [ ] **Step 2: Run the tests to confirm they fail**

Run: `go test ./internal/report/... -run TestValidateRef -v`
Expected: FAIL — `refs/.hidden/x`, `a/.git/config`, `x/y.lock/z`, `.`, `refs/heads/.x` are currently accepted (no per-component check exists yet).

- [ ] **Step 3: Implement the tightened `ValidateRef`**

Replace `ValidateRef` in `internal/report/validate.go`:

```go
// ValidateRef checks that s is a safe commit SHA, tag or branch name.
// It is deliberately stricter than git: refs later reach git's command
// line, so anything that could parse as an option or revision
// expression (leading '-', "..", '@', '~', ':') is rejected. Every
// path component is checked too, not just the whole string: a
// component starting with '.' or ending in ".lock" is rejected
// wherever it appears, since these are git-internal path shapes a
// reporter-controlled ref should never be able to reach.
func ValidateRef(s string) error {
	if !refRe.MatchString(s) ||
		strings.Contains(s, "..") ||
		strings.Contains(s, "//") ||
		strings.HasSuffix(s, "/") ||
		strings.HasSuffix(s, ".") {
		return fmt.Errorf("report: invalid ref %q", s)
	}
	for _, part := range strings.Split(s, "/") {
		if strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return fmt.Errorf("report: invalid ref %q", s)
		}
	}
	return nil
}
```

- [ ] **Step 4: Run the tests to confirm they pass**

Run: `go test ./internal/report/... -v`
Expected: PASS — all of `TestValidateRepo`, `TestValidateRef`, `TestIsFullSHA`.

- [ ] **Step 5: Run the full build to confirm nothing else broke**

Run: `go build ./... && go test ./...`
Expected: PASS. (`ValidateRef` is called from `internal/intake/file` at report-intake time; confirm no existing corpus fixture's ref now gets wrongly rejected — the corpus refs are all full 40-hex SHAs or simple tags like `v1.2.3`, none of which trips the new per-component check.)

- [ ] **Step 6: Commit and push**

```bash
git add internal/report/validate.go internal/report/validate_test.go
git commit -s -m "fix(report): tighten ValidateRef against dot-leading and .lock path components"
git push origin main
```

---

### Task 2: `internal/ground` — AST declaration search and closest-match

**Files:**
- Create: `internal/ground/ast.go`
- Create: `internal/ground/ast_test.go`

**Interfaces:**
- Produces (unexported, package-internal — consumed by Task 4): `declaration{name, receiver, file string; line, endLine int}`; `parseDeclarations(file string, content []byte) []declaration`; `findDeclaration(decls []declaration, value string) *declaration`; `closestDeclaration(decls []declaration, value string) *declaration`; `splitFunctionClaim(value string) (receiver, name string)`; `levenshtein(a, b string) int`.
- Consumes: nothing new — pure `go/ast`/`go/parser`/`go/token` and `strings`.

- [ ] **Step 1: Write the failing tests**

Create `internal/ground/ast_test.go`:

```go
package ground

import "testing"

func TestParseDeclarationsFunctionAndMethod(t *testing.T) {
	src := []byte(`package p

func Foo() {}

func (t *Type) Method() {}

func (v Value) OtherMethod() {}
`)
	decls := parseDeclarations("p.go", src)
	if len(decls) != 3 {
		t.Fatalf("decls = %+v, want 3", decls)
	}
	want := map[string]string{"Foo": "", "Method": "Type", "OtherMethod": "Value"}
	got := map[string]string{}
	for _, d := range decls {
		got[d.name] = d.receiver
	}
	for name, recv := range want {
		if v, ok := got[name]; !ok || v != recv {
			t.Errorf("decl %q receiver = %q (present=%v), want %q", name, v, ok, recv)
		}
	}
}

func TestParseDeclarationsPositions(t *testing.T) {
	src := []byte("package p\n\nfunc Foo() {\n\treturn\n}\n")
	decls := parseDeclarations("p.go", src)
	if len(decls) != 1 {
		t.Fatalf("decls = %+v, want 1", decls)
	}
	if decls[0].line != 3 || decls[0].endLine != 5 {
		t.Errorf("decl = %+v, want line 3, endLine 5", decls[0])
	}
}

func TestParseDeclarationsInvalidSyntaxIsNotFatal(t *testing.T) {
	decls := parseDeclarations("bad.go", []byte("this is not go code {{{"))
	if decls != nil {
		t.Errorf("decls = %+v, want nil for unparseable input", decls)
	}
}

func TestParseDeclarationsGenericReceiver(t *testing.T) {
	src := []byte(`package p

type Type[T any] struct{}

func (t *Type[T]) Method() {}

func (t Type[T, U]) Other() {}
`)
	decls := parseDeclarations("p.go", src)
	if len(decls) != 2 {
		t.Fatalf("decls = %+v, want 2", decls)
	}
	for _, d := range decls {
		if d.receiver != "Type" {
			t.Errorf("decl %q receiver = %q, want %q (generic receivers must still resolve their base type name)", d.name, d.receiver, "Type")
		}
	}
}

func TestSplitFunctionClaim(t *testing.T) {
	tests := []struct {
		value        string
		wantReceiver string
		wantName     string
	}{
		{"Foo", "", "Foo"},
		{"pkg.Foo", "pkg", "Foo"},
		{"(*Type).Method", "Type", "Method"},
		{"(Type).Method", "Type", "Method"},
	}
	for _, tt := range tests {
		recv, name := splitFunctionClaim(tt.value)
		if recv != tt.wantReceiver || name != tt.wantName {
			t.Errorf("splitFunctionClaim(%q) = %q, %q, want %q, %q", tt.value, recv, name, tt.wantReceiver, tt.wantName)
		}
	}
}

func TestFindDeclarationPlainFunction(t *testing.T) {
	decls := []declaration{{name: "Foo", file: "p.go", line: 3}}
	if d := findDeclaration(decls, "pkg.Foo"); d == nil || d.name != "Foo" {
		t.Errorf("findDeclaration(pkg.Foo) = %v, want a match on Foo", d)
	}
	if d := findDeclaration(decls, "Foo"); d == nil {
		t.Errorf("findDeclaration(Foo) = nil, want a match")
	}
	if d := findDeclaration(decls, "pkg.Bar"); d != nil {
		t.Errorf("findDeclaration(pkg.Bar) = %v, want nil", d)
	}
}

func TestFindDeclarationMethod(t *testing.T) {
	decls := []declaration{{name: "Method", receiver: "Type", file: "p.go", line: 5}}
	if d := findDeclaration(decls, "(*Type).Method"); d == nil {
		t.Errorf("findDeclaration((*Type).Method) = nil, want a match")
	}
	if d := findDeclaration(decls, "Type.Method"); d == nil {
		t.Errorf("findDeclaration(Type.Method) = nil, want a match")
	}
	if d := findDeclaration(decls, "(*Other).Method"); d != nil {
		t.Errorf("findDeclaration((*Other).Method) = %v, want nil (wrong receiver)", d)
	}
}

func TestClosestDeclaration(t *testing.T) {
	decls := []declaration{
		{name: "parseHeaders", file: "frame.go", line: 412},
		{name: "unrelated", file: "other.go", line: 1},
	}
	got := closestDeclaration(decls, "http2.parseHeader")
	if got == nil || got.name != "parseHeaders" {
		t.Errorf("closestDeclaration = %v, want parseHeaders", got)
	}
}

func TestClosestDeclarationEmpty(t *testing.T) {
	if got := closestDeclaration(nil, "anything"); got != nil {
		t.Errorf("closestDeclaration(nil, ...) = %v, want nil", got)
	}
}

func TestLevenshtein(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "abc", 0},
		{"abc", "", 3},
		{"parseHeader", "parseHeaders", 1},
		{"kitten", "sitting", 3},
	}
	for _, tt := range tests {
		if got := levenshtein(tt.a, tt.b); got != tt.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}
```

- [ ] **Step 2: Run the tests to confirm they fail**

Run: `go test ./internal/ground/...`
Expected: FAIL — package doesn't exist yet.

- [ ] **Step 3: Implement `internal/ground/ast.go`**

```go
// Package ground checks extracted claims against the actual code at
// the reporter's claimed commit, using git (shelled out to) and
// go/parser only. Function and method grounding is a syntax-level
// search, not import-aware or type-checked: it never claims "package"
// identity it didn't verify.
package ground

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

// declaration is one top-level function or method declaration found
// while scanning a repo tree at a resolved commit.
type declaration struct {
	name     string // function name, or method name for a method
	receiver string // receiver type name, without "*"; empty for a plain function
	file     string
	line     int
	endLine  int
}

// parseDeclarations parses one Go source file's content and returns
// every top-level function and method declaration in it. A file that
// fails to parse contributes no declarations rather than failing the
// whole search: build-tag-gated syntax this parser can't handle, or a
// hostile/malformed file, must never abort grounding.
func parseDeclarations(file string, content []byte) []declaration {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, content, 0)
	if err != nil {
		return nil
	}
	var out []declaration
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		decl := declaration{
			name:    fn.Name.Name,
			file:    file,
			line:    fset.Position(fn.Pos()).Line,
			endLine: fset.Position(fn.End()).Line,
		}
		if fn.Recv != nil && len(fn.Recv.List) > 0 {
			decl.receiver = receiverTypeName(fn.Recv.List[0].Type)
		}
		out = append(out, decl)
	}
	return out
}

func receiverTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return receiverTypeName(t.X)
	case *ast.IndexExpr: // generic receiver, one type param: func (t *Type[T]) M()
		return receiverTypeName(t.X)
	case *ast.IndexListExpr: // generic receiver, multiple type params: func (t *Type[T, U]) M()
		return receiverTypeName(t.X)
	case *ast.Ident:
		return t.Name
	default:
		return ""
	}
}

// splitFunctionClaim parses a claim value shaped "pkg.Func",
// "(*Type).Method", "(Type).Method", or a bare "Func" into a
// (receiver, name) pair. receiver is empty for a plain function or
// package-qualified function claim — "pkg.Func"'s "pkg" part is
// syntactically identical to a method claim's type name, so callers
// try both interpretations (see findDeclaration).
func splitFunctionClaim(value string) (receiver, name string) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "(") {
		closeParen := strings.IndexByte(value, ')')
		if closeParen < 0 {
			return "", value
		}
		recv := strings.TrimPrefix(value[1:closeParen], "*")
		rest := strings.TrimPrefix(value[closeParen+1:], ".")
		return recv, rest
	}
	idx := strings.LastIndexByte(value, '.')
	if idx < 0 {
		return "", value
	}
	return value[:idx], value[idx+1:]
}

// findDeclaration looks for a declaration matching value. A
// "(*Type).Method"/"(Type).Method" claim must match on both receiver
// and name. A "pkg.Func" or bare "Func" claim matches a plain function
// by name; "pkg.Func" additionally matches a method whose receiver
// happens to equal "pkg" and whose name equals "Func", since without
// import resolution a package qualifier and a type name are
// syntactically indistinguishable.
func findDeclaration(decls []declaration, value string) *declaration {
	if strings.HasPrefix(value, "(") {
		recv, name := splitFunctionClaim(value)
		for i := range decls {
			if decls[i].name == name && decls[i].receiver == recv {
				return &decls[i]
			}
		}
		return nil
	}
	recv, name := splitFunctionClaim(value)
	if recv == "" {
		for i := range decls {
			if decls[i].name == name && decls[i].receiver == "" {
				return &decls[i]
			}
		}
		return nil
	}
	for i := range decls {
		if decls[i].name != name {
			continue
		}
		if decls[i].receiver == recv || decls[i].receiver == "" {
			return &decls[i]
		}
	}
	return nil
}

// closestDeclaration returns the declaration whose name is closest to
// value's name part by edit distance, for a "not found, closest match"
// evidence string. Returns nil if decls is empty.
func closestDeclaration(decls []declaration, value string) *declaration {
	if len(decls) == 0 {
		return nil
	}
	_, target := splitFunctionClaim(value)
	var best *declaration
	bestDist := -1
	for i := range decls {
		d := levenshtein(target, decls[i].name)
		if bestDist < 0 || d < bestDist {
			bestDist = d
			best = &decls[i]
		}
	}
	return best
}

// levenshtein computes the edit distance between a and b.
func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	curr := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		curr[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			m := del
			if ins < m {
				m = ins
			}
			if sub < m {
				m = sub
			}
			curr[j] = m
		}
		prev, curr = curr, prev
	}
	return prev[len(rb)]
}
```

- [ ] **Step 4: Run the tests to confirm they pass**

Run: `go test ./internal/ground/...`
Expected: PASS

- [ ] **Step 5: Commit and push**

```bash
git add internal/ground/ast.go internal/ground/ast_test.go
git commit -s -m "feat(ground): add go/ast declaration search and closest-match"
git push origin main
```

---

### Task 3: `internal/ground` — Mirror and path validation

**Files:**
- Create: `internal/ground/mirror.go`
- Create: `internal/ground/mirror_test.go`

**Interfaces:**
- Consumes: `report.ValidateRepo`, `report.ValidateRef` (`internal/report`, already built).
- Produces: `ground.Mirror` type; `ground.OpenMirror(dataDir, repo, originURL string) (*Mirror, error)`; `(*Mirror).EnsureAndResolve(ctx, ref string, fallbackVersions []string) (commit string, resolved bool, err error)`; `(*Mirror).FileExists(ctx, commit, path string) (bool, error)`; `(*Mirror).ReadFile(ctx, commit, path string) ([]byte, bool, error)`; `(*Mirror).ListGoFiles(ctx, commit string) ([]string, error)`; `ground.ValidateClaimPath(path string) error`.

- [ ] **Step 1: Write the failing tests**

Create `internal/ground/mirror_test.go`:

```go
package ground

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// newTestOrigin creates a small real git repo in a temp dir with one
// commit and a tag, usable as a Mirror's originURL — git treats a
// local filesystem path as a valid remote, so no network is needed.
func newTestOrigin(t *testing.T) (dir, commit string) {
	t.Helper()
	dir = t.TempDir()
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
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a\n\nfunc Foo() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "a.go")
	run("commit", "-q", "-m", "init")
	commit = run("rev-parse", "HEAD")
	run("tag", "v1.0.0")
	return dir, commit
}

func TestOpenMirrorRejectsInvalidRepo(t *testing.T) {
	if _, err := OpenMirror(t.TempDir(), "not a repo", "file:///tmp"); err == nil {
		t.Fatal("want error for invalid repo")
	}
}

func TestEnsureAndResolveClonesOnFirstUse(t *testing.T) {
	origin, commit := newTestOrigin(t)
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	sha, resolved, err := m.EnsureAndResolve(context.Background(), commit, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !resolved || sha != commit {
		t.Fatalf("EnsureAndResolve = %q, %v, want %q, true", sha, resolved, commit)
	}
}

func TestEnsureAndResolveCacheHitNeedsNoNetwork(t *testing.T) {
	origin, commit := newTestOrigin(t)
	dataDir := t.TempDir()
	m, err := OpenMirror(dataDir, "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	if _, resolved, err := m.EnsureAndResolve(context.Background(), commit, nil); err != nil || !resolved {
		t.Fatalf("first resolve failed: %v %v", resolved, err)
	}
	// Point a second Mirror at the same on-disk data dir but a
	// nonexistent origin: a cache-hit resolve must not need it.
	m2, err := OpenMirror(dataDir, "owner/name", filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatal(err)
	}
	sha, resolved, err := m2.EnsureAndResolve(context.Background(), commit, nil)
	if err != nil || !resolved || sha != commit {
		t.Fatalf("cache-hit resolve = %q, %v, %v, want %q, true, nil", sha, resolved, err, commit)
	}
}

func TestEnsureAndResolveFetchesOnMiss(t *testing.T) {
	origin, commit1 := newTestOrigin(t)
	dataDir := t.TempDir()
	m, err := OpenMirror(dataDir, "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	if _, resolved, err := m.EnsureAndResolve(context.Background(), commit1, nil); err != nil || !resolved {
		t.Fatalf("first resolve failed: %v %v", resolved, err)
	}
	run := func(args ...string) string {
		cmd := exec.Command("git", args...)
		cmd.Dir = origin
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	if err := os.WriteFile(filepath.Join(origin, "b.go"), []byte("package a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "b.go")
	run("commit", "-q", "-m", "second")
	commit2 := run("rev-parse", "HEAD")

	sha, resolved, err := m.EnsureAndResolve(context.Background(), commit2, nil)
	if err != nil || !resolved || sha != commit2 {
		t.Fatalf("fetch-on-miss resolve = %q, %v, %v, want %q, true, nil", sha, resolved, err, commit2)
	}
}

func TestEnsureAndResolveFallsBackToTag(t *testing.T) {
	origin, commit := newTestOrigin(t)
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	sha, resolved, err := m.EnsureAndResolve(context.Background(), "does-not-exist-as-a-ref", []string{"v1.0.0"})
	if err != nil || !resolved || sha != commit {
		t.Fatalf("fallback resolve = %q, %v, %v, want %q, true, nil", sha, resolved, err, commit)
	}
}

func TestEnsureAndResolveNothingResolves(t *testing.T) {
	origin, _ := newTestOrigin(t)
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	_, resolved, err := m.EnsureAndResolve(context.Background(), "totally-unknown-ref", []string{"also-unknown"})
	if err != nil {
		t.Fatalf("want no error, got %v", err)
	}
	if resolved {
		t.Fatal("want resolved = false")
	}
}

func TestEnsureAndResolveSkipsUnsafeRefCandidates(t *testing.T) {
	origin, commit := newTestOrigin(t)
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	// The primary ref is option-like and must never reach git as an
	// argument; the fallback (a legitimate tag) must still be tried.
	sha, resolved, err := m.EnsureAndResolve(context.Background(), "--upload-pack=x", []string{"v1.0.0"})
	if err != nil || !resolved || sha != commit {
		t.Fatalf("resolve = %q, %v, %v, want %q, true, nil (fallback should still work)", sha, resolved, err, commit)
	}
}

func TestFileExistsAndReadFile(t *testing.T) {
	origin, commit := newTestOrigin(t)
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, _, err := m.EnsureAndResolve(ctx, commit, nil); err != nil {
		t.Fatal(err)
	}
	if ok, err := m.FileExists(ctx, commit, "a.go"); err != nil || !ok {
		t.Errorf("FileExists(a.go) = %v, %v, want true, nil", ok, err)
	}
	if ok, err := m.FileExists(ctx, commit, "missing.go"); err != nil || ok {
		t.Errorf("FileExists(missing.go) = %v, %v, want false, nil", ok, err)
	}
	content, ok, err := m.ReadFile(ctx, commit, "a.go")
	if err != nil || !ok || !strings.Contains(string(content), "func Foo") {
		t.Fatalf("ReadFile(a.go) = %q, %v, %v", content, ok, err)
	}
	if _, ok, err := m.ReadFile(ctx, commit, "missing.go"); err != nil || ok {
		t.Errorf("ReadFile(missing.go) = ok %v, err %v, want false, nil", ok, err)
	}
}

func TestFileExistsRejectsTraversal(t *testing.T) {
	origin, commit := newTestOrigin(t)
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, _, err := m.EnsureAndResolve(ctx, commit, nil); err != nil {
		t.Fatal(err)
	}
	if ok, _ := m.FileExists(ctx, commit, "a/../../../etc/passwd"); ok {
		t.Error("FileExists with a traversal path = true, want false")
	}
}

func TestListGoFiles(t *testing.T) {
	origin, commit := newTestOrigin(t)
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, _, err := m.EnsureAndResolve(ctx, commit, nil); err != nil {
		t.Fatal(err)
	}
	files, err := m.ListGoFiles(ctx, commit)
	if err != nil || len(files) != 1 || files[0] != "a.go" {
		t.Fatalf("ListGoFiles = %v, %v, want [a.go], nil", files, err)
	}
}

func TestValidateClaimPath(t *testing.T) {
	good := []string{"a.go", "internal/hpack/decode.go", "a/b/c.go"}
	bad := []string{"", "../a.go", "a/../b.go", "a/..", "/etc/passwd", "./a.go", "a/./b.go"}
	for _, p := range good {
		if err := ValidateClaimPath(p); err != nil {
			t.Errorf("ValidateClaimPath(%q) = %v, want nil", p, err)
		}
	}
	for _, p := range bad {
		if err := ValidateClaimPath(p); err == nil {
			t.Errorf("ValidateClaimPath(%q) = nil, want error", p)
		}
	}
}
```

- [ ] **Step 2: Run the tests to confirm they fail**

Run: `go test ./internal/ground/... -run 'TestOpenMirror|TestEnsureAndResolve|TestFileExists|TestReadFile|TestListGoFiles|TestValidateClaimPath'`
Expected: FAIL — `OpenMirror`, `ValidateClaimPath`, and `Mirror`'s methods don't exist yet.

- [ ] **Step 3: Implement `internal/ground/mirror.go`**

```go
package ground

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

const (
	maxReadBytes = 10 << 20 // bound the work: a single file read is capped, not unlimited
)

// Mirror is a bare git mirror for one repo, rooted at a fixed path
// under a data dir. Every operation shells out to git; nothing here
// uses a third-party git library, and nothing here writes a
// working-tree checkout to disk.
type Mirror struct {
	path   string // <data_dir>/git-mirrors/<owner>/<repo>.git
	origin string // URL or local path git clone/fetch pulls from
}

// OpenMirror computes the mirror's local path for repo under dataDir.
// It touches neither disk nor network — call EnsureAndResolve or a
// file-access method to do that.
func OpenMirror(dataDir, repo, originURL string) (*Mirror, error) {
	if dataDir == "" {
		return nil, fmt.Errorf("ground: data dir is empty")
	}
	if err := report.ValidateRepo(repo); err != nil {
		return nil, fmt.Errorf("ground: %w", err)
	}
	return &Mirror{
		path:   filepath.Join(dataDir, "git-mirrors", repo+".git"),
		origin: originURL,
	}, nil
}

func (m *Mirror) exists() bool {
	fi, err := os.Stat(m.path)
	return err == nil && fi.IsDir()
}

func (m *Mirror) runGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(errBuf.String()))
	}
	return out.String(), nil
}

func (m *Mirror) clone(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(m.path), 0o700); err != nil {
		return fmt.Errorf("ground: mkdir: %w", err)
	}
	_, err := m.runGit(ctx, "", "clone", "--mirror", "--", m.origin, m.path)
	return err
}

func (m *Mirror) fetch(ctx context.Context) error {
	_, err := m.runGit(ctx, m.path, "fetch", "--prune", "origin")
	return err
}

func (m *Mirror) resolve(ctx context.Context, ref string) (string, bool) {
	out, err := m.runGit(ctx, m.path, "rev-parse", "--verify", "--end-of-options", ref+"^{commit}")
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(out), true
}

// EnsureAndResolve resolves ref to a full commit SHA. It clones the
// mirror on first use, tries to resolve locally first, and only
// fetches (once) if that fails and the mirror wasn't just created. If
// ref itself never resolves, it tries each of fallbackVersions in
// order as a ref, with the same policy. resolved is false, with no
// error, if nothing resolved at all. Every candidate (ref and each
// fallback) is validated with report.ValidateRef before it ever
// reaches a git command argument; an invalid candidate is skipped, not
// treated as a hard error.
func (m *Mirror) EnsureAndResolve(ctx context.Context, ref string, fallbackVersions []string) (commit string, resolved bool, err error) {
	freshClone := false
	if !m.exists() {
		if err := m.clone(ctx); err != nil {
			return "", false, fmt.Errorf("ground: clone: %w", err)
		}
		freshClone = true
	}
	candidates := append([]string{ref}, fallbackVersions...)
	if sha, ok := m.tryResolve(ctx, candidates); ok {
		return sha, true, nil
	}
	if !freshClone {
		if err := m.fetch(ctx); err != nil {
			return "", false, fmt.Errorf("ground: fetch: %w", err)
		}
		if sha, ok := m.tryResolve(ctx, candidates); ok {
			return sha, true, nil
		}
	}
	return "", false, nil
}

func (m *Mirror) tryResolve(ctx context.Context, candidates []string) (string, bool) {
	for _, cand := range candidates {
		if cand == "" {
			continue
		}
		if err := report.ValidateRef(cand); err != nil {
			continue
		}
		if sha, ok := m.resolve(ctx, cand); ok {
			return sha, true
		}
	}
	return "", false
}

// FileExists reports whether path exists as a blob at commit. It
// never treats a checked-out ref as ambiguous: EnsureAndResolve has
// already confirmed commit itself resolves, so a cat-file failure here
// only ever means the path doesn't exist in that tree, not a
// network/transient error.
func (m *Mirror) FileExists(ctx context.Context, commit, path string) (bool, error) {
	if err := ValidateClaimPath(path); err != nil {
		return false, nil
	}
	_, err := m.runGit(ctx, m.path, "cat-file", "-e", commit+":"+path)
	return err == nil, nil
}

// ReadFile returns the blob content at commit:path, capped at
// maxReadBytes. ok is false if the path doesn't exist — not an error.
func (m *Mirror) ReadFile(ctx context.Context, commit, path string) ([]byte, bool, error) {
	if err := ValidateClaimPath(path); err != nil {
		return nil, false, nil
	}
	out, err := m.runGit(ctx, m.path, "show", commit+":"+path)
	if err != nil {
		return nil, false, nil
	}
	if len(out) > maxReadBytes {
		out = out[:maxReadBytes]
	}
	return []byte(out), true, nil
}

// ListGoFiles returns every ".go" file path at commit, via one
// `git ls-tree`, filtered client-side.
func (m *Mirror) ListGoFiles(ctx context.Context, commit string) ([]string, error) {
	out, err := m.runGit(ctx, m.path, "ls-tree", "-r", "--name-only", commit)
	if err != nil {
		return nil, fmt.Errorf("ground: list files at %s: %w", commit, err)
	}
	var files []string
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if line != "" && strings.HasSuffix(line, ".go") {
			files = append(files, line)
		}
	}
	return files, nil
}

// ValidateClaimPath rejects any path with a "." or ".." component (or
// a leading "/"), mirroring report.ValidateRef's defensive posture for
// refs, applied to paths. Grounding is the first stage to feed a
// claim value into a real git command argument, and deterministic
// extraction's file regex allows "." and "/" in a claim value, so a
// path-traversal-shaped value like "a/../../../etc/foo.go" is a legal
// regex match that must never reach git.
func ValidateClaimPath(path string) error {
	if path == "" || strings.HasPrefix(path, "/") {
		return fmt.Errorf("ground: invalid path %q", path)
	}
	for _, part := range strings.Split(path, "/") {
		if part == "." || part == ".." {
			return fmt.Errorf("ground: invalid path %q", path)
		}
	}
	return nil
}
```

- [ ] **Step 4: Run the tests to confirm they pass**

Run: `go test ./internal/ground/... -v`
Expected: PASS

- [ ] **Step 5: Commit and push**

```bash
git add internal/ground/mirror.go internal/ground/mirror_test.go
git commit -s -m "feat(ground): add bare git mirror management and path validation"
git push origin main
```

---

### Task 4: `internal/ground` — claim grounding orchestration

**Files:**
- Create: `internal/ground/ground.go`
- Create: `internal/ground/ground_test.go`

**Interfaces:**
- Consumes: `declaration`, `parseDeclarations`, `findDeclaration`, `closestDeclaration` (Task 2); `*Mirror`, `EnsureAndResolve`, `FileExists`, `ReadFile`, `ListGoFiles` (Task 3); `report.Claim`, `report.ClaimKind` constants, `report.Tri*`, `report.Printable`, `report.Report` (`internal/report`).
- Produces (unexported — consumed by Task 5): `groundClaims(ctx context.Context, m *Mirror, r report.Report, claims []report.Claim) (grounded []report.Claim, refResolved bool, resolvedCommit string, err error)`.

- [ ] **Step 1: Write the failing tests**

Create `internal/ground/ground_test.go`:

```go
package ground

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

func newGroundTestOrigin(t *testing.T) (dir, commit string) {
	t.Helper()
	dir = t.TempDir()
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
		"internal/http2/frame.go": "package http2\n\nfunc parseHeaders() {}\n",
		"main.go":                 "package main\n\nfunc main() {}\n",
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
	commit = run("rev-parse", "HEAD")
	return dir, commit
}

func TestGroundClaimsFileAndFunction(t *testing.T) {
	origin, commit := newGroundTestOrigin(t)
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	r := report.Report{ID: "R1", Repo: "owner/name", ClaimedRef: commit}
	claims := []report.Claim{
		{Kind: report.ClaimFile, Value: "internal/http2/frame.go"},
		{Kind: report.ClaimFile, Value: "does/not/exist.go"},
		{Kind: report.ClaimFunction, Value: "http2.parseHeaders"},
		{Kind: report.ClaimFunction, Value: "http2.parseHeader"}, // invented, close to parseHeaders
	}
	grounded, resolved, resolvedCommit, err := groundClaims(context.Background(), m, r, claims)
	if err != nil {
		t.Fatal(err)
	}
	if !resolved || resolvedCommit != commit {
		t.Fatalf("resolved = %v, commit = %q, want true, %q", resolved, resolvedCommit, commit)
	}
	byValue := map[string]report.Claim{}
	for _, c := range grounded {
		byValue[c.Value] = c
	}
	if byValue["internal/http2/frame.go"].Verified != report.TriYes {
		t.Errorf("existing file claim = %+v, want Verified: yes", byValue["internal/http2/frame.go"])
	}
	if byValue["does/not/exist.go"].Verified != report.TriNo {
		t.Errorf("missing file claim = %+v, want Verified: no", byValue["does/not/exist.go"])
	}
	if byValue["http2.parseHeaders"].Verified != report.TriYes {
		t.Errorf("existing function claim = %+v, want Verified: yes", byValue["http2.parseHeaders"])
	}
	invented := byValue["http2.parseHeader"]
	if invented.Verified != report.TriNo {
		t.Errorf("invented function claim = %+v, want Verified: no", invented)
	}
	if !strings.Contains(invented.Evidence, "parseHeaders") {
		t.Errorf("invented function claim evidence = %q, want it to mention the closest match", invented.Evidence)
	}
}

func TestGroundClaimsRefDoesNotResolve(t *testing.T) {
	origin, _ := newGroundTestOrigin(t)
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	r := report.Report{ID: "R1", Repo: "owner/name", ClaimedRef: "totally-unknown"}
	grounded, resolved, _, err := groundClaims(context.Background(), m, r, []report.Claim{{Kind: report.ClaimFile, Value: "main.go"}})
	if err != nil {
		t.Fatal(err)
	}
	if resolved {
		t.Fatal("want resolved = false")
	}
	if grounded[0].Verified != report.TriUnknown {
		t.Errorf("claim = %+v, want unchanged/unverified when the ref never resolved", grounded[0])
	}
}

func TestGroundClaimsLineClaim(t *testing.T) {
	origin, commit := newGroundTestOrigin(t)
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	r := report.Report{ID: "R1", Repo: "owner/name", ClaimedRef: commit}
	claims := []report.Claim{
		{Kind: report.ClaimLine, Value: "main.go:3"},    // inside func main
		{Kind: report.ClaimLine, Value: "main.go:9999"}, // out of range
	}
	grounded, _, _, err := groundClaims(context.Background(), m, r, claims)
	if err != nil {
		t.Fatal(err)
	}
	if grounded[0].Verified != report.TriYes {
		t.Errorf("in-range line claim = %+v, want Verified: yes", grounded[0])
	}
	if grounded[1].Verified != report.TriNo {
		t.Errorf("out-of-range line claim = %+v, want Verified: no", grounded[1])
	}
	// A line claim is soft: whether it fails never contributes to
	// GROUNDING_FAILED. That precedence is Task 6's concern (Compose),
	// not groundClaims's — this test only checks Verified/Evidence.
}

func TestGroundClaimsFallsBackToVersionClaims(t *testing.T) {
	origin, commit := newGroundTestOrigin(t)
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = origin
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("tag", "v2.0.0")
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	r := report.Report{ID: "R1", Repo: "owner/name", ClaimedRef: "does-not-resolve"}
	claims := []report.Claim{{Kind: report.ClaimVersion, Value: "v2.0.0"}}
	_, resolved, resolvedCommit, err := groundClaims(context.Background(), m, r, claims)
	if err != nil {
		t.Fatal(err)
	}
	if !resolved || resolvedCommit != commit {
		t.Fatalf("resolved = %v, commit = %q, want true, %q", resolved, resolvedCommit, commit)
	}
}

func TestGroundClaimsLeavesOtherKindsAlone(t *testing.T) {
	origin, commit := newGroundTestOrigin(t)
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	r := report.Report{ID: "R1", Repo: "owner/name", ClaimedRef: commit}
	claims := []report.Claim{{Kind: report.ClaimVulnClass, Value: "dos", Verified: report.TriUnknown}}
	grounded, _, _, err := groundClaims(context.Background(), m, r, claims)
	if err != nil {
		t.Fatal(err)
	}
	if grounded[0].Verified != report.TriUnknown {
		t.Errorf("vuln_class claim = %+v, want Verified unchanged (unknown)", grounded[0])
	}
}
```

- [ ] **Step 2: Run the tests to confirm they fail**

Run: `go test ./internal/ground/... -run TestGroundClaims`
Expected: FAIL — `groundClaims` doesn't exist yet.

- [ ] **Step 3: Implement `internal/ground/ground.go`**

```go
package ground

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

const (
	maxGoFiles       = 5000 // bound the work on pathologically large repos
	maxFallbackRefs  = 20   // bound how many ClaimVersion values become ref candidates
)

// groundClaims checks r's claimed ref (falling back to any
// ClaimVersion values already in claims) and grounds every
// file/function/line claim against the resolved commit. It returns
// the same claims with Verified and Evidence updated, plus whether a
// ref resolved and which commit it resolved to. An error here means
// the mirror itself couldn't be used (clone/fetch failure); callers
// must degrade to "not resolved" rather than propagate it as a
// pipeline failure (see Task 5's Service).
func groundClaims(ctx context.Context, m *Mirror, r report.Report, claims []report.Claim) (grounded []report.Claim, refResolved bool, resolvedCommit string, err error) {
	var versions []string
	for _, c := range claims {
		if c.Kind == report.ClaimVersion {
			versions = append(versions, c.Value)
			if len(versions) >= maxFallbackRefs {
				break
			}
		}
	}
	commit, resolved, err := m.EnsureAndResolve(ctx, r.ClaimedRef, versions)
	if err != nil {
		return claims, false, "", err
	}
	if !resolved {
		return claims, false, "", nil
	}

	var decls []declaration
	var declsLoaded bool
	loadDecls := func() []declaration {
		if declsLoaded {
			return decls
		}
		declsLoaded = true
		files, err := m.ListGoFiles(ctx, commit)
		if err != nil {
			return nil
		}
		if len(files) > maxGoFiles {
			files = files[:maxGoFiles]
		}
		for _, f := range files {
			content, ok, err := m.ReadFile(ctx, commit, f)
			if err != nil || !ok {
				continue
			}
			decls = append(decls, parseDeclarations(f, content)...)
		}
		return decls
	}

	out := make([]report.Claim, len(claims))
	copy(out, claims)
	for i := range out {
		switch out[i].Kind {
		case report.ClaimFile:
			groundFileClaim(ctx, m, commit, &out[i])
		case report.ClaimFunction:
			groundFunctionClaim(&out[i], loadDecls())
		case report.ClaimLine:
			groundLineClaim(ctx, m, commit, &out[i], loadDecls())
		}
	}
	return out, true, commit, nil
}

func groundFileClaim(ctx context.Context, m *Mirror, commit string, c *report.Claim) {
	ok, err := m.FileExists(ctx, commit, c.Value)
	short := shortSHA(commit)
	if err != nil {
		return // leave Verified/Evidence as extraction left them
	}
	if ok {
		c.Verified = report.TriYes
		c.Evidence = fmt.Sprintf("file exists at %s", short)
	} else {
		c.Verified = report.TriNo
		c.Evidence = fmt.Sprintf("not found at %s", short)
	}
}

func groundFunctionClaim(c *report.Claim, decls []declaration) {
	if d := findDeclaration(decls, c.Value); d != nil {
		c.Verified = report.TriYes
		c.Evidence = fmt.Sprintf("declared at %s:%d", report.Printable(d.file), d.line)
		return
	}
	c.Verified = report.TriNo
	if closest := closestDeclaration(decls, c.Value); closest != nil {
		c.Evidence = fmt.Sprintf("not declared in the repository; closest match: %s (%s:%d)",
			report.Printable(closest.name), report.Printable(closest.file), closest.line)
	} else {
		c.Evidence = "not declared in the repository"
	}
}

func groundLineClaim(ctx context.Context, m *Mirror, commit string, c *report.Claim, decls []declaration) {
	file, lineNum, ok := splitFileLine(c.Value)
	if !ok {
		return
	}
	content, exists, err := m.ReadFile(ctx, commit, file)
	if err != nil || !exists {
		c.Verified = report.TriNo
		c.Evidence = "file not found"
		return
	}
	total := strings.Count(string(content), "\n") + 1
	if lineNum < 1 || lineNum > total {
		c.Verified = report.TriNo
		c.Evidence = fmt.Sprintf("file has %d lines", total)
		return
	}
	for _, d := range decls {
		if d.file == file && lineNum >= d.line && lineNum <= d.endLine {
			c.Verified = report.TriYes
			c.Evidence = fmt.Sprintf("inside %s (%s:%d-%d)", report.Printable(d.name), report.Printable(d.file), d.line, d.endLine)
			return
		}
	}
	c.Verified = report.TriYes
	c.Evidence = fmt.Sprintf("line exists (file has %d lines)", total)
}

// splitFileLine parses a claim value shaped "file.go:123" — the exact
// shape deterministic.lineClaims produces.
func splitFileLine(value string) (file string, line int, ok bool) {
	idx := strings.LastIndexByte(value, ':')
	if idx < 0 {
		return "", 0, false
	}
	n, err := strconv.Atoi(value[idx+1:])
	if err != nil || n < 1 {
		return "", 0, false
	}
	return value[:idx], n, true
}

func shortSHA(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}
```

- [ ] **Step 4: Run the tests to confirm they pass**

Run: `go test ./internal/ground/... -v`
Expected: PASS

- [ ] **Step 5: Commit and push**

```bash
git add internal/ground/ground.go internal/ground/ground_test.go
git commit -s -m "feat(ground): add claim grounding orchestration"
git push origin main
```

---

### Task 5: `internal/ground` — `Grounder` interface and `Service`

**Files:**
- Create: `internal/ground/service.go`
- Create: `internal/ground/service_test.go`

**Interfaces:**
- Consumes: `OpenMirror`, `groundClaims` (Tasks 3–4); `report.Claim`, `report.Report` (`internal/report`).
- Produces: `ground.Grounder` interface (`Ground(ctx, r, claims) (grounded []report.Claim, refResolved bool, resolvedRef string)` — no error); `ground.Service` type; `ground.NewService(dataDir string) *Service`.

- [ ] **Step 1: Write the failing tests**

Create `internal/ground/service_test.go`:

```go
package ground

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

func TestGithubOriginURL(t *testing.T) {
	if got := githubOriginURL("golang/net"); got != "https://github.com/golang/net.git" {
		t.Errorf("githubOriginURL = %q", got)
	}
}

func TestServiceGroundSuccess(t *testing.T) {
	origin, commit := newGroundTestOrigin(t)
	s := NewService(t.TempDir())
	s.originURL = func(string) string { return origin }
	r := report.Report{ID: "R1", Repo: "owner/name", ClaimedRef: commit}
	claims := []report.Claim{{Kind: report.ClaimFile, Value: "main.go"}}
	grounded, resolved, resolvedRef := s.Ground(context.Background(), r, claims)
	if !resolved || resolvedRef != commit {
		t.Fatalf("resolved = %v, resolvedRef = %q, want true, %q", resolved, resolvedRef, commit)
	}
	if grounded[0].Verified != report.TriYes {
		t.Errorf("claim = %+v, want Verified: yes", grounded[0])
	}
}

func TestServiceGroundDegradesOnCloneFailure(t *testing.T) {
	s := NewService(t.TempDir())
	s.originURL = func(string) string { return filepath.Join(t.TempDir(), "does-not-exist") }
	r := report.Report{ID: "R1", Repo: "owner/name", ClaimedRef: "deadbeef"}
	claims := []report.Claim{{Kind: report.ClaimFile, Value: "a.go"}}
	grounded, resolved, resolvedRef := s.Ground(context.Background(), r, claims)
	if resolved {
		t.Error("want resolved = false for an unreachable origin")
	}
	if resolvedRef != "" {
		t.Errorf("resolvedRef = %q, want empty", resolvedRef)
	}
	if len(grounded) != 1 || grounded[0].Value != "a.go" {
		t.Errorf("grounded = %+v, want the original claims returned unchanged", grounded)
	}
}

func TestServiceImplementsGrounder(t *testing.T) {
	var _ Grounder = (*Service)(nil)
}
```

- [ ] **Step 2: Run the tests to confirm they fail**

Run: `go test ./internal/ground/... -run 'TestGithubOriginURL|TestServiceGround|TestServiceImplementsGrounder'`
Expected: FAIL — `Service`, `NewService`, `githubOriginURL`, `Grounder` don't exist yet.

- [ ] **Step 3: Implement `internal/ground/service.go`**

```go
package ground

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// Grounder is what pipeline.Run needs from this package. It never
// returns an error: a grounding failure (unreachable repo, a
// clone/fetch error, a git error) degrades to refResolved=false, the
// same signal as a ref that simply never resolved — Compose already
// treats that as NEEDS_INFO, never a rejection.
type Grounder interface {
	Ground(ctx context.Context, r report.Report, claims []report.Claim) (grounded []report.Claim, refResolved bool, resolvedRef string)
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
// (claims unchanged, false, "") rather than surfacing as an error.
func (s *Service) Ground(ctx context.Context, r report.Report, claims []report.Claim) ([]report.Claim, bool, string) {
	m, err := OpenMirror(s.dataDir, r.Repo, s.originURL(r.Repo))
	if err != nil {
		slog.Default().Warn("grounding: could not open mirror, degrading to ungrounded claims",
			"report_id", r.ID, "repo", r.Repo, "error", err)
		return claims, false, ""
	}
	grounded, resolved, commit, err := groundClaims(ctx, m, r, claims)
	if err != nil {
		slog.Default().Warn("grounding failed, degrading to ungrounded claims",
			"report_id", r.ID, "repo", r.Repo, "error", err)
		return claims, false, ""
	}
	return grounded, resolved, commit
}

func githubOriginURL(repo string) string {
	return fmt.Sprintf("https://github.com/%s.git", repo)
}
```

- [ ] **Step 4: Run the tests to confirm they pass**

Run: `go test ./internal/ground/... -v`
Expected: PASS. Confirm `TestServiceGroundDegradesOnCloneFailure` completes quickly (it must never attempt real network access — the overridden `originURL` points at a nonexistent local path).

- [ ] **Step 5: Run the whole `ground` package suite once more**

Run: `go build ./... && go test ./internal/ground/... -v`
Expected: PASS — every test from Tasks 2–5 together.

- [ ] **Step 6: Commit and push**

```bash
git add internal/ground/service.go internal/ground/service_test.go
git commit -s -m "feat(ground): add Grounder interface and Service"
git push origin main
```

---

### Task 6: `verdict.StageResults` and `Compose` grounding outcomes

**Files:**
- Modify: `internal/verdict/verdict.go`
- Modify: `internal/verdict/verdict_test.go`

**Interfaces:**
- Produces: `verdict.StageResults` gains `GroundingRan bool`, `RefResolved bool`, `ResolvedRef string` (additive; `Claims` and `LLMUnavailable` unchanged). `Compose`'s signature is unchanged (`Compose(r report.Report, res StageResults) report.Verdict`).
- Consumes: `report.ClaimFile`, `report.ClaimFunction`, `report.TriNo` (`internal/report`, already built).

- [ ] **Step 1: Write the failing tests**

Add these to `internal/verdict/verdict_test.go` (keep every existing test unchanged):

```go
func TestComposeRefNotResolved(t *testing.T) {
	v := Compose(report.Report{ID: "R1", ClaimedRef: "deadbeef"}, StageResults{GroundingRan: true, RefResolved: false})
	if v.Outcome != report.OutcomeNeedsInfo {
		t.Errorf("Outcome = %s, want NEEDS_INFO", v.Outcome)
	}
}

func TestComposeGroundingFailedOnHardClaim(t *testing.T) {
	tests := []report.ClaimKind{report.ClaimFile, report.ClaimFunction}
	for _, kind := range tests {
		claims := []report.Claim{{Kind: kind, Value: "x", Verified: report.TriNo}}
		v := Compose(report.Report{ID: "R1", ClaimedRef: "v1"}, StageResults{Claims: claims, GroundingRan: true, RefResolved: true})
		if v.Outcome != report.OutcomeGroundingFailed {
			t.Errorf("kind %s: Outcome = %s, want GROUNDING_FAILED", kind, v.Outcome)
		}
	}
}

func TestComposeLineOnlyFailureNeverGroundingFails(t *testing.T) {
	claims := []report.Claim{{Kind: report.ClaimLine, Value: "a.go:9999", Verified: report.TriNo}}
	v := Compose(report.Report{ID: "R1", ClaimedRef: "v1"}, StageResults{Claims: claims, GroundingRan: true, RefResolved: true})
	if v.Outcome != report.OutcomeInconclusive {
		t.Errorf("Outcome = %s, want INCONCLUSIVE (a line claim alone must never cause GROUNDING_FAILED)", v.Outcome)
	}
}

func TestComposeGroundingSucceededNoHardFailure(t *testing.T) {
	claims := []report.Claim{{Kind: report.ClaimFile, Value: "a.go", Verified: report.TriYes}}
	v := Compose(report.Report{ID: "R1", ClaimedRef: "v1"}, StageResults{Claims: claims, GroundingRan: true, RefResolved: true})
	if v.Outcome != report.OutcomeInconclusive {
		t.Errorf("Outcome = %s, want INCONCLUSIVE", v.Outcome)
	}
}

func TestComposeNoGrounderConfiguredIsUnaffected(t *testing.T) {
	// GroundingRan defaults to false (the zero value) when no Grounder
	// was wired into the pipeline at all — this must behave exactly
	// like Week 2 (no regression for callers that don't configure one).
	v := Compose(report.Report{ID: "R1", ClaimedRef: "v1"}, StageResults{})
	if v.Outcome != report.OutcomeInconclusive {
		t.Errorf("Outcome = %s, want INCONCLUSIVE", v.Outcome)
	}
}

func TestComposeStillAppendsLLMUnavailableNote(t *testing.T) {
	claims := []report.Claim{{Kind: report.ClaimFile, Value: "x", Verified: report.TriNo}}
	v := Compose(report.Report{ID: "R1", ClaimedRef: "v1"}, StageResults{Claims: claims, GroundingRan: true, RefResolved: true, LLMUnavailable: true})
	if v.Outcome != report.OutcomeGroundingFailed {
		t.Errorf("Outcome = %s, want GROUNDING_FAILED", v.Outcome)
	}
	found := false
	for _, n := range v.Notes {
		if strings.Contains(n, "LLM extraction unavailable") {
			found = true
		}
	}
	if !found {
		t.Errorf("Notes = %v, want the LLM-unavailable note to still be appended alongside a GROUNDING_FAILED outcome", v.Notes)
	}
}
```

- [ ] **Step 2: Run the tests to confirm they fail**

Run: `go test ./internal/verdict/...`
Expected: FAIL — `StageResults` has no `GroundingRan`/`RefResolved` fields yet, and `Compose` doesn't produce `GROUNDING_FAILED`.

- [ ] **Step 3: Implement the changes**

In `internal/verdict/verdict.go`, replace `StageResults` and `Compose`:

```go
// StageResults carries the outputs of pipeline stages that have run so
// far. It grows one field per milestone; each addition is a
// non-breaking change as long as callers use named-field struct
// literals.
type StageResults struct {
	Claims []report.Claim
	// LLMUnavailable is true when the pipeline configured an LLM
	// extraction chain but every provider in it failed, so the
	// verdict's claims are deterministic-only even though an operator
	// expected LLM-assisted extraction. It's false, and produces no
	// note, when no LLM was configured at all (the normal, expected,
	// non-error state).
	LLMUnavailable bool
	// GroundingRan is true when a Grounder was configured and called.
	// It's false (the zero value) when no grounder was wired in at
	// all — a caller that never sets it up keeps Week 2's behavior
	// exactly (no NEEDS_INFO/GROUNDING_FAILED path from this stage).
	GroundingRan bool
	// RefResolved is true when the claimed ref (or a fallback
	// ClaimVersion value) resolved to a commit. Only meaningful when
	// GroundingRan is true.
	RefResolved bool
	// ResolvedRef is the commit grounding actually checked claims
	// against, if RefResolved.
	ResolvedRef string
}

// Compose builds the verdict from the stage results available so far.
// Precedence: no ref given -> NEEDS_INFO; a ref given but grounding
// couldn't resolve it (or any fallback) -> NEEDS_INFO; a hard claim
// (file or function) that grounding found missing -> GROUNDING_FAILED,
// never on a line-only mismatch; otherwise INCONCLUSIVE, since dedupe
// and sandbox aren't implemented yet.
func Compose(r report.Report, res StageResults) report.Verdict {
	v := report.Verdict{ReportID: r.ID, Claims: res.Claims}
	switch {
	case r.ClaimedRef == "":
		v.Outcome = report.OutcomeNeedsInfo
		v.Notes = append(v.Notes, "no commit or tag given; can't check claims against the code")
	case res.GroundingRan && !res.RefResolved:
		v.Outcome = report.OutcomeNeedsInfo
		v.Notes = append(v.Notes, "claimed ref did not resolve to a commit in the repository")
	case res.GroundingRan && hardClaimFailed(res.Claims):
		v.Outcome = report.OutcomeGroundingFailed
		v.Notes = append(v.Notes, "a claimed file or function does not exist at the resolved commit")
	default:
		v.Outcome = report.OutcomeInconclusive
		v.Notes = append(v.Notes, "dedupe and sandbox stages are not implemented yet")
	}
	if res.LLMUnavailable {
		v.Notes = append(v.Notes, "LLM extraction unavailable; deterministic claims only")
	}
	return v
}

// hardClaimFailed reports whether any hard claim (file or function)
// was checked and found missing. A line claim (soft) is never
// consulted here, regardless of its own Verified value.
func hardClaimFailed(claims []report.Claim) bool {
	for _, c := range claims {
		if (c.Kind == report.ClaimFile || c.Kind == report.ClaimFunction) && c.Verified == report.TriNo {
			return true
		}
	}
	return false
}
```

Leave `Render` and `shortRef` unchanged.

- [ ] **Step 4: Run the tests to confirm they pass**

Run: `go test ./internal/verdict/... -v`
Expected: PASS — every existing test plus the six new ones.

- [ ] **Step 5: Run the full build**

Run: `go build ./... && go test ./...`
Expected: PASS. `internal/pipeline` and `cmd/kritolith` still call `Compose`/build `StageResults{...}` with named fields only, so this addition doesn't break either — confirm that directly rather than assuming it.

- [ ] **Step 6: Commit and push**

```bash
git add internal/verdict/verdict.go internal/verdict/verdict_test.go
git commit -s -m "feat(verdict): add GROUNDING_FAILED/NEEDS_INFO precedence for grounding"
git push origin main
```

---

### Task 7: `pipeline.WithGround` wiring

**Files:**
- Modify: `internal/pipeline/pipeline.go`
- Modify: `internal/pipeline/pipeline_test.go`

**Interfaces:**
- Consumes: `ground.Grounder` (Task 5); `verdict.StageResults`'s new fields (Task 6).
- Produces: `(*Pipeline).WithGround(g ground.Grounder) *Pipeline`. `Pipeline.Run`'s behavior changes (documented below); its signature does not.

- [ ] **Step 1: Write the failing tests**

Add these to `internal/pipeline/pipeline_test.go` (keep every existing test, including the Task-9-of-Week-2 additions, unchanged):

```go
type fakeGrounder struct {
	claims      []report.Claim // if non-nil, returned as-is instead of the input claims
	resolved    bool
	resolvedRef string
}

func (g fakeGrounder) Ground(ctx context.Context, r report.Report, claims []report.Claim) ([]report.Claim, bool, string) {
	out := claims
	if g.claims != nil {
		out = g.claims
	}
	return out, g.resolved, g.resolvedRef
}

func TestRunGroundingFailedOutcome(t *testing.T) {
	fs := &fakeStore{}
	r := report.Report{ID: "R1", Repo: "a/b", ClaimedRef: "v1", Body: "See a.go for the bug."}
	failed := []report.Claim{{Kind: report.ClaimFile, Value: "a.go", Verified: report.TriNo, Evidence: "not found"}}
	v, err := New(fs).WithGround(fakeGrounder{claims: failed, resolved: true, resolvedRef: "abc123"}).Run(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if v.Outcome != report.OutcomeGroundingFailed {
		t.Errorf("Outcome = %s, want GROUNDING_FAILED", v.Outcome)
	}
}

func TestRunGroundingRefNotResolved(t *testing.T) {
	fs := &fakeStore{}
	r := report.Report{ID: "R1", Repo: "a/b", ClaimedRef: "v1", Body: "See a.go."}
	v, err := New(fs).WithGround(fakeGrounder{resolved: false}).Run(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if v.Outcome != report.OutcomeNeedsInfo {
		t.Errorf("Outcome = %s, want NEEDS_INFO", v.Outcome)
	}
}

func TestRunWithNoGrounderConfiguredIsUnchanged(t *testing.T) {
	fs := &fakeStore{}
	r := report.Report{ID: "R1", Repo: "a/b", ClaimedRef: "v1", Body: "See a.go."}
	v, err := New(fs).Run(context.Background(), r) // no WithGround call
	if err != nil {
		t.Fatal(err)
	}
	if v.Outcome != report.OutcomeInconclusive {
		t.Errorf("Outcome = %s, want INCONCLUSIVE (no grounder configured must behave exactly like before Week 3)", v.Outcome)
	}
}
```

- [ ] **Step 2: Run the tests to confirm they fail**

Run: `go test ./internal/pipeline/...`
Expected: FAIL — `WithGround` doesn't exist yet.

- [ ] **Step 3: Implement the pipeline changes**

Replace `internal/pipeline/pipeline.go` in full:

```go
// Package pipeline runs a report through Kritolith's stages and stores
// the result. Later milestones add dedupe and sandbox between
// grounding and composing the verdict.
package pipeline

import (
	"context"
	"fmt"

	"github.com/ergasterion-dev/kritolith/internal/extract/deterministic"
	"github.com/ergasterion-dev/kritolith/internal/extract/llmextract"
	"github.com/ergasterion-dev/kritolith/internal/ground"
	"github.com/ergasterion-dev/kritolith/internal/report"
	"github.com/ergasterion-dev/kritolith/internal/verdict"
)

// Store is the persistence the pipeline needs.
type Store interface {
	SaveReport(ctx context.Context, r report.Report) error
	SaveVerdict(ctx context.Context, v report.Verdict) error
}

// Pipeline processes reports.
type Pipeline struct {
	store    Store
	llmChain llmextract.Chain // nil when no LLM is configured
	grounder ground.Grounder  // nil when no Grounder is configured
}

// New returns a Pipeline that persists to s, with no LLM or Grounder
// configured.
func New(s Store) *Pipeline { return &Pipeline{store: s} }

// WithLLM returns p configured to also try LLM extraction through
// chain. A nil chain (New's default) skips the LLM extraction stage
// entirely: Kritolith must work with no LLM configured.
func (p *Pipeline) WithLLM(chain llmextract.Chain) *Pipeline {
	p.llmChain = chain
	return p
}

// WithGround returns p configured to also ground claims through g. A
// nil grounder (New's default) skips the grounding stage entirely:
// Run behaves exactly as it did before Week 3, for any caller that
// doesn't wire one in.
func (p *Pipeline) WithGround(g ground.Grounder) *Pipeline {
	p.grounder = g
	return p
}

// Run stores the report, extracts claims, grounds them, composes the
// verdict and stores that too. Deterministic extraction always runs;
// LLM extraction runs only when WithLLM configured a chain, and its
// claims never override a deterministic claim with the same kind and
// value. Grounding runs only when WithGround configured a grounder; it
// never fails Run — a grounding failure of any kind degrades to a
// "ref not resolved" verdict, never a pipeline error.
func (p *Pipeline) Run(ctx context.Context, r report.Report) (report.Verdict, error) {
	if err := p.store.SaveReport(ctx, r); err != nil {
		return report.Verdict{}, fmt.Errorf("pipeline: save report: %w", err)
	}
	claims := deterministic.Extract(r.Body)
	var llmUnavailable bool
	if p.llmChain != nil {
		llmClaims := llmextract.Extract(ctx, p.llmChain, r)
		llmUnavailable = len(llmClaims) == 0
		claims = mergeClaims(claims, llmClaims)
	}
	res := verdict.StageResults{Claims: claims, LLMUnavailable: llmUnavailable}
	if p.grounder != nil {
		grounded, resolved, resolvedRef := p.grounder.Ground(ctx, r, claims)
		res.Claims = grounded
		res.GroundingRan = true
		res.RefResolved = resolved
		res.ResolvedRef = resolvedRef
	}
	v := verdict.Compose(r, res)
	if err := p.store.SaveVerdict(ctx, v); err != nil {
		return report.Verdict{}, fmt.Errorf("pipeline: save verdict: %w", err)
	}
	return v, nil
}

// mergeClaims combines deterministic and LLM-sourced claims. A
// deterministic claim always wins over an LLM claim with the same
// (Kind, Value): the LLM claim is dropped, not appended.
func mergeClaims(det, fromLLM []report.Claim) []report.Claim {
	seen := make(map[string]bool, len(det))
	for _, c := range det {
		seen[string(c.Kind)+"\x00"+c.Value] = true
	}
	out := append([]report.Claim(nil), det...)
	for _, c := range fromLLM {
		if seen[string(c.Kind)+"\x00"+c.Value] {
			continue
		}
		out = append(out, c)
	}
	return out
}
```

- [ ] **Step 4: Run the tests to confirm they pass**

Run: `go test ./internal/pipeline/... -v`
Expected: PASS — every Week 1/2 test unchanged in outcome, plus the three new ones.

- [ ] **Step 5: Run the full build**

Run: `go build ./... && go test ./...`
Expected: PASS.

- [ ] **Step 6: Commit and push**

```bash
git add internal/pipeline/pipeline.go internal/pipeline/pipeline_test.go
git commit -s -m "feat(pipeline): wire grounding as an optional stage"
git push origin main
```

---

### Task 8: CLI wiring (`check`, `eval`)

**Files:**
- Modify: `cmd/kritolith/check.go`
- Modify: `cmd/kritolith/eval.go`

**Interfaces:**
- Consumes: `ground.NewService(dataDir string) *ground.Service` (Task 5); `(*Pipeline).WithGround` (Task 7).
- Produces: nothing new — both commands now always ground reports.

- [ ] **Step 1: Add the import and wire `WithGround` in `check.go`**

In `cmd/kritolith/check.go`, add `"github.com/ergasterion-dev/kritolith/internal/ground"` to the imports, and change the pipeline construction:

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

(`dir` is already the resolved data dir computed a few lines above by `resolveDataDir`.)

- [ ] **Step 2: Add the import and wire `WithGround` in `eval.go`**

In `cmd/kritolith/eval.go`, add the same import, and change the pipeline construction the same way:

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

- [ ] **Step 3: Run the existing CLI tests to confirm nothing broke**

Run: `go build ./... && go test ./cmd/kritolith/... -v`
Expected: Most tests unaffected — `TestCheckEndToEnd`, `TestCheckJSONStoresVerdict` and similar tests that use `--repo golang/net --ref <a real SHA>` will now try to actually clone `golang/net` from GitHub (network required; confirmed reachable from this environment during planning). Read the actual output of every test that changed and update any hardcoded outcome expectation (e.g. an assertion that literally checks for `INCONCLUSIVE` on a report whose ref/claims would now genuinely ground and, depending on the report body, might land on a different outcome) — do not weaken an assertion just to make it pass; if a test's expected outcome is now wrong, figure out why from the real grounding behavior and fix the expectation to match reality, or the report content if that's what's actually unrealistic.

- [ ] **Step 4: Fix or extend any test whose expectation Step 3 revealed as stale**

There is no pre-written diff for this step — the exact changes depend on what Step 3's test run actually shows. Read every failing test's report body/PoC content, confirm what SHOULD happen once real grounding runs against the real `golang/net` (or whichever repo) commit each test uses, and adjust that test's expectation to match. Do not touch `internal/ground`, `internal/verdict`, or `internal/pipeline` from this task — if a test failure looks like a grounding *logic* bug rather than a stale test expectation, stop and report NEEDS_CONTEXT rather than patching around it here (that class of bug belongs to Task 9's corpus acceptance work, which has the full picture).

- [ ] **Step 5: Run the full build and suite**

Run: `go build ./... && go test ./...`
Expected: PASS.

- [ ] **Step 6: Commit and push**

```bash
git add cmd/kritolith/check.go cmd/kritolith/eval.go cmd/kritolith/check_test.go cmd/kritolith/eval_test.go
git commit -s -m "feat(cli): wire grounding into check and eval"
git push origin main
```

(Include `check_test.go`/`eval_test.go` in the `git add` only if Step 4 actually touched them — Steps 1–2 alone don't require it.)

---

### Task 9: Eval corpus acceptance run

**Files:** none pre-specified — this task verifies the whole milestone against the real 40-case corpus (real GitHub repos, real network) and fixes whatever it finds. It may touch any file under `internal/ground/`, and only there, unless a genuine bug in an earlier task's file is the actual root cause.

**Interfaces:** none new. This task's job is verification and, if needed, correction of the code already built in Tasks 1–8.

**This is the acceptance test for the whole milestone.** CLAUDE.md's hard v1 target — zero real reports wrongly marked `GROUNDING_FAILED` — is the actual gate here, not a description of intended behavior. A false `GROUNDING_FAILED` on a real report is the single worst bug this project can ship (CLAUDE.md principle 2).

- [ ] **Step 1: Run the full eval corpus for real**

Run: `make eval` (this will take real wall-clock time and real network — it clones ~20 real GitHub repos, including `golang/net`, on first run; subsequent runs reuse the mirrors if `--data-dir` is held constant, but `make eval`'s default uses a fresh temp dir each time, so every `make eval` invocation re-clones everything. Use `go run ./cmd/kritolith eval --corpus testdata/corpus --data-dir /tmp/kritolith-eval-work` instead while iterating, so repeated runs during this task reuse warm mirrors and go faster — clean up `/tmp/kritolith-eval-work` when you're done, it's not part of the repo).

Read the full scoreboard output, not just the summary line.

- [ ] **Step 2: Confirm the hard gate**

The summary line `real wrongly GROUNDING_FAILED: N (must be 0)` must show `N == 0`. If it's not zero:

1. Identify which real case(s) are wrongly `GROUNDING_FAILED`.
2. For each one, read `testdata/corpus/real/<id>/report.md` and its `meta.json` to see exactly what claim(s) the report makes and what commit it's grounded against.
3. Read the actual repository content at that commit (`git show <ref>:<path>` against the mirror that `make eval`/your iteration run already created under your `--data-dir`, or `git clone` it yourself into a scratch dir to look around) to see what the claimed file/function actually looks like there.
4. Diagnose why grounding said "not found" when the real code says otherwise. The likely culprits, roughly in order of likelihood:
   - The function-matching heuristic in `internal/ground/ast.go` is too strict for a real claim shape (e.g. a claim written as `(*Type).Method` where the actual receiver in source is unexported, or a generic type parameter confuses `receiverTypeName`, or an interface method claim that has no concrete `FuncDecl` at all — interface method claims can't be grounded this way and should be treated as "can't verify" (`Verified: unknown`), not "not found," since we have no way to confirm or deny them by declaration search alone).
   - A claim's value doesn't match `internal/extract/deterministic`'s intended shape (check what `deterministic.Extract` actually produced for that report — a bug or gap in Week 2's extractor showing up now that its output is actually being checked for real).
   - `ValidateClaimPath` or `ValidateRef` over-rejecting a legitimate value.
5. Fix the root cause with the smallest correct change. If the fix is in `internal/ground`, add a regression test for the exact shape that failed (a fixture mirroring the real claim, not a copy of the real report's content — never commit real embargoed-adjacent report text into the repo, and this corpus is public advisories anyway, but keep test fixtures minimal and synthetic where possible). If you're not confident a proposed fix is correct and narrowly scoped (versus a much larger design gap), stop and report `BLOCKED`/`DONE_WITH_CONCERNS` describing exactly what you found rather than shipping a guess against this hard gate.
6. Re-run and re-check. Repeat until `real wrongly GROUNDING_FAILED: 0`.

**Never** relax this gate, weaken a test, or special-case a specific corpus ID to make the number go to zero without a genuine fix. That defeats the entire purpose of this task.

- [ ] **Step 3: Check the fabricated-catch rate**

The scoreboard's `fabricated caught by grounding: M/15` should be **≥80% (12/15)** per the spec's acceptance target. If it's below that, read the failing fabricated cases the same way (Step 2's method, applied to `testdata/corpus/fabricated/`) and fix genuine gaps the same way. This target is a should, not a hard gate like Step 2's — if you get close but not quite there after reasonable effort, report the actual number and what you tried in `DONE_WITH_CONCERNS` rather than forcing it.

- [ ] **Step 4: Confirm `fab-018`/`fab-019` and `fab-015`/`016`/`017` are unaffected**

`fab-018`/`fab-019` (no ref, no PoC) should still show `NEEDS_INFO` — unrelated to grounding, but confirm this milestone didn't regress it. `fab-015`/`016`/`017` (near-duplicates, real files/functions referenced) should ground cleanly and land on `INCONCLUSIVE` (dedupe, which would otherwise reclassify them as `LIKELY_DUPLICATE`, is Week 4's job, not this one's).

- [ ] **Step 5: Run the full test suite and `make ci` one more time**

Run: `go build ./... && go test ./... && make ci`
Expected: PASS. Confirm `go.mod` is unchanged (no new dependency snuck in while iterating).

- [ ] **Step 6: Commit and push**

If Step 2 or Step 3 required any code changes:

```bash
git add internal/ground/  # plus any other files a genuine root-cause fix required
git commit -s -m "fix(ground): <describe the specific gap the real corpus run found>"
git push origin main
```

If no changes were needed (the hard gate and the 80% target both passed on the first real run), report that plainly — there's nothing to commit.

---

## Final verification (after all 9 tasks)

```bash
make ci
go run ./cmd/kritolith eval --corpus testdata/corpus --data-dir /tmp/kritolith-final-check
rm -rf /tmp/kritolith-final-check
gh run watch --exit-status $(gh run list --workflow ci --limit 1 --json databaseId --jq '.[0].databaseId')
```

Confirm against the spec's acceptance criteria (§7):
- `make eval`: zero real cases wrongly `GROUNDING_FAILED` (hard gate).
- ≥80% of the 15 fabricated fake-code cases now reach `GROUNDING_FAILED`.
- `fab-018`/`fab-019` still `NEEDS_INFO`; `fab-015`/`016`/`017` still `INCONCLUSIVE` (not reclassified — dedupe is Week 4).
- No claim value ever reaches a `git` subprocess argument without passing through `ValidateClaimPath`/`ValidateRef` first (spot-check `internal/ground/mirror.go`'s call sites).
- `make ci` green; `go.mod` unchanged from before this plan.
