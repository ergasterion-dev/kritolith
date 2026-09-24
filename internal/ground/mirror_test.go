package ground

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/report"
	"github.com/ergasterion-dev/kritolith/internal/verdict"
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
	sha, resolved, viaFallback, err := m.EnsureAndResolve(context.Background(), commit, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !resolved || sha != commit || viaFallback {
		t.Fatalf("EnsureAndResolve = %q, %v, %v, want %q, true, false", sha, resolved, viaFallback, commit)
	}
}

func TestEnsureAndResolveCacheHitNeedsNoNetwork(t *testing.T) {
	origin, commit := newTestOrigin(t)
	dataDir := t.TempDir()
	m, err := OpenMirror(dataDir, "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	if _, resolved, _, err := m.EnsureAndResolve(context.Background(), commit, nil); err != nil || !resolved {
		t.Fatalf("first resolve failed: %v %v", resolved, err)
	}
	// Point a second Mirror at the same on-disk data dir but a
	// nonexistent origin: a cache-hit resolve must not need it.
	m2, err := OpenMirror(dataDir, "owner/name", filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatal(err)
	}
	sha, resolved, _, err := m2.EnsureAndResolve(context.Background(), commit, nil)
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
	if _, resolved, _, err := m.EnsureAndResolve(context.Background(), commit1, nil); err != nil || !resolved {
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

	sha, resolved, _, err := m.EnsureAndResolve(context.Background(), commit2, nil)
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
	sha, resolved, viaFallback, err := m.EnsureAndResolve(context.Background(), "does-not-exist-as-a-ref", []string{"v1.0.0"})
	if err != nil || !resolved || sha != commit || !viaFallback {
		t.Fatalf("fallback resolve = %q, %v, %v, %v, want %q, true, true, nil", sha, resolved, viaFallback, err, commit)
	}
}

func TestEnsureAndResolveNothingResolves(t *testing.T) {
	origin, _ := newTestOrigin(t)
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	_, resolved, _, err := m.EnsureAndResolve(context.Background(), "totally-unknown-ref", []string{"also-unknown"})
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
	sha, resolved, _, err := m.EnsureAndResolve(context.Background(), "--upload-pack=x", []string{"v1.0.0"})
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
	if _, _, _, err := m.EnsureAndResolve(ctx, commit, nil); err != nil {
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

func TestReadFileSkipsOversizedBlobBeforeReading(t *testing.T) {
	origin, commit1 := newTestOrigin(t)
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, _, _, err := m.EnsureAndResolve(ctx, commit1, nil); err != nil {
		t.Fatal(err)
	}

	// Add a file that's larger than a tiny, test-only cap. It doesn't
	// need to be anywhere near the real 10MB default — the point is to
	// prove the size gate fires, not to exercise a multi-megabyte
	// fixture.
	big := strings.Repeat("x", 1000)
	if err := os.WriteFile(filepath.Join(origin, "big.go"), []byte(big), 0o644); err != nil {
		t.Fatal(err)
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
	run("add", "big.go")
	run("commit", "-q", "-m", "add big file")
	commit2 := run("rev-parse", "HEAD")
	if _, resolved, _, err := m.EnsureAndResolve(ctx, commit2, nil); err != nil || !resolved {
		t.Fatalf("resolve commit2 failed: %v %v", resolved, err)
	}

	old := maxReadBytes
	maxReadBytes = 100 // well under len(big); forces the size gate to trip
	defer func() { maxReadBytes = old }()

	// Confirm the file genuinely exists in the tree, so a false result
	// from ReadFile below is attributable to the size gate — not to a
	// missing-path false, which is a different code path.
	if ok, err := m.FileExists(ctx, commit2, "big.go"); err != nil || !ok {
		t.Fatalf("FileExists(big.go) = %v, %v, want true, nil", ok, err)
	}

	content, ok, err := m.ReadFile(ctx, commit2, "big.go")
	if err != nil || ok || content != nil {
		t.Fatalf("ReadFile(big.go) over cap = %q, %v, %v, want nil, false, nil", content, ok, err)
	}
}

func TestFileExistsRejectsTraversal(t *testing.T) {
	origin, commit := newTestOrigin(t)
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, _, _, err := m.EnsureAndResolve(ctx, commit, nil); err != nil {
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
	if _, _, _, err := m.EnsureAndResolve(ctx, commit, nil); err != nil {
		t.Fatal(err)
	}
	files, gitlinks, err := m.ListGoFiles(ctx, commit)
	if err != nil || len(files) != 1 || files[0] != "a.go" || gitlinks != 0 {
		t.Fatalf("ListGoFiles = %v, %d, %v, want [a.go], 0, nil", files, gitlinks, err)
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

// commitIn adds a Go file to dir's current branch and returns the new
// commit.
func commitIn(t *testing.T, dir, name, content string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, dir, "add", name)
	gitIn(t, dir, "commit", "-q", "-m", "add "+name)
	return gitIn(t, dir, "rev-parse", "HEAD")
}

// Final-review C1, the reviewer's reproduction: the mirror was cloned
// at v1.0.0, upstream then gained a commit adding parseThing, and a
// report cites that newer commit while also mentioning v1.0.0. The
// claimed commit must win (after a fetch) over the fallback tag that
// happens to resolve against the stale mirror.
func TestEnsureAndResolveStaleMirrorPrefersClaimedCommitOverFallback(t *testing.T) {
	origin, commit1 := newTestOrigin(t) // tagged v1.0.0
	dataDir := t.TempDir()
	m, err := OpenMirror(dataDir, "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, resolved, _, err := m.EnsureAndResolve(ctx, "v1.0.0", nil); err != nil || !resolved {
		t.Fatalf("initial clone/resolve failed: %v %v", resolved, err)
	}
	commit2 := commitIn(t, origin, "thing.go", "package a\n\nfunc parseThing() {}\n")

	sha, resolved, viaFallback, err := m.EnsureAndResolve(ctx, commit2, []string{"v1.0.0"})
	if err != nil || !resolved || sha != commit2 || viaFallback {
		t.Fatalf("resolve = %q, %v, %v, %v; want %q (the claimed commit), true, false, nil — not the stale fallback %q", sha, resolved, viaFallback, err, commit2, commit1)
	}

	// End to end: the claimed function exists at the claimed commit, so
	// the report must not be GROUNDING_FAILED.
	r := report.Report{ID: "R1", Repo: "owner/name", ClaimedRef: commit2}
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "parseThing", Verified: report.TriUnknown},
		{Kind: report.ClaimVersion, Value: "v1.0.0"},
	}
	m2, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	// Reproduce the stale state for groundClaims too: clone at v1.0.0
	// via a fresh data dir whose origin is then advanced again.
	if _, _, _, err := m2.EnsureAndResolve(ctx, "v1.0.0", nil); err != nil {
		t.Fatal(err)
	}
	commit3 := commitIn(t, origin, "thing2.go", "package a\n\nfunc parseOther() {}\n")
	r.ClaimedRef = commit3
	claims[0].Value = "parseOther"
	grounded, resolved, got, viaFallback, _, err := groundClaims(ctx, m2, r, claims)
	if err != nil || !resolved || got != commit3 || viaFallback {
		t.Fatalf("groundClaims = resolved %v, commit %q, viaFallback %v, err %v; want true, %q, false, nil", resolved, got, viaFallback, err, commit3)
	}
	if grounded[0].Verified != report.TriYes {
		t.Errorf("parseOther: Verified = %s, want yes; evidence: %s", grounded[0].Verified, grounded[0].Evidence)
	}
	v := verdict.Compose(r, verdict.StageResults{Claims: grounded, GroundingRan: true, RefResolved: resolved, ResolvedRef: got, ResolvedViaFallback: viaFallback})
	if v.Outcome == report.OutcomeGroundingFailed {
		t.Errorf("Outcome = GROUNDING_FAILED for a real claim at the exact claimed commit")
	}
}

// Final-review C1: a branch name resolved from an existing mirror may
// be stale; it must be refreshed, not trusted from the cache.
func TestEnsureAndResolveRefreshesMovableRef(t *testing.T) {
	origin, commit1 := newTestOrigin(t)
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if sha, resolved, _, err := m.EnsureAndResolve(ctx, "main", nil); err != nil || !resolved || sha != commit1 {
		t.Fatalf("first resolve = %q, %v, %v, want %q", sha, resolved, err, commit1)
	}
	commit2 := commitIn(t, origin, "b.go", "package a\n")
	sha, resolved, viaFallback, err := m.EnsureAndResolve(ctx, "main", nil)
	if err != nil || !resolved || sha != commit2 || viaFallback {
		t.Fatalf("second resolve = %q, %v, %v, %v, want %q (new tip), true, false, nil — not the stale %q", sha, resolved, viaFallback, err, commit2, commit1)
	}
}

// Final-review I2: every git subprocess must run with terminal
// prompting disabled and without inherited repo-redirecting variables.
func TestGitCommandEnvironment(t *testing.T) {
	t.Setenv("GIT_DIR", "/somewhere/else.git")
	t.Setenv("GIT_WORK_TREE", "/somewhere/else")
	t.Setenv("GIT_INDEX_FILE", "/somewhere/else/index")
	t.Setenv("GIT_TERMINAL_PROMPT", "1")
	cmd := gitCommand(context.Background(), t.TempDir(), "status")
	has := map[string]string{}
	for _, kv := range cmd.Env {
		k, v, _ := strings.Cut(kv, "=")
		if _, dup := has[k]; dup {
			t.Errorf("%s set more than once in cmd.Env", k)
		}
		has[k] = v
	}
	if has["GIT_TERMINAL_PROMPT"] != "0" {
		t.Errorf("GIT_TERMINAL_PROMPT = %q, want 0", has["GIT_TERMINAL_PROMPT"])
	}
	if has["GIT_CONFIG_NOSYSTEM"] != "1" {
		t.Errorf("GIT_CONFIG_NOSYSTEM = %q, want 1", has["GIT_CONFIG_NOSYSTEM"])
	}
	for _, k := range []string{"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"} {
		if _, ok := has[k]; ok {
			t.Errorf("%s inherited into cmd.Env, want it stripped", k)
		}
	}
	if cmd.WaitDelay == 0 {
		t.Error("WaitDelay = 0, want a bound so a killed git can't hang Wait")
	}
}

// Final-review I2: an inherited GIT_DIR must not redirect a real
// mirror operation to another repository.
func TestMirrorIgnoresInheritedGitDir(t *testing.T) {
	origin, commit := newTestOrigin(t)
	decoy, _ := newTestOrigin(t)
	t.Setenv("GIT_DIR", filepath.Join(decoy, ".git"))
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	sha, resolved, _, err := m.EnsureAndResolve(context.Background(), commit, nil)
	if err != nil || !resolved || sha != commit {
		t.Fatalf("resolve with a decoy GIT_DIR = %q, %v, %v, want %q", sha, resolved, err, commit)
	}
}

// Final-review I2: clone and fetch are bounded even when the caller's
// context has no deadline, and a failed clone leaves no partial mirror.
func TestCloneTimeoutLeavesNoPartialMirror(t *testing.T) {
	origin, commit := newTestOrigin(t)
	old := networkTimeout
	networkTimeout = time.Nanosecond
	defer func() { networkTimeout = old }()
	dataDir := t.TempDir()
	m, err := OpenMirror(dataDir, "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := m.EnsureAndResolve(context.Background(), commit, nil); err == nil {
		t.Fatal("want a clone error under a 1ns network timeout")
	}
	if m.exists() {
		t.Error("a failed clone left a directory at the mirror path")
	}
	entries, _ := os.ReadDir(filepath.Dir(m.path))
	if len(entries) != 0 {
		t.Errorf("a failed clone left %d entries behind in %s", len(entries), filepath.Dir(m.path))
	}
	networkTimeout = old
	if sha, resolved, _, err := m.EnsureAndResolve(context.Background(), commit, nil); err != nil || !resolved || sha != commit {
		t.Fatalf("retry after failed clone = %q, %v, %v, want %q", sha, resolved, err, commit)
	}
}
