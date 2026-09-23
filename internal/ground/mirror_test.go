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
