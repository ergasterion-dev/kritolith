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
