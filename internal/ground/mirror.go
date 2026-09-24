package ground

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// maxReadBytes bounds the work, not just the result: ReadFile checks a
// blob's size (via a cheap `git cat-file -s`) before ever running
// `git show` on it, so an oversized blob is skipped, not read into
// memory and then truncated. It is a var, not a const, so tests can
// override it with a tiny threshold instead of committing a
// multi-megabyte fixture.
var maxReadBytes int64 = 10 << 20

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

// blobSize returns the byte size of the blob at commit:path via
// `git cat-file -s`, which reports only the size — it never streams
// the blob's content, so it's safe to call on an arbitrarily large
// object before deciding whether to read it.
func (m *Mirror) blobSize(ctx context.Context, commit, path string) (int64, error) {
	out, err := m.runGit(ctx, m.path, "cat-file", "-s", commit+":"+path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(out), 10, 64)
}

// ReadFile returns the blob content at commit:path. ok is false if
// the path doesn't exist, or if the blob is larger than
// maxReadBytes — not an error either way. The size is checked with a
// cheap `git cat-file -s` before `git show` ever runs, so an
// oversized blob is skipped, not read into memory and truncated
// after the fact: `git show`'s output is buffered in full by runGit,
// so bounding it after the read would already have paid the memory
// cost the cap is meant to avoid.
func (m *Mirror) ReadFile(ctx context.Context, commit, path string) ([]byte, bool, error) {
	if err := ValidateClaimPath(path); err != nil {
		return nil, false, nil
	}
	size, err := m.blobSize(ctx, commit, path)
	if err != nil {
		return nil, false, nil
	}
	if size > maxReadBytes {
		return nil, false, nil
	}
	out, err := m.runGit(ctx, m.path, "show", commit+":"+path)
	if err != nil {
		return nil, false, nil
	}
	return []byte(out), true, nil
}

// ListGoFiles returns every ".go" file path at commit, via one
// `git ls-tree -r -z`, filtered client-side, plus the number of
// submodule (gitlink, mode 160000) entries in the tree. ls-tree never
// recurses into a submodule, so any Go code inside one is invisible to
// grounding; callers must treat a non-zero gitlinks as an incomplete
// view of the source.
func (m *Mirror) ListGoFiles(ctx context.Context, commit string) (files []string, gitlinks int, err error) {
	out, err := m.runGit(ctx, m.path, "ls-tree", "-r", "-z", commit)
	if err != nil {
		return nil, 0, fmt.Errorf("ground: list files at %s: %w", commit, err)
	}
	for _, entry := range strings.Split(out, "\x00") {
		if entry == "" {
			continue
		}
		// "<mode> SP <type> SP <object> TAB <path>"
		meta, path, ok := strings.Cut(entry, "\t")
		if !ok {
			return nil, 0, fmt.Errorf("ground: list files at %s: malformed ls-tree entry", commit)
		}
		mode, _, _ := strings.Cut(meta, " ")
		if mode == "160000" {
			gitlinks++
			continue
		}
		if strings.HasSuffix(path, ".go") {
			files = append(files, path)
		}
	}
	return files, gitlinks, nil
}

// ContainsWord reports whether name occurs as a whole word anywhere in
// the tracked content at commit — every file, Go or not, including
// string literals, struct tags, templates, and scripts — via
// `git grep -q -w -F`. found is true on git grep's exit 0 and false
// only on its exit 1 ("no match"). Any other outcome is returned as an
// error, never as "not found": callers use a false result as part of
// proving a claim false, so a git failure must not be able to
// masquerade as absence.
func (m *Mirror) ContainsWord(ctx context.Context, commit, name string) (found bool, err error) {
	cmd := exec.CommandContext(ctx, "git", "grep", "-q", "-w", "-F", "-e", name, commit, "--")
	cmd.Dir = m.path
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	runErr := cmd.Run()
	if runErr == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) && exitErr.ExitCode() == 1 && errBuf.Len() == 0 {
		return false, nil
	}
	return false, fmt.Errorf("ground: git grep at %s: %w: %s", commit, runErr, strings.TrimSpace(errBuf.String()))
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
