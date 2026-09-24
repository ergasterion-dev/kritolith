package ground

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

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

// networkTimeout is a hard cap on each clone or fetch — the only
// operations here that touch the network. The CLI's context carries no
// deadline, so without it a remote that trickles data forever would
// hang a check or eval run. It is generous because a first mirror clone
// of a large repository legitimately takes many minutes (cosmos-sdk
// takes over ten); a stalled transfer is caught much sooner by
// networkStallArgs. It is a var so tests can shorten it.
var networkTimeout = 30 * time.Minute

// networkStallArgs makes git itself abort an HTTP transfer that stays
// below 1 KiB/s for two minutes, so a dead connection fails fast
// without the hard cap having to cut off a slow but healthy clone.
var networkStallArgs = []string{"-c", "http.lowSpeedLimit=1024", "-c", "http.lowSpeedTime=120"}

// waitDelay bounds how long a git process's I/O may outlive it after
// its context is done: a killed git can leave a helper
// (git-remote-https) holding the output pipes open, and without a
// WaitDelay, Wait would block on that helper instead of returning.
const waitDelay = 10 * time.Second

// strippedGitEnv lists inherited variables that could redirect a git
// command to a repository, index, or object store other than the one
// cmd.Dir names — for example when Kritolith runs inside a git hook,
// which exports GIT_DIR. cmd.Dir must be the only thing that decides
// which repository git operates on.
var strippedGitEnv = []string{
	"GIT_DIR",
	"GIT_WORK_TREE",
	"GIT_INDEX_FILE",
	"GIT_OBJECT_DIRECTORY",
	"GIT_ALTERNATE_OBJECT_DIRECTORIES",
	"GIT_COMMON_DIR",
	"GIT_NAMESPACE",
}

// gitEnv returns environ with strippedGitEnv removed and hardening
// settings appended: GIT_TERMINAL_PROMPT=0 makes git fail instead of
// prompting on the terminal for credentials (a private or nonexistent
// GitHub repo answers 401, and a prompt would hang the run), and
// GIT_CONFIG_NOSYSTEM=1 keeps the machine-wide gitconfig out of a
// security tool's git calls.
func gitEnv(environ []string) []string {
	env := make([]string, 0, len(environ)+2)
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if slices.Contains(strippedGitEnv, name) || name == "GIT_TERMINAL_PROMPT" || name == "GIT_CONFIG_NOSYSTEM" {
			continue
		}
		env = append(env, kv)
	}
	return append(env, "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1")
}

// gitCommand builds every git subprocess this package runs, so the
// environment hardening and WaitDelay apply uniformly.
func gitCommand(ctx context.Context, dir string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = gitEnv(os.Environ())
	cmd.WaitDelay = waitDelay
	return cmd
}

func (m *Mirror) runGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := gitCommand(ctx, dir, args...)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(errBuf.String()))
	}
	return out.String(), nil
}

// clone creates the mirror. It clones into a temporary sibling
// directory and renames it into place only on success, so a clone that
// is interrupted (timeout, cancellation, a killed process) never leaves
// a half-written directory at m.path for a later run to mistake for a
// usable mirror.
func (m *Mirror) clone(ctx context.Context) error {
	parent := filepath.Dir(m.path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("ground: mkdir: %w", err)
	}
	tmp, err := os.MkdirTemp(parent, filepath.Base(m.path)+".clone-*")
	if err != nil {
		return fmt.Errorf("ground: mkdir: %w", err)
	}
	defer os.RemoveAll(tmp) // no-op once renamed
	ctx, cancel := context.WithTimeout(ctx, networkTimeout)
	defer cancel()
	args := append(slices.Clone(networkStallArgs), "clone", "--mirror", "--", m.origin, tmp)
	if _, err := m.runGit(ctx, "", args...); err != nil {
		return err
	}
	if err := os.Rename(tmp, m.path); err != nil {
		if m.exists() {
			return nil // another run created the mirror first; use it
		}
		return fmt.Errorf("ground: install mirror: %w", err)
	}
	return nil
}

func (m *Mirror) fetch(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, networkTimeout)
	defer cancel()
	_, err := m.runGit(ctx, m.path, append(slices.Clone(networkStallArgs), "fetch", "--prune", "origin")...)
	return err
}

func (m *Mirror) resolve(ctx context.Context, ref string) (string, bool) {
	out, err := m.runGit(ctx, m.path, "rev-parse", "--verify", "--end-of-options", ref+"^{commit}")
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(out), true
}

// EnsureAndResolve resolves ref — the report's claimed ref — to a full
// commit SHA, cloning the mirror on first use. The claimed ref always
// gets the first and best chance to resolve, and only if it can't
// resolve even after the mirror is fresh are fallbackVersions tried:
//
//  1. Resolve ref alone against the local mirror. A hit is trusted
//     immediately only if ref is a full 40-hex SHA (immutable) or the
//     mirror was cloned by this call (already current). A branch or
//     tag name resolved from an older mirror may be stale, so it isn't
//     trusted yet.
//  2. Otherwise, unless the mirror was just cloned, fetch once and
//     resolve ref alone again. A claimed commit newer than the mirror
//     is found here, instead of losing to a fallback version that
//     happened to resolve against the stale mirror.
//  3. Only then try each of fallbackVersions, in order.
//
// viaFallback is true when the commit came from a fallback version
// rather than ref: grounding then checks claims against a commit the
// reporter didn't name exactly, which callers must not treat as strong
// enough to reject a report on. resolved is false, with no error, if
// nothing resolved at all. Every candidate (ref and each fallback) is
// validated with report.ValidateRef before it reaches a git command
// argument; an invalid candidate is skipped, not a hard error.
func (m *Mirror) EnsureAndResolve(ctx context.Context, ref string, fallbackVersions []string) (commit string, resolved, viaFallback bool, err error) {
	freshClone := false
	if !m.exists() {
		if err := m.clone(ctx); err != nil {
			return "", false, false, fmt.Errorf("ground: clone: %w", err)
		}
		freshClone = true
	}
	primary := []string{ref}
	if sha, ok := m.tryResolve(ctx, primary); ok && (freshClone || report.IsFullSHA(ref)) {
		return sha, true, false, nil
	}
	if !freshClone {
		if err := m.fetch(ctx); err != nil {
			return "", false, false, fmt.Errorf("ground: fetch: %w", err)
		}
		if sha, ok := m.tryResolve(ctx, primary); ok {
			return sha, true, false, nil
		}
	}
	if sha, ok := m.tryResolve(ctx, fallbackVersions); ok {
		return sha, true, true, nil
	}
	return "", false, false, nil
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

// FileExists reports whether path exists in the tree at commit. found
// is false with a nil error only when git positively reports the path
// missing from a tree it could read. Every other outcome — an invalid
// path, a commit whose tree can't be read, a cancelled or timed-out
// context, a corrupted mirror, unexpected output — is returned as an
// error, never as "not found": callers use a false result to prove a
// file claim false.
//
// `git cat-file -e` can't be used for this: it exits 128 both for a
// path missing from the tree and for a real failure (a missing commit,
// a corrupt object). `git cat-file --batch-check` instead prints
// "<name> missing" for an absent object and exits 0, and exits
// non-zero only on a real failure. The commit's tree is checked in the
// same call, so a missing commit can't be misread as a missing path.
func (m *Mirror) FileExists(ctx context.Context, commit, path string) (bool, error) {
	if err := ValidateClaimPath(path); err != nil {
		return false, err
	}
	if strings.ContainsAny(path, "\n\r") || strings.ContainsAny(commit, "\n\r") {
		return false, fmt.Errorf("ground: invalid path %q", path)
	}
	treeName := commit + "^{tree}"
	pathName := commit + ":" + path
	cmd := gitCommand(ctx, m.path, "cat-file", "--batch-check")
	cmd.Stdin = strings.NewReader(treeName + "\n" + pathName + "\n")
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("ground: check %s at %s: %w: %s", report.Printable(path), commit, err, strings.TrimSpace(errBuf.String()))
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 2 {
		return false, fmt.Errorf("ground: check %s at %s: unexpected cat-file output", report.Printable(path), commit)
	}
	if f := strings.Fields(lines[0]); len(f) != 3 || f[1] != "tree" {
		return false, fmt.Errorf("ground: check %s at %s: commit tree unreadable", report.Printable(path), commit)
	}
	if lines[1] == pathName+" missing" {
		return false, nil
	}
	if f := strings.Fields(lines[1]); len(f) == 3 {
		return true, nil
	}
	return false, fmt.Errorf("ground: check %s at %s: unexpected cat-file output", report.Printable(path), commit)
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
	cmd := gitCommand(ctx, m.path, "grep", "-q", "-w", "-F", "-e", name, commit, "--")
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
