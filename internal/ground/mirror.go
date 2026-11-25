package ground

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
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
// argument; an invalid candidate is skipped, not a hard error. A
// candidate that names a commit on no branch and no tag (see
// onBranchOrTag) is skipped the same way.
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
		if sha, ok := m.resolve(ctx, cand); ok && m.onBranchOrTag(ctx, sha) {
			return sha, true
		}
	}
	return "", false
}

// onBranchOrTag reports whether commit is reachable from a branch or a
// tag of the repository. A mirror holds more than that: GitHub
// publishes every pull request's head as refs/pull/N/head, and anyone
// can open a pull request, so a reporter can put an invented function
// in one and cite that commit. A commit only a pull request (or no ref
// at all) leads to is not the project's code, and a claim that checks
// out against it proves nothing.
//
// A git failure reads as "not reachable": the ref then counts as
// unresolved, which can only produce NEEDS_INFO, never a rejection.
func (m *Mirror) onBranchOrTag(ctx context.Context, commit string) bool {
	out, err := m.runGit(ctx, m.path, "for-each-ref", "--count=1", "--format=%(refname)",
		"--contains", commit, "refs/heads", "refs/tags")
	return err == nil && strings.TrimSpace(out) != ""
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

// ReadFiles reads many blobs at commit with a single
// `git cat-file --batch` process, and calls fn once per path, in the
// order given. ok is false wherever ReadFile's would be: the path is
// invalid or missing, or the blob is larger than maxReadBytes. It is
// also false for anything that isn't a blob (a directory, a
// submodule). An oversized blob is discarded as it streams, never
// buffered.
//
// Indexing a repository reads every Go file in it. Doing that through
// ReadFile costs two git processes per file, which dominates the run
// time on a repository with hundreds of files.
//
// A non-nil error means git failed or answered with something
// unexpected partway through; fn was not called for the paths after
// that point, so the caller must treat its view as incomplete.
func (m *Mirror) ReadFiles(ctx context.Context, commit string, paths []string, fn func(path string, content []byte, ok bool)) error {
	if len(paths) == 0 {
		return nil
	}
	commitOK := !strings.ContainsAny(commit, "\n\r")
	askable := make([]bool, len(paths))
	var stdin bytes.Buffer
	for i, p := range paths {
		// cat-file reads one object name per line, so a path with a
		// line break can't be asked about. ListGoFiles can return one:
		// git allows it in a file name.
		if !commitOK || ValidateClaimPath(p) != nil || strings.ContainsAny(p, "\n\r") {
			continue
		}
		askable[i] = true
		stdin.WriteString(commit + ":" + p + "\n")
	}
	if stdin.Len() == 0 {
		for _, p := range paths {
			fn(p, nil, false)
		}
		return nil
	}

	cmd := gitCommand(ctx, m.path, "cat-file", "--batch")
	cmd.Stdin = &stdin
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("ground: read files at %s: %w", commit, err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("ground: read files at %s: %w", commit, err)
	}
	readErr := readBatch(bufio.NewReaderSize(stdout, 64<<10), paths, askable, fn)
	if readErr != nil {
		// Stop git instead of waiting for it to finish writing output
		// nobody will read.
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if readErr != nil {
		return fmt.Errorf("ground: read files at %s: %w", commit, readErr)
	}
	if waitErr != nil {
		return fmt.Errorf("ground: read files at %s: %w: %s", commit, waitErr, strings.TrimSpace(errBuf.String()))
	}
	return nil
}

// readBatch parses `git cat-file --batch` output for the askable
// paths: a "<object id> <type> <size>" line followed by size bytes
// and a newline, or "<name> missing".
func readBatch(r *bufio.Reader, paths []string, askable []bool, fn func(path string, content []byte, ok bool)) error {
	for i, p := range paths {
		if !askable[i] {
			fn(p, nil, false)
			continue
		}
		header, err := r.ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading the answer for %s: %w", report.Printable(p), err)
		}
		header = strings.TrimSuffix(header, "\n")
		f := strings.Fields(header)
		if len(f) != 3 || !isObjectID(f[0]) {
			if strings.HasSuffix(header, " missing") {
				fn(p, nil, false)
				continue
			}
			return fmt.Errorf("unexpected cat-file answer for %s", report.Printable(p))
		}
		size, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil || size < 0 {
			return fmt.Errorf("unexpected object size for %s", report.Printable(p))
		}
		if f[1] != "blob" || size > maxReadBytes {
			// The content and its trailing newline still have to be
			// consumed to reach the next header.
			if _, err := io.CopyN(io.Discard, r, size+1); err != nil {
				return fmt.Errorf("skipping %s: %w", report.Printable(p), err)
			}
			fn(p, nil, false)
			continue
		}
		content := make([]byte, size)
		if _, err := io.ReadFull(r, content); err != nil {
			return fmt.Errorf("reading %s: %w", report.Printable(p), err)
		}
		if _, err := r.Discard(1); err != nil {
			return fmt.Errorf("reading %s: %w", report.Printable(p), err)
		}
		fn(p, content, true)
	}
	return nil
}

// isObjectID reports whether s is a full SHA-1 or SHA-256 object name.
func isObjectID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
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

// Archive limits. They bound what a hostile repository can make
// Archive write to disk. They are vars so tests can lower them.
var (
	// maxArchiveBytes bounds the total size of the files extracted.
	maxArchiveBytes int64 = 4 << 30
	// maxArchiveEntries bounds the number of tar entries read.
	maxArchiveEntries = 1 << 20
)

// archiveAttributes is written to the mirror's info/attributes, which
// takes precedence over every in-tree .gitattributes: without it a
// repository could hide files (export-ignore), rewrite their content
// (export-subst, ident, text/eol/crlf conversion,
// working-tree-encoding) or name a filter driver (filter) in the
// extracted tree, so the tree the sandbox builds would not be the code
// at the commit. git archive always reads the archived tree's
// .gitattributes (--worktree-attributes only adds the working tree's,
// and a bare mirror has none), so the attributes are unset here rather
// than turned off.
const archiveAttributes = "* -export-ignore -export-subst -filter -ident -text -crlf -eol -working-tree-encoding\n"

// archiveEnv is the whole environment of git archive: no host
// variable (tokens, LLM keys, HOME) reaches it, the global and system
// config and the user attributes file are not read (so a host
// `git lfs install`, core.autocrlf or a filter driver does not apply),
// and PATH is the host's so git finds its own helpers.
func archiveEnv() []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_ATTR_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"HOME=/nonexistent",
		"LC_ALL=C",
	}
}

// archiveArgs pins, on the command line, the settings that would
// otherwise come from the mirror's own config.
var archiveArgs = []string{"-c", "core.attributesFile=/dev/null", "-c", "core.autocrlf=false", "-c", "core.eol=lf"}

// Archive extracts the tree of commit (a full object id the mirror
// holds) into dst, which must be an absolute path to an empty directory
// or a missing one (created 0700). It runs `git archive` and reads the
// tar stream itself instead of piping it to tar(1), so every entry is
// checked before it is written: names must stay inside dst; hard
// links, devices and FIFOs are refused; the total size and entry count
// are bounded. Symlinks are created last, and any whose target is
// absolute, leaves dst, or does not resolve inside dst (also through
// other links) is dropped. On error dst may hold a partial tree; the
// caller removes it.
func (m *Mirror) Archive(ctx context.Context, commit, dst string) (err error) {
	if !isObjectID(commit) {
		return fmt.Errorf("ground: archive: %s is not a full commit id", report.Printable(commit))
	}
	if !filepath.IsAbs(dst) {
		return fmt.Errorf("ground: archive: destination %s is not absolute", report.Printable(dst))
	}
	if sha, ok := m.resolve(ctx, commit); !ok || sha != commit {
		return fmt.Errorf("ground: archive: commit %s is not in the mirror", commit)
	}
	if err := makeEmptyPrivateDir(dst); err != nil {
		return fmt.Errorf("ground: archive: %w", err)
	}
	if err := m.pinArchiveAttributes(); err != nil {
		return fmt.Errorf("ground: archive: %w", err)
	}
	cmd := gitCommand(ctx, m.path, append(append([]string(nil), archiveArgs...), "archive", "--format=tar", commit)...)
	cmd.Env = archiveEnv()
	stderr := &headBuffer{limit: 4096}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("ground: archive: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("ground: archive: %w", err)
	}
	// Tar framing adds at most a header and padding (1 KiB) per entry.
	raw := io.LimitReader(stdout, maxArchiveBytes+int64(maxArchiveEntries)*1024+1<<20)
	exErr := extractTar(raw, dst)
	if exErr != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if exErr != nil {
		return fmt.Errorf("ground: archive %s: %w", commit, exErr)
	}
	if waitErr != nil {
		return fmt.Errorf("ground: archive %s: %w: %s", commit, waitErr, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// headBuffer keeps the first limit bytes written to it.
type headBuffer struct {
	limit int
	buf   bytes.Buffer
}

func (h *headBuffer) Write(p []byte) (int, error) {
	if room := h.limit - h.buf.Len(); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		h.buf.Write(p[:room])
	}
	return len(p), nil
}

func (h *headBuffer) String() string { return h.buf.String() }

// pinArchiveAttributes makes sure info/attributes neutralises in-tree
// export attributes. It writes through a rename so a concurrent
// Archive never sees a partial file.
func (m *Mirror) pinArchiveAttributes() error {
	info := filepath.Join(m.path, "info")
	p := filepath.Join(info, "attributes")
	if b, err := os.ReadFile(p); err == nil && string(b) == archiveAttributes {
		return nil
	}
	if err := os.MkdirAll(info, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(info, "attributes.tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // no-op once renamed
	if _, err := f.WriteString(archiveAttributes); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), p)
}

// makeEmptyPrivateDir creates dst 0700, or accepts an existing empty
// directory (not a symlink) and sets it to 0700.
func makeEmptyPrivateDir(dst string) error {
	fi, err := os.Lstat(dst)
	if errors.Is(err, os.ErrNotExist) {
		return os.Mkdir(dst, 0o700)
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("destination %s is not a directory", report.Printable(dst))
	}
	ents, err := os.ReadDir(dst)
	if err != nil {
		return err
	}
	if len(ents) != 0 {
		return fmt.Errorf("destination %s is not empty", report.Printable(dst))
	}
	return os.Chmod(dst, 0o700)
}

// archiveEntryPath validates a tar entry name: relative, clean once a
// trailing slash is removed, no "." or ".." element, no NUL.
func archiveEntryPath(name string) (string, bool) {
	name = strings.TrimSuffix(name, "/")
	if name == "" || strings.HasPrefix(name, "/") || strings.ContainsRune(name, 0) {
		return "", false
	}
	for _, e := range strings.Split(name, "/") {
		if e == "" || e == "." || e == ".." {
			return "", false
		}
	}
	return name, true
}

type archiveLink struct{ name, target string }

// extractTar writes the entries of a git archive tar stream under root.
// No symlink exists under root until every file and directory has been
// written, so no write can be redirected through one.
func extractTar(r io.Reader, root string) error {
	tr := tar.NewReader(r)
	var total int64
	var links []archiveLink
	for entries := 0; ; entries++ {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar stream: %w", err)
		}
		if entries >= maxArchiveEntries {
			return fmt.Errorf("archive has more than %d entries (limit)", maxArchiveEntries)
		}
		if hdr.Typeflag == tar.TypeXGlobalHeader {
			continue // git's commit id comment
		}
		name, ok := archiveEntryPath(hdr.Name)
		if !ok {
			return fmt.Errorf("refusing archive entry %s", report.Printable(hdr.Name))
		}
		full := filepath.Join(root, filepath.FromSlash(name))
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(full, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if hdr.Size < 0 {
				return fmt.Errorf("archive entry %s has a negative size", report.Printable(name))
			}
			if total += hdr.Size; total > maxArchiveBytes {
				return fmt.Errorf("archive is larger than the %d byte limit", maxArchiveBytes)
			}
			if err := writeArchiveFile(full, hdr, tr); err != nil {
				return err
			}
		case tar.TypeSymlink:
			links = append(links, archiveLink{name: name, target: hdr.Linkname})
		default:
			return fmt.Errorf("refusing archive entry %s of type %q", report.Printable(name), hdr.Typeflag)
		}
	}
	return placeLinks(root, links)
}

func writeArchiveFile(full string, hdr *tar.Header, r io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if hdr.Mode&0o100 != 0 {
		mode = 0o755
	}
	f, err := os.OpenFile(full, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, io.LimitReader(r, hdr.Size)); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// placeLinks creates the symlinks whose target is relative and stays
// inside root lexically, then removes, until none is left, every link
// that does not really resolve inside root: a chain of links that each
// look inside ("l -> ..", "x -> l/..") can still leave the tree.
func placeLinks(root string, links []archiveLink) error {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	var made []string
	for _, l := range links {
		if l.target == "" || strings.HasPrefix(l.target, "/") || strings.ContainsRune(l.target, 0) {
			continue
		}
		joined := path.Join(path.Dir(l.name), l.target)
		if joined == ".." || strings.HasPrefix(joined, "../") {
			continue
		}
		full := filepath.Join(root, filepath.FromSlash(l.name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.Symlink(l.target, full); err != nil {
			return err
		}
		made = append(made, full)
	}
	for changed := true; changed; {
		changed = false
		kept := made[:0]
		for _, full := range made {
			real, err := filepath.EvalSymlinks(full)
			if err != nil || (real != realRoot && !strings.HasPrefix(real, realRoot+string(filepath.Separator))) {
				if err := os.Remove(full); err != nil {
					return err
				}
				changed = true
				continue
			}
			kept = append(kept, full)
		}
		made = kept
	}
	return nil
}

// DefaultBranchRef returns the commit at the tip of the remote's
// default branch, asked of the remote with `git ls-remote --symref
// origin HEAD`. The mirror's own HEAD symref is never used: fetch
// --prune does not refresh it, so after the remote renames its default
// branch it is stale. If the mirror lacks the commit it is fetched once;
// the commit must then be on a branch or tag of the mirror.
func (m *Mirror) DefaultBranchRef(ctx context.Context) (string, error) {
	if !m.exists() {
		return "", fmt.Errorf("ground: default branch: the mirror has not been cloned")
	}
	nctx, cancel := context.WithTimeout(ctx, networkTimeout)
	defer cancel()
	out, err := m.runGit(nctx, m.path, append(slices.Clone(networkStallArgs), "ls-remote", "--symref", "origin", "HEAD")...)
	if err != nil {
		return "", fmt.Errorf("ground: default branch: %w", err)
	}
	sha, err := parseLsRemoteHead(out)
	if err != nil {
		return "", fmt.Errorf("ground: default branch: %w", err)
	}
	if got, ok := m.resolve(ctx, sha); !ok || got != sha {
		if err := m.fetch(ctx); err != nil {
			return "", fmt.Errorf("ground: default branch: fetch: %w", err)
		}
		if got, ok := m.resolve(ctx, sha); !ok || got != sha {
			return "", fmt.Errorf("ground: default branch: commit %s is not in the mirror after a fetch", sha)
		}
	}
	if !m.onBranchOrTag(ctx, sha) {
		return "", fmt.Errorf("ground: default branch: commit %s is on no branch or tag of the mirror", sha)
	}
	return sha, nil
}

// parseLsRemoteHead reads `ls-remote --symref origin HEAD` output:
// an optional "ref: refs/heads/<name>\tHEAD" line and a
// "<object id>\tHEAD" line. A symref, if present, must name a branch.
func parseLsRemoteHead(out string) (string, error) {
	sha := ""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSuffix(line, "\r")
		left, ref, ok := strings.Cut(line, "\t")
		if !ok || ref != "HEAD" {
			continue
		}
		if target, isSym := strings.CutPrefix(left, "ref: "); isSym {
			if !strings.HasPrefix(target, "refs/heads/") {
				return "", fmt.Errorf("remote HEAD points at %s, not a branch", report.Printable(target))
			}
			continue
		}
		if !isObjectID(left) {
			return "", fmt.Errorf("unexpected ls-remote output")
		}
		if sha != "" && sha != left {
			return "", fmt.Errorf("remote reports more than one HEAD")
		}
		sha = left
	}
	if sha == "" {
		return "", fmt.Errorf("the remote has no HEAD")
	}
	return sha, nil
}
