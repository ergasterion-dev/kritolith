package sandbox

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// Source is where the Runner gets the code at a commit. *ground.Mirror
// implements it.
type Source interface {
	// Archive extracts the tree of commit into dst, an absolute path to
	// an empty or missing directory, never carrying a symlink that
	// leaves dst.
	Archive(ctx context.Context, commit, dst string) error
	// DefaultBranchRef returns the commit at the tip of the remote's
	// default branch (the HEAD the control runs at).
	DefaultBranchRef(ctx context.Context) (string, error)
}

// pocProgramDir is where a program PoC is built, relative to the
// module root.
const pocProgramDir = "cmd/kritolith-poc"

// Copy limits for copyTree. Vars so tests can lower them.
var (
	maxCopyBytes   int64 = 4 << 30
	maxCopyEntries       = 1 << 20
)

// goModModule returns the module path a go.mod declares, or "" when
// there is none or it is not a plausible module path.
func goModModule(content []byte) string {
	src := strings.TrimPrefix(string(content), "\xef\xbb\xbf")
	for _, line := range strings.Split(src, "\n") {
		toks := goModTokens(line)
		if len(toks) == 2 && toks[0] == "module" && validModulePath(toks[1]) {
			return toks[1]
		}
	}
	return ""
}

// relTo returns dir (tree-relative) relative to root (tree-relative),
// and false when dir is not root or below it.
func relTo(root, dir string) (string, bool) {
	if root == "." {
		return dir, true
	}
	if dir == root {
		return ".", true
	}
	if rest, ok := strings.CutPrefix(dir, root+"/"); ok {
		return rest, true
	}
	return "", false
}

// moduleClaims keeps the verified function and file claims whose
// package directory belongs to the module rooted at modRoot (its
// nearest go.mod is modRoot's), rewritten so paths are relative to the
// module root, which is what TargetsFromClaims, the coverage profile
// and the runtime's symbol names use. A claim in another module of the
// repository (a nested go.mod) is dropped: it is not code this build
// can attribute.
func moduleClaims(tree Tree, modRoot string, claims []report.Claim) []report.Claim {
	roots := map[string]string{}
	rootOf := func(dir string) string {
		if r, ok := roots[dir]; ok {
			return r
		}
		r, err := ModuleRoot(tree, dir)
		if err != nil {
			r = ""
		}
		roots[dir] = r
		return r
	}
	var out []report.Claim
	for _, c := range claims {
		if c.Verified != report.TriYes {
			continue
		}
		var raw string
		switch c.Kind {
		case report.ClaimFunction:
			raw = c.DeclPkgDir
		case report.ClaimFile:
			raw = path.Dir(c.Value)
		default:
			continue
		}
		dir, ok := cleanDir(raw)
		if !ok || rootOf(dir) != modRoot {
			continue
		}
		rel, ok := relTo(modRoot, dir)
		if !ok {
			continue
		}
		switch c.Kind {
		case report.ClaimFunction:
			c.DeclPkgDir = rel
		case report.ClaimFile:
			if path.Clean(c.Value) != c.Value {
				continue
			}
			c.Value = path.Join(rel, path.Base(c.Value))
		}
		out = append(out, c)
	}
	return out
}

// parsedDir is the parsed Go files of one directory.
type parsedDir struct {
	files []parsedFile
}

type parsedFile struct {
	name string // base name
	fset *token.FileSet
	f    *ast.File
}

// parseDir parses the Go files the go tool would consider in dir
// (tree-relative): not hidden, not "_" prefixed, at most
// maxGoFilesPerDir of them. Unparseable files are skipped.
func parseDir(tree Tree, dir string) parsedDir {
	names, err := tree.ReadDir(dir)
	if err != nil {
		return parsedDir{}
	}
	var pd parsedDir
	for _, n := range names {
		if !strings.HasSuffix(n, ".go") || strings.HasPrefix(n, ".") || strings.HasPrefix(n, "_") {
			continue
		}
		if len(pd.files) >= maxGoFilesPerDir {
			break
		}
		src, err := tree.ReadFile(path.Join(dir, n))
		if err != nil {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, n, src, parser.SkipObjectResolution)
		if err != nil || f == nil {
			continue
		}
		pd.files = append(pd.files, parsedFile{name: n, fset: fset, f: f})
	}
	return pd
}

func recvName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	t := fd.Recv.List[0].Type
	for {
		switch x := t.(type) {
		case *ast.StarExpr:
			t = x.X
		case *ast.IndexExpr:
			t = x.X
		case *ast.IndexListExpr:
			t = x.X
		case *ast.ParenExpr:
			t = x.X
		case *ast.Ident:
			return x.Name
		default:
			return ""
		}
	}
}

// claimRanges looks up the declaration of every module-relative
// function claim in its package directory and returns the claims to
// keep and the line ranges of their declarations, keyed by the
// module-relative file. A claim is kept only when it is declared in a
// non-test file: a claim naming a repository test helper (declared
// only in a _test.go file) must never count, and neither must one
// whose declaration cannot be found at this ref. File claims are kept
// as they are (TargetsFromClaims drops _test.go files).
func claimRanges(tree Tree, modRoot string, claims []report.Claim) ([]report.Claim, map[string][]FuncRange) {
	dirs := map[string]parsedDir{}
	ranges := map[string][]FuncRange{}
	seen := map[string]bool{}
	var kept []report.Claim
	for _, c := range claims {
		if c.Kind != report.ClaimFunction {
			kept = append(kept, c)
			continue
		}
		if c.DeclName == "" || c.DeclPkgDir == "" {
			continue
		}
		tdir := path.Join(modRoot, c.DeclPkgDir)
		pd, ok := dirs[tdir]
		if !ok {
			pd = parseDir(tree, tdir)
			dirs[tdir] = pd
		}
		name := c.DeclName
		if c.DeclReceiver != "" {
			name = c.DeclReceiver + "." + c.DeclName
		}
		found := false
		for _, pf := range pd.files {
			if strings.HasSuffix(pf.name, "_test.go") {
				continue
			}
			for _, d := range pf.f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Name.Name != c.DeclName || recvName(fd) != c.DeclReceiver {
					continue
				}
				found = true
				file := path.Join(c.DeclPkgDir, pf.name)
				r := FuncRange{Name: name, Start: pf.fset.Position(fd.Pos()).Line, End: pf.fset.Position(fd.End()).Line}
				key := fmt.Sprintf("%s:%s:%d", file, r.Name, r.Start)
				if !seen[key] {
					seen[key] = true
					ranges[file] = append(ranges[file], r)
				}
			}
		}
		if found {
			kept = append(kept, c)
		}
	}
	for _, rs := range ranges {
		sort.Slice(rs, func(i, j int) bool { return rs[i].Start < rs[j].Start })
	}
	if len(ranges) == 0 {
		ranges = nil
	}
	return kept, ranges
}

// hasFuzzTarget reports whether a _test.go file in dir declares
// func <name>(*testing.F).
func hasFuzzTarget(tree Tree, dir, name string) bool {
	for _, pf := range parseDir(tree, dir).files {
		if !strings.HasSuffix(pf.name, "_test.go") {
			continue
		}
		for _, d := range pf.f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name.Name != name || fd.Type.Params.NumFields() != 1 {
				continue
			}
			if star, ok := fd.Type.Params.List[0].Type.(*ast.StarExpr); ok {
				if sel, ok := star.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "F" {
					return true
				}
			}
		}
	}
	return false
}

// pocPaths returns where the PoC's files go, relative to the tree root
// (tree) and to the module root (mod). dir is the placement directory.
func pocPaths(p PoC, modRoot, dir string) (tree, mod []string) {
	base := dir
	if p.Shape == ShapeProgram {
		base = path.Join(modRoot, pocProgramDir)
	}
	for _, f := range p.Files {
		t := path.Join(base, f.Name)
		tree = append(tree, t)
		if m, ok := relTo(modRoot, t); ok {
			mod = append(mod, m)
		}
	}
	return tree, mod
}

// inside reports whether p is root or below it (both cleaned, absolute).
func inside(root, p string) bool {
	return p == root || strings.HasPrefix(p, root+string(filepath.Separator))
}

// copyTree copies the tree at src into dst (which must not exist),
// keeping regular files (and their executable bit), directories, and
// only those symlinks whose target is relative and resolves inside src
// both lexically and for real. Everything else (devices, sockets,
// FIFOs, escaping or dangling links) is dropped. A symlink in src is
// never followed, so no write in dst goes through one.
func copyTree(src, dst string) error {
	realSrc, err := filepath.EvalSymlinks(src)
	if err != nil {
		return err
	}
	if err := os.Mkdir(dst, 0o700); err != nil {
		return err
	}
	var total int64
	entries := 0
	return filepath.WalkDir(realSrc, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entries++; entries > maxCopyEntries {
			return fmt.Errorf("source tree has more than %d entries (limit)", maxCopyEntries)
		}
		rel, err := filepath.Rel(realSrc, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		out := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.Mkdir(out, 0o755)
		case d.Type().IsRegular():
			fi, err := d.Info()
			if err != nil {
				return err
			}
			if total += fi.Size(); total > maxCopyBytes {
				return fmt.Errorf("source tree is larger than the %d byte limit", maxCopyBytes)
			}
			return copyFile(p, out, fi.Mode())
		case d.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil || target == "" || filepath.IsAbs(target) {
				return nil
			}
			lex := filepath.Join(filepath.Dir(p), target)
			if !inside(realSrc, lex) {
				return nil
			}
			real, err := filepath.EvalSymlinks(p)
			if err != nil || !inside(realSrc, real) {
				return nil
			}
			return os.Symlink(target, out)
		}
		return nil // device, socket, FIFO: dropped
	})
}

func copyFile(from, to string, mode fs.FileMode) error {
	in, err := os.OpenFile(from, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	perm := fs.FileMode(0o644)
	if mode&0o100 != 0 {
		perm = 0o755
	}
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// mkdirNoLinks creates the tree-relative directory rel under root (an
// absolute host path), refusing any existing component that is a
// symlink or not a directory.
func mkdirNoLinks(root, rel string) (string, error) {
	cur := root
	if rel == "." {
		return cur, nil
	}
	for _, e := range strings.Split(rel, "/") {
		cur = filepath.Join(cur, e)
		fi, err := os.Lstat(cur)
		switch {
		case errors.Is(err, os.ErrNotExist):
			if err := os.Mkdir(cur, 0o755); err != nil {
				return "", err
			}
		case err != nil:
			return "", err
		case fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir():
			return "", &Inconclusive{Reason: "the PoC directory is reached through a symlink or a file in the repository"}
		}
	}
	return cur, nil
}

// writePoC copies the PoC files into the build copy at root (absolute
// host path) at the tree-relative paths pocPaths gives. A PoC file
// that would replace a repository file is refused (*NeedsInfo: the
// reporter can rename it); a program PoC needs cmd/kritolith-poc to be
// absent from the module (*Inconclusive otherwise).
func writePoC(root string, p PoC, modRoot, dir string) error {
	if p.Shape == ShapeProgram {
		progDir := path.Join(modRoot, pocProgramDir)
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(progDir))); !errors.Is(err, os.ErrNotExist) {
			return &Inconclusive{Reason: "the repository already has a " + pocProgramDir + " directory, where a program PoC is built"}
		}
	}
	paths, _ := pocPaths(p, modRoot, dir)
	for i, f := range p.Files {
		rel := paths[i]
		d, err := mkdirNoLinks(root, path.Dir(rel))
		if err != nil {
			return err
		}
		out, err := os.OpenFile(filepath.Join(d, path.Base(rel)), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
		if errors.Is(err, os.ErrExist) {
			return needs("PoC file %s has the name of a file already in the repository; rename it", quote(f.Name))
		}
		if err != nil {
			return err
		}
		if _, err := out.Write(f.Content); err != nil {
			out.Close()
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
	}
	return nil
}

// readBounded reads a regular file the container may have written,
// never following a symlink, keeping at most limit bytes.
func readBounded(p string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", filepath.Base(p))
	}
	return io.ReadAll(io.LimitReader(f, limit))
}

// chownTree hands every entry under root to uid:gid without following
// symlinks. Used only when the host process runs as root, so the
// unprivileged container user can use its scratch directories.
func chownTree(root string, uid, gid int) error {
	return filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	})
}
