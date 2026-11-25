package sandbox

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// maxTreeFileBytes bounds a single ReadFile so a hostile repository
// cannot exhaust memory through the tree reader.
const maxTreeFileBytes = 8 << 20

type dirTree struct{ root string } // root is absolute with symlinks resolved

// DirTree returns a Tree backed by a directory on disk. It never
// follows a symlink that leaves root: such entries are not listed and
// cannot be read. Paths are checked after resolving symlinks, so a
// link whose target is inside root is fine.
func DirTree(root string) Tree {
	abs, err := filepath.Abs(root)
	if err == nil {
		if r, err2 := filepath.EvalSymlinks(abs); err2 == nil {
			abs = r
		}
	}
	return &dirTree{root: abs}
}

func (t *dirTree) inside(p string) bool {
	return p == t.root || strings.HasPrefix(p, t.root+string(filepath.Separator))
}

// resolve maps a tree-relative slash path to a real path inside root.
func (t *dirTree) resolve(rel string) (string, error) {
	d, ok := cleanDir(rel)
	if !ok {
		return "", fmt.Errorf("path %s is not inside the tree", quote(rel))
	}
	real, err := filepath.EvalSymlinks(filepath.Join(t.root, filepath.FromSlash(d)))
	if err != nil {
		return "", err
	}
	if !t.inside(real) {
		return "", fmt.Errorf("path %s resolves outside the tree", quote(rel))
	}
	return real, nil
}

func (t *dirTree) ReadDir(rel string) ([]string, error) {
	real, err := t.resolve(rel)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(real)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if checkComponent(name) != nil {
			continue
		}
		target, err := filepath.EvalSymlinks(filepath.Join(real, name))
		if err != nil || !t.inside(target) {
			continue // dangling or escaping link
		}
		fi, err := os.Stat(target)
		if err != nil {
			continue
		}
		switch {
		case fi.IsDir():
			out = append(out, name+"/")
		case fi.Mode().IsRegular():
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (t *dirTree) ReadFile(rel string) ([]byte, error) {
	real, err := t.resolve(rel)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(real)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", quote(rel))
	}
	b, err := io.ReadAll(io.LimitReader(f, maxTreeFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxTreeFileBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", quote(rel), maxTreeFileBytes)
	}
	return b, nil
}
