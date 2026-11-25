//go:build !linux

package sandbox

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
)

// forceRemoveTree is the portable fallback (development hosts only:
// the sandbox runs on Linux). Every step goes through an os.Root opened
// on root's parent, which never resolves a symlink to outside that
// directory, so a directory swapped for a link to a host path makes the
// chmod fail instead of reaching the host path.
func forceRemoveTree(root string) error {
	root = filepath.Clean(root)
	r, err := os.OpenRoot(filepath.Dir(root))
	if err != nil {
		return fmt.Errorf("sandbox: open %s: %w", filepath.Dir(root), err)
	}
	defer r.Close()
	var walk func(rel string) error
	walk = func(rel string) error {
		fi, err := r.Lstat(rel)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return r.Remove(rel)
		}
		if perm := fi.Mode().Perm(); perm&0o700 != 0o700 {
			beforeForceChmod(filepath.Join(filepath.Dir(root), filepath.FromSlash(rel)))
			if fi2, err := r.Lstat(rel); err != nil || !fi2.IsDir() {
				return r.Remove(rel)
			}
			if err := r.Chmod(rel, perm|0o700); err != nil {
				return fmt.Errorf("sandbox: chmod %s: %w", rel, err)
			}
		}
		f, err := r.Open(rel)
		if err != nil {
			return err
		}
		names, rerr := f.Readdirnames(-1)
		f.Close()
		errs := []error{rerr}
		for _, n := range names {
			errs = append(errs, walk(path.Join(rel, n)))
		}
		errs = append(errs, r.Remove(rel))
		return errors.Join(errs...)
	}
	return walk(filepath.Base(root))
}
