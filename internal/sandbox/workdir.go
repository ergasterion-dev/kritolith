package sandbox

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
)

// workDirMarker, directly in the work dir, says that Kritolith owns the
// directory. It is created (0600) only in a directory that is new or
// empty, and the sweep and the driver refuse a non-empty work dir
// without it: the sweep deletes by name, so it must never run in a
// shared directory such as /var/lib.
const workDirMarker = ".kritolith-workdir"

const workDirMarkerText = "This directory is a Kritolith sandbox work dir. Kritolith deletes what it finds here.\n"

// orphanNameRe is the exact shape of the names Kritolith creates in the
// work dir: os.MkdirTemp(dir, "kritolith-*") for a bundle (also the
// container id) and os.MkdirTemp(dir, "kritolith-run-*") for a scratch
// tree. MkdirTemp replaces "*" with a decimal random number.
var orphanNameRe = regexp.MustCompile(`^` + orphanPrefix + `(run-)?[0-9]+$`)

func isOrphanName(n string) bool { return orphanNameRe.MatchString(n) }

// checkAncestors refuses a work dir whose existing ancestors could let
// someone else swap it: an ancestor that is a symlink, is owned by a
// user other than root or this user, or is group or world writable
// without the sticky bit (/tmp's 1777 is fine). Ancestors that do not
// exist yet are skipped; call it again once they are created.
func checkAncestors(workDir string) error {
	uid := os.Geteuid()
	for p := filepath.Dir(workDir); ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return fmt.Errorf("sandbox: work dir ancestor: %w", err)
		case fi.Mode()&os.ModeSymlink != 0:
			return fmt.Errorf("sandbox: work dir ancestor %s is a symlink; use the resolved path", p)
		case !fi.IsDir():
			return fmt.Errorf("sandbox: work dir ancestor %s is not a directory", p)
		default:
			st, ok := fi.Sys().(*syscall.Stat_t)
			if !ok || (int(st.Uid) != 0 && int(st.Uid) != uid) {
				return fmt.Errorf("sandbox: work dir ancestor %s is owned by another user", p)
			}
			if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
				return fmt.Errorf("sandbox: work dir ancestor %s is group or world writable (%v)", p, fi.Mode().Perm())
			}
		}
		if p == "/" {
			return nil
		}
	}
}

// markerState says whether workDir carries a valid marker (ok), or is
// empty and so may be claimed (empty). Any other state is an error.
func markerState(workDir string) (ok, empty bool, err error) {
	p := filepath.Join(workDir, workDirMarker)
	fi, err := os.Lstat(p)
	if err == nil {
		st, sok := fi.Sys().(*syscall.Stat_t)
		switch {
		case !fi.Mode().IsRegular():
			return false, false, fmt.Errorf("sandbox: work dir marker %s is not a regular file", p)
		case !sok || int(st.Uid) != os.Geteuid():
			return false, false, fmt.Errorf("sandbox: work dir marker %s is not owned by this user", p)
		case fi.Mode().Perm()&0o077 != 0:
			return false, false, fmt.Errorf("sandbox: work dir marker %s is accessible to other users (%v)", p, fi.Mode().Perm())
		}
		return true, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return false, false, fmt.Errorf("sandbox: work dir marker: %w", err)
	}
	d, err := os.Open(workDir)
	if err != nil {
		return false, false, fmt.Errorf("sandbox: %w", err)
	}
	defer d.Close()
	if _, err := d.Readdirnames(1); errors.Is(err, io.EOF) {
		return false, true, nil
	} else if err != nil {
		return false, false, fmt.Errorf("sandbox: read %s: %w", workDir, err)
	}
	return false, false, notDedicated(workDir)
}

func notDedicated(workDir string) error {
	return fmt.Errorf("sandbox: work dir %s is not a dedicated Kritolith work dir (no %s marker, and not empty); "+
		"point sandbox.work_dir at a new or empty directory used for nothing else", workDir, workDirMarker)
}

// claimWorkDir makes sure workDir (an existing, private directory)
// carries the marker: it accepts a valid one, creates one in an empty
// directory, and refuses anything else.
func claimWorkDir(workDir string) error {
	ok, empty, err := markerState(workDir)
	if err != nil || ok {
		return err
	}
	if !empty {
		return notDedicated(workDir)
	}
	p := filepath.Join(workDir, workDirMarker)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if errors.Is(err, os.ErrExist) {
		// Claimed concurrently: validate what is there.
		_, _, err = markerState(workDir)
		return err
	}
	if err != nil {
		return fmt.Errorf("sandbox: create work dir marker: %w", err)
	}
	if _, err := f.WriteString(workDirMarkerText); err != nil {
		f.Close()
		return fmt.Errorf("sandbox: write work dir marker: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("sandbox: write work dir marker: %w", err)
	}
	return nil
}

// checkWorkDirOverlap refuses a rootfs or forbidden path that is, lies
// inside, or contains the work dir, both as written and with symlinks
// resolved: the sweep deletes under the work dir, and a container must
// never be able to reach a forbidden path through a scratch mount.
func checkWorkDirOverlap(workDir, rootfs string, forbidden []string) error {
	w := []string{filepath.Clean(workDir)}
	if r := evalBestEffort(workDir); r != "" {
		w = append(w, r)
	}
	check := func(name, p string) error {
		if p == "" || !filepath.IsAbs(p) {
			return nil
		}
		ps := []string{filepath.Clean(p)}
		if r := evalBestEffort(p); r != "" {
			ps = append(ps, r)
		}
		for _, a := range ps {
			for _, b := range w {
				if under(a, b) || under(b, a) {
					return fmt.Errorf("sandbox: the %s %s overlaps the work dir %s; the work dir must be a separate directory", name, p, workDir)
				}
			}
		}
		return nil
	}
	if err := check("rootfs", rootfs); err != nil {
		return err
	}
	for _, f := range forbidden {
		if err := check("forbidden path", f); err != nil {
			return err
		}
	}
	return nil
}
