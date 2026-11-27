package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	// oPath is O_PATH (Linux, every architecture Kritolith builds for):
	// an fd that names a file without opening it, so a directory with no
	// permissions can still be pinned and chmodded.
	oPath = 0x200000
	// atRemoveDir is AT_REMOVEDIR for unlinkat.
	atRemoveDir = 0x200
	// maxForceDepth bounds the walk. Each level holds two fds while its
	// children are removed: the pinned O_PATH fd and the fd the
	// directory is read through. A tree with more levels is left behind
	// below the cap, with an error.
	maxForceDepth = 512
)

// forceRemoveTree removes root fd-relatively. Each directory is pinned
// with openat(O_PATH|O_DIRECTORY|O_NOFOLLOW) relative to its parent's
// fd, so a symlink is never followed; the chmod goes through that
// pinned fd (via /proc/self/fd, since fchmod refuses an O_PATH fd), and
// the directory is read through an fd opened from the pinned one. A
// directory swapped for a link after it was pinned is still the one
// that gets chmodded; the link itself is only ever unlinked.
func forceRemoveTree(root string) error {
	root = filepath.Clean(root)
	parent, name := filepath.Dir(root), filepath.Base(root)
	pfd, err := syscall.Open(parent, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("sandbox: open %s: %w", parent, err)
	}
	defer syscall.Close(pfd)
	return removeAt(pfd, name, root, 0)
}

// removeAt removes the entry name in the directory dirfd; p is its path,
// for errors and the test hook only (never used to reach the entry).
func removeAt(dirfd int, name, p string, depth int) error {
	fd, err := syscall.Openat(dirfd, name, oPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, syscall.ENOENT):
		return nil
	case errors.Is(err, syscall.ENOTDIR), errors.Is(err, syscall.ELOOP):
		// A file or a symlink: unlink the entry itself.
		return unlinkEntry(dirfd, name, p)
	case err != nil:
		return fmt.Errorf("sandbox: open %s: %w", p, err)
	}
	defer syscall.Close(fd)
	if depth >= maxForceDepth {
		return fmt.Errorf("sandbox: remove %s: tree deeper than %d levels", p, maxForceDepth)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fmt.Errorf("sandbox: stat %s: %w", p, err)
	}
	if perm := st.Mode & 0o7777; perm&0o700 != 0o700 {
		beforeForceChmod(p)
		// The magic link resolves to the pinned directory, whatever the
		// name in its parent points at now.
		if err := syscall.Chmod("/proc/self/fd/"+strconv.Itoa(fd), (perm|0o700)&0o777); err != nil {
			return fmt.Errorf("sandbox: chmod %s: %w", p, err)
		}
	}
	rfd, err := syscall.Openat(fd, ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("sandbox: open %s: %w", p, err)
	}
	f := os.NewFile(uintptr(rfd), p)
	names, rerr := f.Readdirnames(-1)
	var errs []error
	if rerr != nil {
		errs = append(errs, fmt.Errorf("sandbox: read %s: %w", p, rerr))
	}
	for _, n := range names {
		if err := removeAt(rfd, n, filepath.Join(p, n), depth+1); err != nil {
			errs = append(errs, err)
		}
	}
	f.Close()
	if err := rmdirAt(dirfd, name); err != nil {
		if errors.Is(err, syscall.ENOTDIR) {
			// Swapped for a non-directory since it was pinned: remove
			// that entry as itself, never through it.
			return errors.Join(append(errs, unlinkEntry(dirfd, name, p))...)
		}
		if !errors.Is(err, syscall.ENOENT) {
			errs = append(errs, fmt.Errorf("sandbox: remove %s: %w", p, err))
		}
	}
	return errors.Join(errs...)
}

func unlinkEntry(dirfd int, name, p string) error {
	if err := syscall.Unlinkat(dirfd, name); err != nil && !errors.Is(err, syscall.ENOENT) {
		if errors.Is(err, syscall.EISDIR) {
			// Swapped for a directory: removed at the next sweep.
			return fmt.Errorf("sandbox: remove %s: changed while being removed", p)
		}
		return fmt.Errorf("sandbox: remove %s: %w", p, err)
	}
	return nil
}

func rmdirAt(dirfd int, name string) error {
	b, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, e := syscall.Syscall(syscall.SYS_UNLINKAT, uintptr(dirfd), uintptr(unsafe.Pointer(b)), atRemoveDir)
	if e != 0 {
		return e
	}
	return nil
}
