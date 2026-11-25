package sandbox

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// umountNoFollow is UMOUNT_NOFOLLOW: never unmount through a symlink.
const umountNoFollow = 0x8

// hostTmpfs mounts the run phase's /out cap on the host. It needs
// CAP_SYS_ADMIN, which the sandbox already needs (Kritolith runs as
// root so runsc can create the sandbox).
type hostTmpfs struct{}

func newHostOutFS() outMounter { return hostTmpfs{} }

// Mount pins dir with O_PATH|O_NOFOLLOW|O_DIRECTORY and mounts on the
// pinned fd, so a directory swapped for a symlink is never mounted
// over the link's target.
func (hostTmpfs) Mount(dir string, size int64, inodes, uid, gid int) (func() error, error) {
	fd, err := syscall.Open(dir, oPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", runOutDirName, err)
	}
	defer syscall.Close(fd)
	opts := fmt.Sprintf("size=%d,nr_inodes=%d,mode=0700,uid=%d,gid=%d", size, inodes, uid, gid)
	if err := syscall.Mount("kritolith-out", "/proc/self/fd/"+strconv.Itoa(fd), "tmpfs",
		syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, opts); err != nil {
		return nil, fmt.Errorf("mount a %d byte tmpfs: %w", size, err)
	}
	return func() error { return unmountDetach(dir) }, nil
}

// unmountDetach lazily unmounts p without following a symlink; a path
// that is not a mount point is not an error.
func unmountDetach(p string) error {
	if err := syscall.Unmount(p, syscall.MNT_DETACH|umountNoFollow); err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("unmount %s: %w", runOutDirName, err)
	}
	return nil
}

// unmountRunOuts unmounts every run-phase /out cap a crashed run left
// in workDir: mount points <workDir>/kritolith-run-<digits>/runout.
func unmountRunOuts(workDir string) error {
	mps, err := mountPointsUnder(workDir)
	if err != nil {
		return err
	}
	var errs []error
	for _, mp := range mps {
		if filepath.Base(mp) != runOutDirName || filepath.Dir(filepath.Dir(mp)) != workDir || !isOrphanName(filepath.Base(filepath.Dir(mp))) {
			continue
		}
		if err := unmountDetach(mp); err != nil {
			errs = append(errs, fmt.Errorf("sandbox: sweep: %w", err))
		}
	}
	return errors.Join(errs...)
}

// mountPointsUnder lists the mount points strictly under dir, from
// /proc/self/mountinfo.
func mountPointsUnder(dir string) ([]string, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, fmt.Errorf("sandbox: read mounts: %w", err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	prefix := strings.TrimSuffix(dir, "/") + "/"
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		if mp := unescapeMountinfo(fields[4]); strings.HasPrefix(mp, prefix) {
			out = append(out, mp)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("sandbox: read mounts: %w", err)
	}
	return out, nil
}

// unescapeMountinfo undoes the kernel's octal escapes (\040 for space,
// \011, \012, \134) in a mountinfo path.
func unescapeMountinfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
