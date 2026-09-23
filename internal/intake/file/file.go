// Package file turns a report file on disk (plus optional PoC directory)
// into a report.Report. Both are treated as hostile input.
package file

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

const (
	MaxReportBytes = 1 << 20 // 1 MiB report text
	MaxPoCFiles    = 64
	MaxPoCBytes    = 8 << 20 // 8 MiB across all PoC files
	maxTitleRunes  = 200
)

// Options describes one file-based report.
type Options struct {
	Repo       string // owner/name, required
	Ref        string // commit SHA or tag; empty means the reporter gave none
	ReportPath string // report text (markdown or plain)
	PoCDir     string // optional directory of PoC files
	Now        func() time.Time
	Rand       io.Reader
}

// Load reads and validates a report and its PoC files.
func Load(opts Options) (report.Report, error) {
	if err := report.ValidateRepo(opts.Repo); err != nil {
		return report.Report{}, fmt.Errorf("intake/file: %w", err)
	}
	if opts.Ref != "" {
		if err := report.ValidateRef(opts.Ref); err != nil {
			return report.Report{}, fmt.Errorf("intake/file: %w", err)
		}
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	rnd := io.Reader(rand.Reader)
	if opts.Rand != nil {
		rnd = opts.Rand
	}

	abs, err := filepath.Abs(opts.ReportPath)
	if err != nil {
		return report.Report{}, fmt.Errorf("intake/file: %w", err)
	}
	// The report path comes from the operator, so symlinks are followed.
	data, err := readRegular(abs, MaxReportBytes, true)
	if err != nil {
		return report.Report{}, fmt.Errorf("intake/file: report: %w", err)
	}
	body := strings.ToValidUTF8(string(data), "�")

	var poc []report.Artifact
	if opts.PoCDir != "" {
		if poc, err = loadPoC(opts.PoCDir); err != nil {
			return report.Report{}, fmt.Errorf("intake/file: poc: %w", err)
		}
	}

	received := now().UTC()
	id, err := report.NewID(received, rnd)
	if err != nil {
		return report.Report{}, fmt.Errorf("intake/file: %w", err)
	}
	return report.Report{
		ID:         id,
		Source:     report.SourceFile,
		SourceRef:  abs,
		Repo:       opts.Repo,
		ClaimedRef: opts.Ref,
		Title:      title(body),
		Body:       body,
		PoC:        poc,
		ReceivedAt: received,
	}, nil
}

// title is the first non-empty line with leading '#' marks removed,
// made printable and cut to maxTitleRunes.
func title(body string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(line), "#"))
		if line == "" {
			continue
		}
		r := []rune(report.Printable(line))
		if len(r) > maxTitleRunes {
			r = r[:maxTitleRunes]
		}
		return string(r)
	}
	return ""
}

// readRegular reads at most limit bytes from a regular file at path. It
// opens non-blocking so a FIFO can't hang intake, and with O_NOFOLLOW
// unless followSymlinks is set. Used for the report path, which is
// operator-supplied and may itself be a symlink.
func readRegular(path string, limit int64, followSymlinks bool) ([]byte, error) {
	flags := os.O_RDONLY | syscall.O_NONBLOCK
	if !followSymlinks {
		flags |= syscall.O_NOFOLLOW
	}
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s is a symlink; symlinks are rejected", path)
		}
		return nil, err
	}
	defer f.Close()
	return readOpened(f, path, limit)
}

// readOpened reads at most limit bytes from an already-open file,
// rejecting anything that isn't a regular file (catches a FIFO/device/
// socket swapped in after the open) and anything over limit. name is
// used only for error messages.
func readOpened(f *os.File, name string, limit int64) ([]byte, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	if st.Size() > limit {
		return nil, fmt.Errorf("%s is %d bytes; limit is %d", name, st.Size(), limit)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s grew past the %d byte limit while reading", name, limit)
	}
	return data, nil
}

// loadPoC reads every regular file under dir. Symlinks, devices, FIFOs
// and sockets anywhere in the tree are rejected rather than skipped, so
// a hostile PoC can't point Kritolith at files outside the directory.
//
// Files are opened through an os.Root scoped to dir rather than by
// concatenated path. filepath.WalkDir's own lstat only proves what a
// path component was at walk time; if an already-walked directory is
// swapped for a symlink to outside the tree before the file under it is
// opened, a plain os.OpenFile on the concatenated path would follow it
// out. os.Root re-resolves every path component beneath the root's file
// descriptor at open time and refuses any symlink that would leave the
// root, closing that race by construction.
func loadPoC(dir string) ([]report.Artifact, error) {
	root, err := filepath.EvalSymlinks(dir) // the root itself comes from the operator
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}

	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	var (
		arts  []report.Artifact
		total int64
	)
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			return fmt.Errorf("%q is a symlink; symlinks are rejected", rel)
		case d.IsDir():
			return nil
		case !d.Type().IsRegular():
			return fmt.Errorf("%q is not a regular file", rel)
		}
		if len(arts) == MaxPoCFiles {
			return fmt.Errorf("too many files (limit %d)", MaxPoCFiles)
		}
		f, err := r.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
		if err != nil {
			if errors.Is(err, syscall.ELOOP) {
				return fmt.Errorf("%q is a symlink; symlinks are rejected", rel)
			}
			return fmt.Errorf("%q: %w", rel, err)
		}
		defer f.Close()
		data, err := readOpened(f, rel, MaxPoCBytes-total)
		if err != nil {
			return fmt.Errorf("%q: %w (total PoC limit is %d bytes)", rel, err, MaxPoCBytes)
		}
		total += int64(len(data))
		arts = append(arts, report.Artifact{Name: filepath.ToSlash(rel), Content: data})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return arts, nil
}
