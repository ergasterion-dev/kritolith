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

// readRegular reads at most limit bytes from a regular file. It opens
// non-blocking so a FIFO can't hang intake, and with O_NOFOLLOW unless
// followSymlinks is set.
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
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if st.Size() > limit {
		return nil, fmt.Errorf("%s is %d bytes; limit is %d", path, st.Size(), limit)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s grew past the %d byte limit while reading", path, limit)
	}
	return data, nil
}

// loadPoC reads every regular file under dir. Symlinks, devices, FIFOs
// and sockets anywhere in the tree are rejected rather than skipped, so
// a hostile PoC can't point Kritolith at files outside the directory.
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
			return fmt.Errorf("%s is a symlink; symlinks are rejected", rel)
		case d.IsDir():
			return nil
		case !d.Type().IsRegular():
			return fmt.Errorf("%s is not a regular file", rel)
		}
		if len(arts) == MaxPoCFiles {
			return fmt.Errorf("too many files (limit %d)", MaxPoCFiles)
		}
		data, err := readRegular(path, MaxPoCBytes-total, false)
		if err != nil {
			return fmt.Errorf("%s: %w (total PoC limit is %d bytes)", rel, err, MaxPoCBytes)
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
