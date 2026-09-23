//go:build unix

package file

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestLoadPoCRejectsFIFO(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "report.md")
	writeFile(t, p, "report")
	poc := filepath.Join(dir, "poc")
	writeFile(t, filepath.Join(poc, "ok.go"), "package x")
	if err := syscall.Mkfifo(filepath.Join(poc, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	o := opts(t, p)
	o.PoCDir = poc
	_, err := Load(o)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("err = %v, want FIFO rejection (and no hang)", err)
	}
}
