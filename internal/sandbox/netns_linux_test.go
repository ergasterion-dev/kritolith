package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnmountNullNetnsToleratesNonMounts(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("umount needs root")
	}
	root := t.TempDir()
	if err := unmountNullNetns(root); err != nil {
		t.Fatalf("missing file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, nullNetnsName), nil, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := unmountNullNetns(root); err != nil {
		t.Fatalf("plain file that is not a mount: %v", err)
	}
}
