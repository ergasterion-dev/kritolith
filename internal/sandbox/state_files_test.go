package sandbox

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestRemoveStateFilesOnlyTouchesThisID(t *testing.T) {
	root := t.TempDir()
	id, longer := "kritolith-111", "kritolith-1112"
	for _, n := range []string{
		id + "_sandbox:" + id + ".lock", "runsc-" + id + ".sock",
		longer + "_sandbox:" + longer + ".lock", "runsc-" + longer + ".sock", "keep",
	} {
		if err := os.WriteFile(filepath.Join(root, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := removeStateFiles(root, id); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(root)
	var got []string
	for _, e := range ents {
		got = append(got, e.Name())
	}
	sort.Strings(got)
	want := []string{"keep", longer + "_sandbox:" + longer + ".lock", "runsc-" + longer + ".sock"}
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestRemoveStateFilesRefusesNonOrphanID(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeStateFiles(root, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "a")); err != nil {
		t.Fatal("removed a file for a non-orphan id")
	}
}
