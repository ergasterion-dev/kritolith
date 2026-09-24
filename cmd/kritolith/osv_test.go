package main

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/store"
)

func buildFixtureZip(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestSyncOSV(t *testing.T) {
	fixture := buildFixtureZip(t, map[string]string{
		"GO-2022-0603.json": `{"id":"GO-2022-0603","modified":"2022-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"Go","name":"gopkg.in/yaml.v3"},"ecosystem_specific":{"imports":[{"symbols":["parser.peek"]}]}}]}`,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixture)
	}))
	defer srv.Close()

	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	written, skipped, err := syncOSV(ctx, st, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if written != 1 || skipped != 0 {
		t.Fatalf("first sync: written = %d, skipped = %d, want 1, 0", written, skipped)
	}

	written, skipped, err = syncOSV(ctx, st, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if written != 0 || skipped != 1 {
		t.Fatalf("re-sync with unchanged data: written = %d, skipped = %d, want 0, 1", written, skipped)
	}

	entries, err := st.OSVEntriesByModule(ctx, "gopkg.in/yaml.v3")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != "GO-2022-0603" {
		t.Fatalf("entries = %+v, want one GO-2022-0603 entry", entries)
	}
}

func TestSyncOSVSkipsEntryWithoutAffected(t *testing.T) {
	fixture := buildFixtureZip(t, map[string]string{
		"GO-2022-0603.json": `{"id":"GO-2022-0603","modified":"2022-01-01T00:00:00Z","affected":[]}`,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixture)
	}))
	defer srv.Close()

	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	written, skipped, err := syncOSV(ctx, st, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if written != 0 || skipped != 0 {
		t.Errorf("written = %d, skipped = %d, want 0, 0 for an entry with no affected packages", written, skipped)
	}
}

func TestRunOSVUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"osv"}, &out, &errOut)
	if code != 2 {
		t.Errorf("code = %d, want 2 for a missing subcommand", code)
	}
}
