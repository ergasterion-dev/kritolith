package main

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

	res, err := syncOSV(ctx, st, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if res != (osvSyncResult{written: 1}) {
		t.Fatalf("first sync: %+v, want 1 written", res)
	}

	res, err = syncOSV(ctx, st, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if res != (osvSyncResult{unchanged: 1}) {
		t.Fatalf("re-sync with unchanged data: %+v, want 1 unchanged", res)
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

	res, err := syncOSV(ctx, st, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if res != (osvSyncResult{}) {
		t.Errorf("%+v, want nothing for an entry with no affected packages", res)
	}
}

func TestRunOSVUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"osv"}, &out, &errOut)
	if code != 2 {
		t.Errorf("code = %d, want 2 for a missing subcommand", code)
	}
}

// One bad file in the export must not stop the sync, and an entry
// that affects no Go package is not ours to store.
func TestSyncOSVSkipsMalformedAndOtherEcosystems(t *testing.T) {
	fixture := buildFixtureZip(t, map[string]string{
		"GO-1.json":       `{"id":"GO-1","modified":"m","affected":[{"package":{"ecosystem":"Go","name":"example.com/a"}}]}`,
		"broken.json":     `{"id":"GO-2","modified":`,
		"PYSEC-1.json":    `{"id":"PYSEC-1","modified":"m","affected":[{"package":{"ecosystem":"PyPI","name":"requests"}}]}`,
		"GHSA-mixed.json": `{"id":"GHSA-mixed","modified":"m","affected":[{"package":{"ecosystem":"npm","name":"left-pad"}},{"package":{"ecosystem":"Go","name":"example.com/b"}}]}`,
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

	res, err := syncOSV(ctx, st, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if res != (osvSyncResult{written: 2, malformed: 1}) {
		t.Fatalf("%+v, want 2 written and 1 malformed", res)
	}
	for module, want := range map[string]int{"example.com/a": 1, "example.com/b": 1, "requests": 0, "left-pad": 0} {
		entries, err := st.OSVEntriesByModule(ctx, module)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != want {
			t.Errorf("%s: %d entries, want %d", module, len(entries), want)
		}
	}

	var out, errOut bytes.Buffer
	dataDir := filepath.Join(t.TempDir(), "cli")
	if code := run(ctx, []string{"osv", "sync", "--url", srv.URL, "--data-dir", dataDir}, &out, &errOut); code != 0 {
		t.Fatalf("code = %d, stderr: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "synced 2 OSV entries") || !strings.Contains(errOut.String(), "1 entries in the export could not be read") {
		t.Errorf("stdout = %q, stderr = %q", out.String(), errOut.String())
	}
}

// A server that accepts the request and then goes quiet must not hang
// a cron job forever.
func TestSyncOSVTimesOut(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	old := osvFetchTimeout
	osvFetchTimeout = 100 * time.Millisecond
	defer func() { osvFetchTimeout = old }()

	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	start := time.Now()
	if _, err := syncOSV(ctx, st, srv.URL); err == nil {
		t.Fatal("want an error from a server that never answers")
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("sync did not give up")
	}
}
