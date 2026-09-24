package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	s, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}

func sampleReport() report.Report {
	return report.Report{
		ID:         "01ARYZ6S410000000000000000",
		Source:     report.SourceFile,
		SourceRef:  "/tmp/report.md",
		Repo:       "golang/net",
		ClaimedRef: "e1fcd82abba34df74614020343be8eb1fe85f0d9",
		Title:      "HTTP/2 over-read",
		Body:       "body \x1b[2J with hostile bytes",
		PoC:        []report.Artifact{{Name: "poc_test.go", Content: []byte("package http2")}},
		ReceivedAt: time.Date(2026, 9, 28, 10, 0, 0, 123, time.UTC),
	}
}

func TestOpenCreatesPrivateFiles(t *testing.T) {
	_, dir := openTemp(t)
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o700 {
		t.Errorf("data dir mode = %v, want 0700", st.Mode().Perm())
	}
	st, err = os.Stat(filepath.Join(dir, "kritolith.db"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("db mode = %v, want 0600", st.Mode().Perm())
	}
}

func TestOpenRejectsLooseDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Open(context.Background(), dir)
	if err == nil || !strings.Contains(err.Error(), "chmod 700") {
		t.Fatalf("err = %v, want chmod hint", err)
	}
}

func TestOpenTightensDBFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "kritolith.db")
	if err := os.WriteFile(db, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	st, _ := os.Stat(db)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("db mode = %v, want 0600", st.Mode().Perm())
	}
}

func TestOpenRejectsBadDataDir(t *testing.T) {
	for _, dir := range []string{"", "/tmp/a?b", "/tmp/a#b"} {
		if _, err := Open(context.Background(), dir); err == nil {
			t.Errorf("Open(%q) succeeded, want error", dir)
		}
	}
}

func TestOpenRejectsSymlinkedDB(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "kritolith.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), dir); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("err = %v, want symlink error", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret" {
		t.Fatalf("symlink target modified: got %q", got)
	}
}

func TestOpenPathWithSpaces(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "my data")
	s, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
}

func TestOpenPragmasAndMigrations(t *testing.T) {
	s, dir := openTemp(t)
	var fk, version int
	if err := s.db.QueryRow("PRAGMA foreign_keys").Scan(&fk); err != nil || fk != 1 {
		t.Fatalf("foreign_keys = %d, %v", fk, err)
	}
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 2 {
		t.Fatalf("user_version = %d, %v", version, err)
	}
	s.Close()
	s2, err := Open(context.Background(), dir) // reopening must not re-run migrations
	if err != nil {
		t.Fatal(err)
	}
	s2.Close()
}

func TestMigrationBackfillsExistingClaimsRows(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(ctx, filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	r := sampleReport()
	if err := s.SaveReport(ctx, r); err != nil {
		t.Fatal(err)
	}
	// Simulate a claim saved before this migration existed by inserting
	// directly with only the pre-migration columns present in the
	// INSERT — the new columns must still default to '' via the
	// migration's DEFAULT '', not NULL or an error.
	if err := s.SaveVerdict(ctx, report.Verdict{
		ReportID: r.ID, Outcome: report.OutcomeInconclusive,
		Claims: []report.Claim{{Kind: report.ClaimFunction, Value: "pkg.Old", Verified: report.TriYes}},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetVerdict(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Claims) != 1 || got.Claims[0].DeclPkgDir != "" || got.Claims[0].DeclReceiver != "" || got.Claims[0].DeclName != "" {
		t.Fatalf("claim = %+v, want empty decl_* fields for a claim saved with none set", got.Claims[0])
	}
}

func TestOpenRejectsNewerSchema(t *testing.T) {
	s, dir := openTemp(t)
	if _, err := s.db.Exec("PRAGMA user_version = 99"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	_, err := Open(context.Background(), dir)
	if err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("err = %v, want newer-schema error", err)
	}
}

func TestReportRoundTrip(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	want := sampleReport()
	if err := s.SaveReport(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetReport(ctx, want.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.ReceivedAt.Equal(want.ReceivedAt) {
		t.Errorf("ReceivedAt = %v, want %v", got.ReceivedAt, want.ReceivedAt)
	}
	got.ReceivedAt, want.ReceivedAt = time.Time{}, time.Time{}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	if _, err := s.GetReport(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing report err = %v, want ErrNotFound", err)
	}
}

func TestVerdictRoundTrip(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	r := sampleReport()
	if err := s.SaveReport(ctx, r); err != nil {
		t.Fatal(err)
	}
	want := report.Verdict{
		ReportID: r.ID,
		Outcome:  report.OutcomeGroundingFailed,
		Claims: []report.Claim{
			{Kind: report.ClaimFunction, Value: "http2.parseHeader", Source: "deterministic", Verified: report.TriNo, Evidence: "not declared", DeclPkgDir: "internal/http2", DeclReceiver: "", DeclName: "parseHeader"},
			{Kind: report.ClaimFile, Value: "http2/frame.go", Source: "deterministic", Verified: report.TriYes, Evidence: "found"},
		},
		Duplicates: []report.DupMatch{{AdvisoryID: "GHSA-xxxx", Score: 0.91}},
		Repro:      &report.ReproResult{Ref: r.ClaimedRef, Signal: "none"},
		Notes:      []string{"grounding failed on a hard claim"},
		DraftReply: "draft",
		Signature:  []byte{1, 2, 3},
		SignedAt:   time.Date(2026, 9, 28, 11, 0, 0, 0, time.UTC),
	}
	if err := s.SaveVerdict(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetVerdict(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.SignedAt.Equal(want.SignedAt) {
		t.Errorf("SignedAt = %v, want %v", got.SignedAt, want.SignedAt)
	}
	got.SignedAt, want.SignedAt = time.Time{}, time.Time{}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestSaveVerdictReplacesClaims(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	r := sampleReport()
	if err := s.SaveReport(ctx, r); err != nil {
		t.Fatal(err)
	}
	two := report.Verdict{ReportID: r.ID, Outcome: report.OutcomeInconclusive, Claims: []report.Claim{
		{Kind: report.ClaimFile, Value: "a.go", Source: "deterministic", Verified: report.TriUnknown},
		{Kind: report.ClaimFile, Value: "b.go", Source: "deterministic", Verified: report.TriUnknown},
	}}
	one := report.Verdict{ReportID: r.ID, Outcome: report.OutcomeNeedsInfo, Claims: two.Claims[:1]}
	if err := s.SaveVerdict(ctx, two); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveVerdict(ctx, one); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetVerdict(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != report.OutcomeNeedsInfo || len(got.Claims) != 1 {
		t.Fatalf("got outcome %s with %d claims, want NEEDS_INFO with 1", got.Outcome, len(got.Claims))
	}
	if got.Duplicates != nil || got.Notes != nil || got.Repro != nil || got.Signature != nil || !got.SignedAt.IsZero() {
		t.Fatalf("empty fields not preserved as zero values: %+v", got)
	}
}

func TestSaveVerdictErrors(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	if err := s.SaveVerdict(ctx, report.Verdict{ReportID: "no-such-report", Outcome: report.OutcomeInconclusive}); err == nil {
		t.Error("verdict for unknown report: want foreign key error")
	}
	r := sampleReport()
	if err := s.SaveReport(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveVerdict(ctx, report.Verdict{ReportID: r.ID, Outcome: "MAYBE"}); err == nil {
		t.Error("invalid outcome: want error")
	}
	if _, err := s.GetVerdict(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing verdict err = %v, want ErrNotFound", err)
	}
}

func TestClaimsByRepo(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)

	r1 := report.Report{ID: "r1", Repo: "owner/repo", ReceivedAt: time.Now()}
	r2 := report.Report{ID: "r2", Repo: "owner/repo", ReceivedAt: time.Now()}
	r3 := report.Report{ID: "r3", Repo: "other/repo", ReceivedAt: time.Now()}
	for _, r := range []report.Report{r1, r2, r3} {
		if err := s.SaveReport(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SaveVerdict(ctx, report.Verdict{
		ReportID: "r1", Outcome: report.OutcomeInconclusive,
		Claims: []report.Claim{
			{Kind: report.ClaimFunction, Value: "(*T).M", Verified: report.TriYes, DeclPkgDir: "pkg", DeclReceiver: "T", DeclName: "M"},
			{Kind: report.ClaimFile, Value: "a.go", Verified: report.TriUnknown}, // not function/vuln_class: excluded
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveVerdict(ctx, report.Verdict{
		ReportID: "r3", Outcome: report.OutcomeInconclusive,
		Claims: []report.Claim{{Kind: report.ClaimFunction, Value: "(*Other).N", Verified: report.TriYes}},
	}); err != nil {
		t.Fatal(err)
	}

	got, err := s.ClaimsByRepo(ctx, "owner/repo", "r2", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got["r1"]) != 1 || got["r1"][0].Value != "(*T).M" {
		t.Fatalf("ClaimsByRepo = %+v, want exactly r1's function claim", got)
	}
	if _, ok := got["r3"]; ok {
		t.Error("ClaimsByRepo returned a claim from a different repo")
	}
	if got["r1"][0].DeclPkgDir != "pkg" || got["r1"][0].DeclReceiver != "T" || got["r1"][0].DeclName != "M" {
		t.Errorf("ClaimsByRepo = %+v, want the decl_* columns round-tripped", got["r1"][0])
	}
}

// saveAnchor saves a report and a verdict carrying one function claim,
// so it's a candidate fingerprint-match anchor for ClaimsByRepo.
func saveAnchor(t *testing.T, s *Store, id, sourceRef string, outcome report.Outcome) {
	t.Helper()
	ctx := context.Background()
	r := report.Report{ID: id, Source: report.SourceFile, SourceRef: sourceRef, Repo: "owner/repo", ReceivedAt: time.Now()}
	if err := s.SaveReport(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveVerdict(ctx, report.Verdict{
		ReportID: id, Outcome: outcome,
		Claims: []report.Claim{{Kind: report.ClaimFunction, Value: "(*T).M", Verified: report.TriYes}},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestClaimsByRepoExcludesSameSourceRef(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)

	// A first run of the same report file (different ULID, same
	// SourceRef) and an unrelated report with no SourceRef at all.
	saveAnchor(t, s, "first-run", "/corpus/real/a/report.md", report.OutcomeInconclusive)
	saveAnchor(t, s, "other-file", "/corpus/real/b/report.md", report.OutcomeInconclusive)
	saveAnchor(t, s, "no-ref", "", report.OutcomeInconclusive)

	got, err := s.ClaimsByRepo(ctx, "owner/repo", "second-run", "/corpus/real/a/report.md")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["first-run"]; ok {
		t.Error("ClaimsByRepo must exclude a prior report with the same SourceRef (a re-run of the same report)")
	}
	if _, ok := got["other-file"]; !ok {
		t.Error("ClaimsByRepo must keep a prior report with a different SourceRef")
	}
	if _, ok := got["no-ref"]; !ok {
		t.Error("ClaimsByRepo must keep a prior report with an empty SourceRef")
	}

	// An empty excludeSourceRef must exclude nothing beyond the ID —
	// in particular not every report whose own SourceRef is empty.
	got, err = s.ClaimsByRepo(ctx, "owner/repo", "second-run", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Errorf("ClaimsByRepo with empty excludeSourceRef = %d reports, want all 3", len(got))
	}
}

func TestClaimsByRepoExcludesRejectedAnchors(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)

	saveAnchor(t, s, "grounding-failed", "", report.OutcomeGroundingFailed)
	saveAnchor(t, s, "needs-info", "", report.OutcomeNeedsInfo)
	saveAnchor(t, s, "already-dup", "", report.OutcomeLikelyDuplicate)
	saveAnchor(t, s, "inconclusive", "", report.OutcomeInconclusive)
	saveAnchor(t, s, "reproduced", "", report.OutcomeReproduced)
	// A saved report with no verdict yet must never anchor a match.
	if err := s.SaveReport(ctx, report.Report{ID: "no-verdict", Repo: "owner/repo", ReceivedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	got, err := s.ClaimsByRepo(ctx, "owner/repo", "new", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"grounding-failed", "needs-info", "already-dup", "no-verdict"} {
		if _, ok := got[id]; ok {
			t.Errorf("ClaimsByRepo returned %q; a rejected, duplicate, or unverdicted report must never anchor a match", id)
		}
	}
	for _, id := range []string{"inconclusive", "reproduced"} {
		if _, ok := got[id]; !ok {
			t.Errorf("ClaimsByRepo dropped %q; a normal prior report must still anchor a match", id)
		}
	}
}

func TestSaveAndFindEmbeddingsByRepo(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)

	for _, id := range []string{"r1", "r2"} {
		if err := s.SaveReport(ctx, report.Report{ID: id, Repo: "owner/repo", ReceivedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	vec := []float32{0.1, 0.2, 0.3}
	if err := s.SaveEmbedding(ctx, "r1", "local-embed", vec); err != nil {
		t.Fatal(err)
	}

	got, err := s.EmbeddingsByRepo(ctx, "owner/repo", "r2")
	if err != nil {
		t.Fatal(err)
	}
	e, ok := got["r1"]
	if !ok || e.Model != "local-embed" || len(e.Vector) != 3 {
		t.Fatalf("EmbeddingsByRepo = %+v, want r1's embedding", got)
	}
	for i := range vec {
		if e.Vector[i] != vec[i] {
			t.Errorf("Vector[%d] = %v, want %v", i, e.Vector[i], vec[i])
		}
	}

	// Overwrite: SaveEmbedding replaces, not appends.
	if err := s.SaveEmbedding(ctx, "r1", "local-embed", []float32{0.9}); err != nil {
		t.Fatal(err)
	}
	got, err = s.EmbeddingsByRepo(ctx, "owner/repo", "r2")
	if err != nil {
		t.Fatal(err)
	}
	if len(got["r1"].Vector) != 1 {
		t.Fatalf("EmbeddingsByRepo after overwrite = %+v, want a single-element vector", got)
	}
}

func TestUpsertAndFindOSVEntriesByModule(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)

	changed, err := s.UpsertOSVEntry(ctx, "GO-2022-0603", "gopkg.in/yaml.v3", "2022-01-01T00:00:00Z", []byte(`{"id":"GO-2022-0603"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("first upsert of a new entry should report changed = true")
	}

	// Re-upsert with the same modified timestamp: no-op.
	changed, err = s.UpsertOSVEntry(ctx, "GO-2022-0603", "gopkg.in/yaml.v3", "2022-01-01T00:00:00Z", []byte(`{"id":"GO-2022-0603"}`))
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("re-upserting an unchanged entry should report changed = false")
	}

	// Re-upsert with a newer modified timestamp: writes.
	changed, err = s.UpsertOSVEntry(ctx, "GO-2022-0603", "gopkg.in/yaml.v3", "2022-02-01T00:00:00Z", []byte(`{"id":"GO-2022-0603","modified":"2022-02-01T00:00:00Z"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("re-upserting with a newer modified timestamp should report changed = true")
	}

	entries, err := s.OSVEntriesByModule(ctx, "gopkg.in/yaml.v3")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != "GO-2022-0603" || entries[0].Modified != "2022-02-01T00:00:00Z" {
		t.Fatalf("OSVEntriesByModule = %+v, want one entry with the latest modified value", entries)
	}
	// Verify that raw and module are also updated on conflict update.
	wantRaw := []byte(`{"id":"GO-2022-0603","modified":"2022-02-01T00:00:00Z"}`)
	if !bytes.Equal(entries[0].Raw, wantRaw) {
		t.Errorf("Raw after update = %s, want %s (must update raw on ON CONFLICT)", entries[0].Raw, wantRaw)
	}
	if entries[0].Module != "gopkg.in/yaml.v3" {
		t.Errorf("Module = %q, want %q", entries[0].Module, "gopkg.in/yaml.v3")
	}

	// Update with a different module to verify module field is also updated.
	changed, err = s.UpsertOSVEntry(ctx, "GO-2022-0603", "gopkg.in/yaml.v2", "2022-03-01T00:00:00Z", []byte(`{"id":"GO-2022-0603","modified":"2022-03-01T00:00:00Z"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("re-upserting with newer modified and different module should report changed = true")
	}

	// Verify old module no longer has the entry.
	old, err := s.OSVEntriesByModule(ctx, "gopkg.in/yaml.v3")
	if err != nil {
		t.Fatal(err)
	}
	if len(old) != 0 {
		t.Fatalf("OSVEntriesByModule for gopkg.in/yaml.v3 after module change = %+v, want empty (module field was updated)", old)
	}

	// Verify new module has the entry with the updated raw and modified.
	entries, err = s.OSVEntriesByModule(ctx, "gopkg.in/yaml.v2")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Module != "gopkg.in/yaml.v2" || entries[0].Modified != "2022-03-01T00:00:00Z" {
		t.Fatalf("OSVEntriesByModule after module update = %+v, want entry in new module with updated modified", entries)
	}
	wantRaw = []byte(`{"id":"GO-2022-0603","modified":"2022-03-01T00:00:00Z"}`)
	if !bytes.Equal(entries[0].Raw, wantRaw) {
		t.Errorf("Raw after module update = %s, want %s", entries[0].Raw, wantRaw)
	}

	if none, err := s.OSVEntriesByModule(ctx, "no/such/module"); err != nil || len(none) != 0 {
		t.Fatalf("OSVEntriesByModule for an unknown module = %+v, %v, want empty, nil", none, err)
	}
}
