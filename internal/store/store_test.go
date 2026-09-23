package store

import (
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
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 1 {
		t.Fatalf("user_version = %d, %v", version, err)
	}
	s.Close()
	s2, err := Open(context.Background(), dir) // reopening must not re-run migrations
	if err != nil {
		t.Fatal(err)
	}
	s2.Close()
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
			{Kind: report.ClaimFunction, Value: "http2.parseHeader", Source: "deterministic", Verified: report.TriNo, Evidence: "not declared"},
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
