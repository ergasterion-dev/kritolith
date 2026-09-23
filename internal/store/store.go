// Package store persists reports and verdicts in a single SQLite file.
package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver (pure Go, no cgo)

	"github.com/ergasterion-dev/kritolith/internal/report"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("store: not found")

const dbFile = "kritolith.db"

// Store is the SQLite-backed persistence layer.
type Store struct {
	db *sql.DB
}

// Open creates dataDir (0700) and the database file (0600) if needed,
// then applies pending migrations. It refuses a data dir that group or
// others can access, because the database holds embargoed reports.
func Open(ctx context.Context, dataDir string) (*Store, error) {
	if dataDir == "" {
		return nil, errors.New("store: data dir is empty")
	}
	if strings.ContainsAny(dataDir, "?#") {
		return nil, fmt.Errorf("store: data dir %q must not contain '?' or '#'", dataDir)
	}
	if err := ensurePrivateDir(dataDir); err != nil {
		return nil, err
	}
	path := filepath.Join(dataDir, dbFile)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("store: %s is a symlink; refusing to open it", path)
	}
	if err != nil {
		return nil, fmt.Errorf("store: create %s: %w", path, err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("store: stat %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("store: %s is not a regular file", path)
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return nil, fmt.Errorf("store: chmod %s: %w", path, err)
	}
	f.Close()

	dsn := path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	// One connection: SQLite serializes writers anyway, and this keeps
	// per-connection pragmas consistent.
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("store: create data dir %s: %w", dir, err)
	}
	st, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("store: stat data dir %s: %w", dir, err)
	}
	if !st.IsDir() {
		return fmt.Errorf("store: data dir %s is not a directory", dir)
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("store: data dir %s has mode %v; it must not be accessible by group or others (run: chmod 700 %s)", dir, perm, dir)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != os.Geteuid() {
		return fmt.Errorf("store: data dir %s is owned by uid %d, not the current user (%d)", dir, sys.Uid, os.Geteuid())
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	names, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("store: list migrations: %w", err)
	}
	sort.Strings(names)

	var current int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&current); err != nil {
		return fmt.Errorf("store: read schema version: %w", err)
	}
	if current > len(names) {
		return fmt.Errorf("store: database schema version %d is newer than this binary supports (%d)", current, len(names))
	}
	for i := current; i < len(names); i++ {
		body, err := migrationFS.ReadFile(names[i])
		if err != nil {
			return fmt.Errorf("store: read %s: %w", names[i], err)
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("store: begin %s: %w", names[i], err)
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: apply %s: %w", names[i], err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: set schema version %d: %w", i+1, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: commit %s: %w", names[i], err)
		}
	}
	return nil
}

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTime(s string) (time.Time, error) { return time.Parse(time.RFC3339Nano, s) }

// SaveReport inserts a new report. IDs are unique; saving twice fails.
func (s *Store) SaveReport(ctx context.Context, r report.Report) error {
	poc := r.PoC
	if poc == nil {
		poc = []report.Artifact{}
	}
	pocJSON, err := json.Marshal(poc)
	if err != nil {
		return fmt.Errorf("store: encode poc for %s: %w", r.ID, err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO reports (id, source, source_ref, repo, claimed_ref, title, body, poc_json, received_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, string(r.Source), r.SourceRef, r.Repo, r.ClaimedRef, r.Title, r.Body, pocJSON, formatTime(r.ReceivedAt))
	if err != nil {
		return fmt.Errorf("store: save report %s: %w", r.ID, err)
	}
	return nil
}

// GetReport loads a report by ID.
func (s *Store) GetReport(ctx context.Context, id string) (report.Report, error) {
	var (
		r          report.Report
		source     string
		pocJSON    []byte
		receivedAt string
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT id, source, source_ref, repo, claimed_ref, title, body, poc_json, received_at
		FROM reports WHERE id = ?`, id).
		Scan(&r.ID, &source, &r.SourceRef, &r.Repo, &r.ClaimedRef, &r.Title, &r.Body, &pocJSON, &receivedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return report.Report{}, fmt.Errorf("store: report %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return report.Report{}, fmt.Errorf("store: get report %s: %w", id, err)
	}
	r.Source = report.Source(source)
	if err := json.Unmarshal(pocJSON, &r.PoC); err != nil {
		return report.Report{}, fmt.Errorf("store: decode poc for %s: %w", id, err)
	}
	if len(r.PoC) == 0 {
		r.PoC = nil
	}
	if r.ReceivedAt, err = parseTime(receivedAt); err != nil {
		return report.Report{}, fmt.Errorf("store: parse received_at for %s: %w", id, err)
	}
	return r, nil
}

// SaveVerdict inserts or replaces the verdict for a report, including
// its claims, in one transaction.
func (s *Store) SaveVerdict(ctx context.Context, v report.Verdict) error {
	if !v.Outcome.Valid() {
		return fmt.Errorf("store: save verdict %s: invalid outcome %q", v.ReportID, v.Outcome)
	}
	dups, err := json.Marshal(emptyIfNil(v.Duplicates))
	if err != nil {
		return fmt.Errorf("store: encode duplicates for %s: %w", v.ReportID, err)
	}
	notes, err := json.Marshal(emptyIfNil(v.Notes))
	if err != nil {
		return fmt.Errorf("store: encode notes for %s: %w", v.ReportID, err)
	}
	var repro, signature, signedAt any
	if v.Repro != nil {
		b, err := json.Marshal(v.Repro)
		if err != nil {
			return fmt.Errorf("store: encode repro for %s: %w", v.ReportID, err)
		}
		repro = b
	}
	if len(v.Signature) > 0 {
		signature = v.Signature
	}
	if !v.SignedAt.IsZero() {
		signedAt = formatTime(v.SignedAt)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin verdict %s: %w", v.ReportID, err)
	}
	defer tx.Rollback() // no-op after Commit

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO verdicts (report_id, outcome, duplicates_json, repro_json, notes_json, draft_reply, signature, signed_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(report_id) DO UPDATE SET
			outcome = excluded.outcome,
			duplicates_json = excluded.duplicates_json,
			repro_json = excluded.repro_json,
			notes_json = excluded.notes_json,
			draft_reply = excluded.draft_reply,
			signature = excluded.signature,
			signed_at = excluded.signed_at,
			created_at = excluded.created_at`,
		v.ReportID, string(v.Outcome), dups, repro, notes, v.DraftReply, signature, signedAt, formatTime(time.Now())); err != nil {
		return fmt.Errorf("store: save verdict %s: %w", v.ReportID, err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM claims WHERE report_id = ?`, v.ReportID); err != nil {
		return fmt.Errorf("store: clear claims for %s: %w", v.ReportID, err)
	}
	for i, c := range v.Claims {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO claims (report_id, kind, value, source, verified, evidence)
			VALUES (?, ?, ?, ?, ?, ?)`,
			v.ReportID, string(c.Kind), c.Value, c.Source, string(c.Verified), c.Evidence); err != nil {
			return fmt.Errorf("store: save claim %d for %s: %w", i, v.ReportID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit verdict %s: %w", v.ReportID, err)
	}
	return nil
}

// GetVerdict loads the verdict and claims for a report.
func (s *Store) GetVerdict(ctx context.Context, reportID string) (report.Verdict, error) {
	var (
		v                  report.Verdict
		outcome            string
		dups, repro, notes []byte
		signedAt           sql.NullString
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT outcome, duplicates_json, repro_json, notes_json, draft_reply, signature, signed_at
		FROM verdicts WHERE report_id = ?`, reportID).
		Scan(&outcome, &dups, &repro, &notes, &v.DraftReply, &v.Signature, &signedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return report.Verdict{}, fmt.Errorf("store: verdict for %s: %w", reportID, ErrNotFound)
	}
	if err != nil {
		return report.Verdict{}, fmt.Errorf("store: get verdict %s: %w", reportID, err)
	}
	v.ReportID = reportID
	if v.Outcome, err = report.ParseOutcome(outcome); err != nil {
		return report.Verdict{}, fmt.Errorf("store: verdict %s: %w", reportID, err)
	}
	if err := json.Unmarshal(dups, &v.Duplicates); err != nil {
		return report.Verdict{}, fmt.Errorf("store: decode duplicates for %s: %w", reportID, err)
	}
	if err := json.Unmarshal(notes, &v.Notes); err != nil {
		return report.Verdict{}, fmt.Errorf("store: decode notes for %s: %w", reportID, err)
	}
	if repro != nil {
		v.Repro = &report.ReproResult{}
		if err := json.Unmarshal(repro, v.Repro); err != nil {
			return report.Verdict{}, fmt.Errorf("store: decode repro for %s: %w", reportID, err)
		}
	}
	if signedAt.Valid {
		if v.SignedAt, err = parseTime(signedAt.String); err != nil {
			return report.Verdict{}, fmt.Errorf("store: parse signed_at for %s: %w", reportID, err)
		}
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT kind, value, source, verified, evidence
		FROM claims WHERE report_id = ? ORDER BY id`, reportID)
	if err != nil {
		return report.Verdict{}, fmt.Errorf("store: get claims for %s: %w", reportID, err)
	}
	defer rows.Close()
	for rows.Next() {
		var c report.Claim
		var kind, verified string
		if err := rows.Scan(&kind, &c.Value, &c.Source, &verified, &c.Evidence); err != nil {
			return report.Verdict{}, fmt.Errorf("store: scan claim for %s: %w", reportID, err)
		}
		c.Kind, c.Verified = report.ClaimKind(kind), report.Tri(verified)
		v.Claims = append(v.Claims, c)
	}
	if err := rows.Err(); err != nil {
		return report.Verdict{}, fmt.Errorf("store: read claims for %s: %w", reportID, err)
	}

	v.Duplicates = nilIfEmpty(v.Duplicates)
	v.Notes = nilIfEmpty(v.Notes)
	return v, nil
}

func emptyIfNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func nilIfEmpty[T any](s []T) []T {
	if len(s) == 0 {
		return nil
	}
	return s
}
