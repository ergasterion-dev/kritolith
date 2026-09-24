// Package store persists reports and verdicts in a single SQLite file.
package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
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

// ClaimsByRepo returns every function and vuln_class claim from
// reports in repo other than excludeReportID, grouped by report ID.
// Dedupe uses this to fingerprint-match a report against every prior
// report already saved for the same repository.
func (s *Store) ClaimsByRepo(ctx context.Context, repo, excludeReportID string) (map[string][]report.Claim, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT c.report_id, c.kind, c.value, c.source, c.verified, c.evidence
		FROM claims c
		JOIN reports r ON r.id = c.report_id
		WHERE r.repo = ? AND c.report_id != ? AND c.kind IN (?, ?)`,
		repo, excludeReportID, string(report.ClaimFunction), string(report.ClaimVulnClass))
	if err != nil {
		return nil, fmt.Errorf("store: claims by repo %s: %w", repo, err)
	}
	defer rows.Close()
	out := map[string][]report.Claim{}
	for rows.Next() {
		var reportID, kind, verified string
		var c report.Claim
		if err := rows.Scan(&reportID, &kind, &c.Value, &c.Source, &verified, &c.Evidence); err != nil {
			return nil, fmt.Errorf("store: scan claim by repo %s: %w", repo, err)
		}
		c.Kind, c.Verified = report.ClaimKind(kind), report.Tri(verified)
		out[reportID] = append(out[reportID], c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read claims by repo %s: %w", repo, err)
	}
	return out, nil
}

// Embedding is one stored report's title+body embedding vector.
type Embedding struct {
	Model  string
	Vector []float32
}

// SaveEmbedding inserts or replaces reportID's embedding.
func (s *Store) SaveEmbedding(ctx context.Context, reportID, model string, vector []float32) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO embeddings (report_id, model, dims, vector)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(report_id) DO UPDATE SET
			model = excluded.model, dims = excluded.dims, vector = excluded.vector`,
		reportID, model, len(vector), encodeVector(vector))
	if err != nil {
		return fmt.Errorf("store: save embedding for %s: %w", reportID, err)
	}
	return nil
}

// EmbeddingsByRepo returns every stored embedding for reports in repo
// other than excludeReportID, keyed by report ID.
func (s *Store) EmbeddingsByRepo(ctx context.Context, repo, excludeReportID string) (map[string]Embedding, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT e.report_id, e.model, e.dims, e.vector
		FROM embeddings e
		JOIN reports r ON r.id = e.report_id
		WHERE r.repo = ? AND e.report_id != ?`, repo, excludeReportID)
	if err != nil {
		return nil, fmt.Errorf("store: embeddings by repo %s: %w", repo, err)
	}
	defer rows.Close()
	out := map[string]Embedding{}
	for rows.Next() {
		var reportID, model string
		var dims int
		var raw []byte
		if err := rows.Scan(&reportID, &model, &dims, &raw); err != nil {
			return nil, fmt.Errorf("store: scan embedding by repo %s: %w", repo, err)
		}
		vec, err := decodeVector(raw, dims)
		if err != nil {
			return nil, fmt.Errorf("store: decode embedding for %s: %w", reportID, err)
		}
		out[reportID] = Embedding{Model: model, Vector: vec}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read embeddings by repo %s: %w", repo, err)
	}
	return out, nil
}

// encodeVector packs a []float32 into a little-endian byte slice for
// the embeddings.vector BLOB column.
func encodeVector(v []float32) []byte {
	buf := make([]byte, 4*len(v))
	for i, f := range v {
		binary.LittleEndian.PutUint32(buf[i*4:], math.Float32bits(f))
	}
	return buf
}

// decodeVector is encodeVector's inverse. A byte length that doesn't
// match 4*dims means the row is corrupt, reported as an error rather
// than silently truncated or padded.
func decodeVector(raw []byte, dims int) ([]float32, error) {
	if len(raw) != 4*dims {
		return nil, fmt.Errorf("store: embedding has %d bytes, want %d for dims=%d", len(raw), 4*dims, dims)
	}
	out := make([]float32, dims)
	for i := range out {
		out[i] = math.Float32frombits(binary.LittleEndian.Uint32(raw[i*4:]))
	}
	return out, nil
}

// OSVEntry is one stored OSV advisory.
type OSVEntry struct {
	ID       string
	Module   string
	Modified string
	Raw      []byte
}

// UpsertOSVEntry inserts id if it's new, or updates it if the stored
// entry's Modified differs from modified. It reports whether the row
// was written: false means the entry already existed with the same
// Modified value, so the caller (kritolith osv sync) can report it as
// unchanged rather than re-synced.
func (s *Store) UpsertOSVEntry(ctx context.Context, id, module, modified string, raw []byte) (bool, error) {
	var existing string
	err := s.db.QueryRowContext(ctx, `SELECT modified FROM osv_entries WHERE id = ?`, id).Scan(&existing)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// New entry: fall through to insert.
	case err != nil:
		return false, fmt.Errorf("store: check osv entry %s: %w", id, err)
	case existing == modified:
		return false, nil
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO osv_entries (id, module, modified, raw)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			module = excluded.module, modified = excluded.modified, raw = excluded.raw`,
		id, module, modified, raw)
	if err != nil {
		return false, fmt.Errorf("store: save osv entry %s: %w", id, err)
	}
	return true, nil
}

// OSVEntriesByModule returns every stored OSV entry for module.
func (s *Store) OSVEntriesByModule(ctx context.Context, module string) ([]OSVEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, module, modified, raw FROM osv_entries WHERE module = ?`, module)
	if err != nil {
		return nil, fmt.Errorf("store: osv entries by module %s: %w", module, err)
	}
	defer rows.Close()
	var out []OSVEntry
	for rows.Next() {
		var e OSVEntry
		if err := rows.Scan(&e.ID, &e.Module, &e.Modified, &e.Raw); err != nil {
			return nil, fmt.Errorf("store: scan osv entry by module %s: %w", module, err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read osv entries by module %s: %w", module, err)
	}
	return out, nil
}
