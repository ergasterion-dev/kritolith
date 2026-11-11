package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Intake job states.
const (
	IntakeQueued  = "queued"
	IntakeRunning = "running"
	IntakeDone    = "done"
	IntakeFailed  = "failed"
)

// maxIntakeError bounds the error text kept for a job. It is for an
// operator to read; it must not become a place where a remote
// server's reply is stored at length.
const maxIntakeError = 500

// IntakeJob is one announced report waiting to be fetched and
// processed.
type IntakeJob struct {
	ID         int64
	Source     string // "github"
	Repo       string // owner/name
	ExternalID string // the GHSA ID
	State      string
	Attempts   int
	LastError  string
	RunAfter   time.Time
	ReportID   string // set once the job is done
}

// EnqueueIntake adds a job unless one for the same (source, repo,
// externalID) already exists, in any state. created says which.
func (s *Store) EnqueueIntake(ctx context.Context, source, repo, externalID string, now time.Time) (created bool, err error) {
	ts := formatTime(now)
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO intake_jobs (source, repo, external_id, state, run_after, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (source, repo, external_id) DO NOTHING`,
		source, repo, externalID, IntakeQueued, now.Unix(), ts, ts)
	if err != nil {
		return false, fmt.Errorf("store: enqueue intake %s %s: %w", repo, externalID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: enqueue intake %s %s: %w", repo, externalID, err)
	}
	return n == 1, nil
}

// ClaimIntake marks the oldest due job as running, counts the attempt
// and returns it. It returns nil, with no error, when nothing is due.
func (s *Store) ClaimIntake(ctx context.Context, now time.Time) (*IntakeJob, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: claim intake: %w", err)
	}
	defer tx.Rollback() // no-op after Commit

	var (
		j        IntakeJob
		runAfter int64
	)
	err = tx.QueryRowContext(ctx, `
		SELECT id, source, repo, external_id, attempts, last_error, run_after
		FROM intake_jobs
		WHERE state = ? AND run_after <= ?
		ORDER BY run_after, id
		LIMIT 1`, IntakeQueued, now.Unix()).
		Scan(&j.ID, &j.Source, &j.Repo, &j.ExternalID, &j.Attempts, &j.LastError, &runAfter)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: claim intake: %w", err)
	}
	j.Attempts++
	j.State = IntakeRunning
	j.RunAfter = time.Unix(runAfter, 0).UTC()
	if _, err := tx.ExecContext(ctx, `
		UPDATE intake_jobs SET state = ?, attempts = ?, updated_at = ? WHERE id = ?`,
		IntakeRunning, j.Attempts, formatTime(now), j.ID); err != nil {
		return nil, fmt.Errorf("store: claim intake %d: %w", j.ID, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: claim intake %d: %w", j.ID, err)
	}
	return &j, nil
}

// FinishIntake marks a job done and records the report it produced.
func (s *Store) FinishIntake(ctx context.Context, id int64, reportID string, now time.Time) error {
	if _, err := s.db.ExecContext(ctx, `
		UPDATE intake_jobs SET state = ?, report_id = ?, last_error = '', updated_at = ? WHERE id = ?`,
		IntakeDone, reportID, formatTime(now), id); err != nil {
		return fmt.Errorf("store: finish intake %d: %w", id, err)
	}
	return nil
}

// RetryIntake puts a job that failed back in the queue, due at
// retryAt, with the reason it failed.
func (s *Store) RetryIntake(ctx context.Context, id int64, reason string, retryAt, now time.Time) error {
	return s.setIntakeFailure(ctx, id, IntakeQueued, reason, retryAt, now)
}

// FailIntake marks a job as failed for good.
func (s *Store) FailIntake(ctx context.Context, id int64, reason string, now time.Time) error {
	return s.setIntakeFailure(ctx, id, IntakeFailed, reason, now, now)
}

func (s *Store) setIntakeFailure(ctx context.Context, id int64, state, reason string, runAfter, now time.Time) error {
	if len(reason) > maxIntakeError {
		reason = reason[:maxIntakeError]
	}
	if _, err := s.db.ExecContext(ctx, `
		UPDATE intake_jobs SET state = ?, last_error = ?, run_after = ?, updated_at = ? WHERE id = ?`,
		state, reason, runAfter.Unix(), formatTime(now), id); err != nil {
		return fmt.Errorf("store: update intake %d: %w", id, err)
	}
	return nil
}

// RequeueRunningIntake puts every job left in the running state back
// in the queue. A job is only running while a worker holds it, so at
// startup a running job means the previous process died mid-job.
func (s *Store) RequeueRunningIntake(ctx context.Context, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE intake_jobs SET state = ?, run_after = ?, updated_at = ? WHERE state = ?`,
		IntakeQueued, now.Unix(), formatTime(now), IntakeRunning)
	if err != nil {
		return 0, fmt.Errorf("store: requeue running intake jobs: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: requeue running intake jobs: %w", err)
	}
	return int(n), nil
}

// GetIntake returns one job.
func (s *Store) GetIntake(ctx context.Context, id int64) (IntakeJob, error) {
	var (
		j        IntakeJob
		runAfter int64
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT id, source, repo, external_id, state, attempts, last_error, run_after, report_id
		FROM intake_jobs WHERE id = ?`, id).
		Scan(&j.ID, &j.Source, &j.Repo, &j.ExternalID, &j.State, &j.Attempts, &j.LastError, &runAfter, &j.ReportID)
	if err != nil {
		return IntakeJob{}, fmt.Errorf("store: get intake %d: %w", id, err)
	}
	j.RunAfter = time.Unix(runAfter, 0).UTC()
	return j, nil
}
