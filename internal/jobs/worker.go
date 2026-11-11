// Package jobs runs the intake queue: it takes announced reports one
// at a time, processes each, and retries the ones that fail.
package jobs

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/report"
	"github.com/ergasterion-dev/kritolith/internal/store"
)

// Queue is the persistence the worker needs. *store.Store implements
// it.
type Queue interface {
	ClaimIntake(ctx context.Context, now time.Time) (*store.IntakeJob, error)
	FinishIntake(ctx context.Context, id int64, reportID string, now time.Time) error
	RetryIntake(ctx context.Context, id int64, reason string, retryAt, now time.Time) error
	FailIntake(ctx context.Context, id int64, reason string, now time.Time) error
	RequeueRunningIntake(ctx context.Context, now time.Time) (int, error)
}

// Process handles one job and returns the ID of the report it stored.
type Process func(ctx context.Context, job store.IntakeJob) (reportID string, err error)

// permanentError marks a failure that retrying cannot fix.
type permanentError struct{ err error }

func (p permanentError) Error() string { return p.err.Error() }
func (p permanentError) Unwrap() error { return p.err }

// Permanent wraps err so the worker fails the job at once instead of
// retrying it.
func Permanent(err error) error { return permanentError{err} }

// Worker processes the queue with one goroutine. Reports are handled
// one at a time on purpose: two reports for the same repository share
// a git mirror, and dedupe compares each report with the ones before.
type Worker struct {
	Queue   Queue
	Process Process
	// Backoff[i] is the wait before attempt i+2. A job that has failed
	// len(Backoff)+1 times is failed for good.
	Backoff []time.Duration
	// Poll is how often the queue is checked when nothing wakes the
	// worker: it is what picks up a retry when its time comes.
	Poll   time.Duration
	Logger *slog.Logger
	Now    func() time.Time

	wake chan struct{}
}

// DefaultBackoff retries a failed job after one minute, then five,
// then thirty, then two hours: long enough to ride out an outage of
// the code host, short enough that a report is not left for a day.
var DefaultBackoff = []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour}

// NewWorker returns a Worker with the default backoff and poll
// interval.
func NewWorker(q Queue, p Process, logger *slog.Logger) *Worker {
	if logger == nil {
		logger = slog.Default()
	}
	return &Worker{Queue: q, Process: p, Backoff: DefaultBackoff, Poll: 15 * time.Second, Logger: logger, Now: time.Now, wake: make(chan struct{}, 1)}
}

// Wake asks the worker to look at the queue now. It never blocks.
func (w *Worker) Wake() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// Run processes jobs until ctx is done. A job in progress when ctx
// ends is given back to the queue, not failed.
func (w *Worker) Run(ctx context.Context) error {
	n, err := w.Queue.RequeueRunningIntake(ctx, w.Now())
	if err != nil {
		return err
	}
	if n > 0 {
		w.Logger.Warn("intake: jobs were left running by a previous process; queued them again", "jobs", n)
	}
	ticker := time.NewTicker(w.Poll)
	defer ticker.Stop()
	for {
		for w.runOne(ctx) {
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		case <-w.wake:
		}
	}
}

// runOne processes at most one due job and reports whether there may
// be more.
func (w *Worker) runOne(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	job, err := w.Queue.ClaimIntake(ctx, w.Now())
	if err != nil {
		w.Logger.Error("intake: could not read the queue", "error", err)
		return false
	}
	if job == nil {
		return false
	}
	log := w.Logger.With("job", job.ID, "repo", job.Repo, "id", job.ExternalID, "attempt", job.Attempts)
	reportID, err := w.Process(ctx, *job)

	// Bookkeeping must survive shutdown: if ctx is already done, the
	// job's fate is still written.
	bctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	now := w.Now()
	switch {
	case err == nil:
		if err := w.Queue.FinishIntake(bctx, job.ID, reportID, now); err != nil {
			log.Error("intake: processed, but could not mark the job done", "error", err)
			return false
		}
		log.Info("intake: done", "report_id", reportID)
	case ctx.Err() != nil:
		// Shutting down is not the job's fault: no attempt is held
		// against it beyond the one already counted.
		if err := w.Queue.RetryIntake(bctx, job.ID, "interrupted by shutdown", now, now); err != nil {
			log.Error("intake: could not requeue an interrupted job", "error", err)
		}
		return false
	default:
		// The reason is printable and bounded before it is logged or
		// stored: it can carry text from a remote server.
		reason := report.Printable(err.Error())
		var perm permanentError
		if errors.As(err, &perm) || job.Attempts > len(w.Backoff) {
			if err := w.Queue.FailIntake(bctx, job.ID, reason, now); err != nil {
				log.Error("intake: could not mark the job failed", "error", err)
				return false
			}
			log.Error("intake: failed for good", "reason", reason)
		} else {
			retryAt := now.Add(w.Backoff[job.Attempts-1])
			if err := w.Queue.RetryIntake(bctx, job.ID, reason, retryAt, now); err != nil {
				log.Error("intake: could not schedule a retry", "error", err)
				return false
			}
			log.Warn("intake: failed, will retry", "reason", reason, "retry_at", retryAt.UTC().Format(time.RFC3339))
		}
	}
	return true
}
