package jobs

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/store"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func setup(t *testing.T, p Process) (*store.Store, *Worker, *clock) {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	c := &clock{t: time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)}
	w := NewWorker(s, p, slog.New(slog.NewTextHandler(io.Discard, nil)))
	w.Now = c.Now
	w.Backoff = []time.Duration{time.Minute, 5 * time.Minute}
	return s, w, c
}

func enqueue(t *testing.T, s *store.Store, c *clock, id string) {
	t.Helper()
	if _, err := s.EnqueueIntake(context.Background(), "github", "a/b", id, c.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerProcessesInOrder(t *testing.T) {
	var seen []string
	s, w, c := setup(t, func(ctx context.Context, j store.IntakeJob) (string, error) {
		seen = append(seen, j.ExternalID)
		return "R-" + j.ExternalID, nil
	})
	enqueue(t, s, c, "one")
	c.Advance(time.Second)
	enqueue(t, s, c, "two")
	c.Advance(time.Second)
	for w.runOne(context.Background()) {
	}
	if len(seen) != 2 || seen[0] != "one" || seen[1] != "two" {
		t.Fatalf("processed %v", seen)
	}
	j, err := s.GetIntake(context.Background(), 1)
	if err != nil || j.State != store.IntakeDone || j.ReportID != "R-one" {
		t.Fatalf("job 1 = %+v, %v", j, err)
	}
}

func TestWorkerRetriesThenGivesUp(t *testing.T) {
	calls := 0
	s, w, c := setup(t, func(ctx context.Context, j store.IntakeJob) (string, error) {
		calls++
		return "", errors.New("upstream \x1b[31mdown\nsecond line")
	})
	enqueue(t, s, c, "x")
	ctx := context.Background()

	w.runOne(ctx)
	j, _ := s.GetIntake(ctx, 1)
	if j.State != store.IntakeQueued || j.Attempts != 1 || !j.RunAfter.Equal(c.Now().Add(time.Minute)) {
		t.Fatalf("after first failure: %+v", j)
	}
	if j.LastError != "upstream �[31mdown�second line" {
		t.Errorf("stored reason = %q, want it made printable", j.LastError)
	}
	// Not due yet: nothing happens.
	if w.runOne(ctx); calls != 1 {
		t.Fatalf("retried before the backoff passed (calls = %d)", calls)
	}
	c.Advance(time.Minute)
	w.runOne(ctx)
	if j, _ = s.GetIntake(ctx, 1); j.Attempts != 2 || !j.RunAfter.Equal(c.Now().Add(5*time.Minute)) {
		t.Fatalf("after second failure: %+v", j)
	}
	c.Advance(5 * time.Minute)
	w.runOne(ctx)
	if j, _ = s.GetIntake(ctx, 1); j.State != store.IntakeFailed || j.Attempts != 3 {
		t.Fatalf("after the last attempt: %+v", j)
	}
	c.Advance(24 * time.Hour)
	if w.runOne(ctx); calls != 3 {
		t.Fatalf("a failed job ran again (calls = %d)", calls)
	}
}

func TestWorkerPermanentErrorIsNotRetried(t *testing.T) {
	calls := 0
	s, w, c := setup(t, func(ctx context.Context, j store.IntakeJob) (string, error) {
		calls++
		return "", Permanent(errors.New("not found"))
	})
	enqueue(t, s, c, "x")
	w.runOne(context.Background())
	c.Advance(24 * time.Hour)
	w.runOne(context.Background())
	j, _ := s.GetIntake(context.Background(), 1)
	if calls != 1 || j.State != store.IntakeFailed || j.LastError != "not found" {
		t.Fatalf("calls = %d, job = %+v", calls, j)
	}
}

func TestWorkerShutdownGivesTheJobBack(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	s, w, c := setup(t, func(ctx context.Context, j store.IntakeJob) (string, error) {
		close(started)
		<-ctx.Done()
		return "", ctx.Err()
	})
	enqueue(t, s, c, "x")
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	<-started
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the worker did not stop")
	}
	j, _ := s.GetIntake(context.Background(), 1)
	if j.State != store.IntakeQueued || j.LastError != "interrupted by shutdown" {
		t.Fatalf("interrupted job = %+v, want it queued again", j)
	}
}

func TestWorkerRunWakesAndRecoversRunningJobs(t *testing.T) {
	processed := make(chan string, 4)
	s, w, c := setup(t, func(ctx context.Context, j store.IntakeJob) (string, error) {
		processed <- j.ExternalID
		return "R", nil
	})
	w.Poll = time.Hour // only Wake or startup can trigger a look
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A job a dead process left "running" is picked up at startup.
	enqueue(t, s, c, "orphan")
	if j, err := s.ClaimIntake(ctx, c.Now()); err != nil || j == nil {
		t.Fatal("test setup: could not claim")
	}
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	expect := func(want string) {
		t.Helper()
		select {
		case got := <-processed:
			if got != want {
				t.Fatalf("processed %q, want %q", got, want)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%q was never processed", want)
		}
	}
	expect("orphan")
	enqueue(t, s, c, "fresh")
	w.Wake()
	expect("fresh")
	cancel()
	<-done
}
