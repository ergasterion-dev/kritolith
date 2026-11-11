package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIntakeQueue(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	t0 := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

	if j, err := s.ClaimIntake(ctx, t0); err != nil || j != nil {
		t.Fatalf("empty queue: %+v, %v", j, err)
	}
	for i, want := range []bool{true, false} { // the second is a redelivery
		created, err := s.EnqueueIntake(ctx, "github", "a/b", "GHSA-aaaa-bbbb-cccc", t0)
		if err != nil || created != want {
			t.Fatalf("enqueue %d: created %v, err %v", i, created, err)
		}
	}
	if created, err := s.EnqueueIntake(ctx, "github", "a/b", "GHSA-2222-3333-4444", t0.Add(time.Second)); err != nil || !created {
		t.Fatalf("second job: %v, %v", created, err)
	}
	// The same ID on another repository is a different report.
	if created, err := s.EnqueueIntake(ctx, "github", "c/d", "GHSA-aaaa-bbbb-cccc", t0.Add(2*time.Second)); err != nil || !created {
		t.Fatalf("same id, other repo: %v, %v", created, err)
	}

	// Not due yet.
	if j, _ := s.ClaimIntake(ctx, t0.Add(-time.Minute)); j != nil {
		t.Fatalf("claimed a job before it was due: %+v", j)
	}
	j1, err := s.ClaimIntake(ctx, t0.Add(time.Minute))
	if err != nil || j1 == nil || j1.ExternalID != "GHSA-aaaa-bbbb-cccc" || j1.Repo != "a/b" || j1.Attempts != 1 {
		t.Fatalf("first claim: %+v, %v", j1, err)
	}
	j2, err := s.ClaimIntake(ctx, t0.Add(time.Minute))
	if err != nil || j2 == nil || j2.ExternalID != "GHSA-2222-3333-4444" {
		t.Fatalf("second claim: %+v, %v", j2, err)
	}

	// Done jobs stay done, and a redelivery of one is still ignored.
	if err := s.FinishIntake(ctx, j1.ID, "R1", t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetIntake(ctx, j1.ID); got.State != IntakeDone || got.ReportID != "R1" {
		t.Fatalf("finished job: %+v", got)
	}
	if created, _ := s.EnqueueIntake(ctx, "github", "a/b", "GHSA-aaaa-bbbb-cccc", t0.Add(time.Hour)); created {
		t.Fatal("a redelivery of a finished report was queued again")
	}

	// A retry is not due until its time, then comes back with the
	// attempt counted and the reason kept (bounded).
	retryAt := t0.Add(10 * time.Minute)
	if err := s.RetryIntake(ctx, j2.ID, strings.Repeat("x", 2000), retryAt, t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetIntake(ctx, j2.ID); got.State != IntakeQueued || len(got.LastError) != maxIntakeError || !got.RunAfter.Equal(retryAt) {
		t.Fatalf("retried job: state %s, error length %d, run after %v", got.State, len(got.LastError), got.RunAfter)
	}
	j3, _ := s.ClaimIntake(ctx, t0.Add(5*time.Minute)) // only c/d is due
	if j3 == nil || j3.Repo != "c/d" {
		t.Fatalf("claim while a retry waits: %+v", j3)
	}
	again, _ := s.ClaimIntake(ctx, retryAt)
	if again == nil || again.ID != j2.ID || again.Attempts != 2 {
		t.Fatalf("retry claim: %+v", again)
	}
	if err := s.FailIntake(ctx, again.ID, "gave up", retryAt); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetIntake(ctx, again.ID); got.State != IntakeFailed || got.LastError != "gave up" {
		t.Fatalf("failed job: %+v", got)
	}

	// j3 is still "running": a restart puts it back.
	n, err := s.RequeueRunningIntake(ctx, t0.Add(time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("requeue: %d, %v", n, err)
	}
	back, _ := s.ClaimIntake(ctx, t0.Add(time.Hour))
	if back == nil || back.ID != j3.ID || back.Attempts != 2 {
		t.Fatalf("after restart: %+v", back)
	}
	if j, _ := s.ClaimIntake(ctx, t0.Add(100*time.Hour)); j != nil {
		t.Fatalf("queue should be empty: %+v", j)
	}
}
