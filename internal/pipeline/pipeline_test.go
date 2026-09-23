package pipeline

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/report"
	"github.com/ergasterion-dev/kritolith/internal/store"
)

type fakeStore struct {
	calls      []string
	reportErr  error
	verdictErr error
}

func (f *fakeStore) SaveReport(_ context.Context, r report.Report) error {
	f.calls = append(f.calls, "report:"+r.ID)
	return f.reportErr
}

func (f *fakeStore) SaveVerdict(_ context.Context, v report.Verdict) error {
	f.calls = append(f.calls, "verdict:"+string(v.Outcome))
	return f.verdictErr
}

func TestRunOrderAndOutcome(t *testing.T) {
	fs := &fakeStore{}
	v, err := New(fs).Run(context.Background(), report.Report{ID: "R1", Repo: "a/b", ClaimedRef: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Outcome != report.OutcomeInconclusive {
		t.Errorf("outcome = %s", v.Outcome)
	}
	if len(fs.calls) != 2 || fs.calls[0] != "report:R1" || fs.calls[1] != "verdict:INCONCLUSIVE" {
		t.Errorf("calls = %v", fs.calls)
	}
}

func TestRunStoreError(t *testing.T) {
	fs := &fakeStore{reportErr: errors.New("disk full")}
	_, err := New(fs).Run(context.Background(), report.Report{ID: "R1"})
	if err == nil {
		t.Fatal("want error")
	}
	if !strings.Contains(err.Error(), "save report:") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "save report:")
	}
	if len(fs.calls) != 1 {
		t.Errorf("verdict saved after report failed: %v", fs.calls)
	}
}

func TestRunVerdictSaveError(t *testing.T) {
	fs := &fakeStore{verdictErr: errors.New("disk full")}
	_, err := New(fs).Run(context.Background(), report.Report{ID: "R1"})
	if err == nil {
		t.Fatal("want error")
	}
	if !strings.Contains(err.Error(), "save verdict:") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "save verdict:")
	}
}

func TestRunWithSQLite(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := report.Report{ID: "01ARYZ6S410000000000000000", Source: report.SourceFile, Repo: "a/b"}
	if _, err := New(s).Run(ctx, r); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetVerdict(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != report.OutcomeNeedsInfo {
		t.Errorf("stored outcome = %s, want NEEDS_INFO", got.Outcome)
	}
}
