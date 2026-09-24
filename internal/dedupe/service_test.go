package dedupe

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/llm"
	"github.com/ergasterion-dev/kritolith/internal/report"
	"github.com/ergasterion-dev/kritolith/internal/store"
)

// openTemp opens a Store in a fresh subdirectory of t.TempDir(). It
// joins a not-yet-existing "data" subdirectory (mirroring
// internal/store's own openTemp test helper) rather than passing
// t.TempDir() directly to store.Open: store.Open only enforces its
// 0700 private-dir check on a directory that already exists, and
// t.TempDir() itself is not guaranteed to be created with mode 0700.
func openTemp(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func saveReportWithClaims(t *testing.T, s *store.Store, id, repo string, claims []report.Claim) {
	t.Helper()
	ctx := context.Background()
	if err := s.SaveReport(ctx, report.Report{ID: id, Repo: repo, ReceivedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveVerdict(ctx, report.Verdict{ReportID: id, Outcome: report.OutcomeInconclusive, Claims: claims}); err != nil {
		t.Fatal(err)
	}
}

func TestServiceDedupeExactFingerprintMatch(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	defer s.Close()

	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*parser).peek", Verified: report.TriYes},
		{Kind: report.ClaimVulnClass, Value: "out-of-bounds read", Verified: report.TriUnknown},
	}
	saveReportWithClaims(t, s, "prior", "go-yaml/yaml", claims)

	svc := NewService(s, nil)
	matches, exact := svc.Dedupe(ctx, report.Report{ID: "new", Repo: "go-yaml/yaml"}, claims, "")
	if !exact {
		t.Fatal("want exact = true for an identical fingerprint")
	}
	if len(matches) != 1 || matches[0].ReportID != "prior" || matches[0].Score != 1.0 {
		t.Fatalf("matches = %+v, want a single exact match on report \"prior\"", matches)
	}
}

func TestServiceDedupeEmptyStoreNoMatch(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	defer s.Close()

	svc := NewService(s, nil)
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*T).M", Verified: report.TriYes},
		{Kind: report.ClaimVulnClass, Value: "race"},
	}
	matches, exact := svc.Dedupe(ctx, report.Report{ID: "first", Repo: "owner/repo"}, claims, "")
	if exact {
		t.Error("want exact = false when the store has no prior reports")
	}
	if len(matches) != 0 {
		t.Errorf("matches = %+v, want none", matches)
	}
}

func TestServiceDedupeBareNameNeverMatches(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	defer s.Close()

	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "Read", Verified: report.TriYes},
		{Kind: report.ClaimVulnClass, Value: "race", Verified: report.TriUnknown},
	}
	saveReportWithClaims(t, s, "prior", "owner/repo", claims)

	svc := NewService(s, nil)
	matches, exact := svc.Dedupe(ctx, report.Report{ID: "new", Repo: "owner/repo"}, claims, "")
	if exact || len(matches) != 0 {
		t.Errorf("matches = %+v, exact = %v; two reports sharing only a bare function name must never match", matches, exact)
	}
}

func TestServiceDedupeDegradesOnClosedStore(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	s.Close() // force every query the Service makes to fail

	svc := NewService(s, nil)
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*T).M", Verified: report.TriYes},
		{Kind: report.ClaimVulnClass, Value: "race"},
	}
	matches, exact := svc.Dedupe(ctx, report.Report{ID: "r", Repo: "owner/repo"}, claims, "")
	if exact || len(matches) != 0 {
		t.Errorf("matches = %+v, exact = %v; a closed store must degrade to no matches, not panic or error out", matches, exact)
	}
}

// fakeEmbedProvider is a test-only llm.Provider that returns a fixed
// vector per input text, so embedding similarity can be tested without
// a real network call.
type fakeEmbedProvider struct {
	vecs map[string][]float32
}

func (f *fakeEmbedProvider) Complete(context.Context, llm.CompleteRequest) (llm.CompleteResponse, error) {
	return llm.CompleteResponse{}, errors.New("fakeEmbedProvider: Complete not implemented")
}

func (f *fakeEmbedProvider) Embed(_ context.Context, texts []string) ([][]float32, error) {
	out := make([][]float32, len(texts))
	for i, t := range texts {
		v, ok := f.vecs[t]
		if !ok {
			return nil, errors.New("fakeEmbedProvider: no fixture vector for text")
		}
		out[i] = v
	}
	return out, nil
}

func (f *fakeEmbedProvider) Name() string  { return "fake-embed" }
func (f *fakeEmbedProvider) IsLocal() bool { return true }

func TestServiceDedupeEmbeddingLeadNeverSetsExact(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	defer s.Close()

	if err := s.SaveReport(ctx, report.Report{ID: "prior", Repo: "owner/repo", ReceivedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEmbedding(ctx, "prior", "fake-embed", []float32{1, 0, 0}); err != nil {
		t.Fatal(err)
	}

	provider := &fakeEmbedProvider{vecs: map[string][]float32{"title\n\nbody": {1, 0, 0}}}
	router := llm.NewRouter(map[string]llm.Provider{"p": provider}, map[string][]string{"embed": {"p"}}, nil, nil)
	svc := NewService(s, router)

	r := report.Report{ID: "new", Repo: "owner/repo", Title: "title", Body: "body"}
	// Dedupe saves r's own embedding once it computes one, and
	// embeddings.report_id has a foreign key on reports(id): the report
	// itself must already be saved, exactly as it would be by intake
	// before the pipeline reaches the dedupe stage.
	if err := s.SaveReport(ctx, r); err != nil {
		t.Fatal(err)
	}
	matches, exact := svc.Dedupe(ctx, r, nil, "")
	if exact {
		t.Error("an embedding-only match must never set exact = true")
	}
	if len(matches) != 1 || matches[0].ReportID != "prior" || matches[0].Score <= 0.99 {
		t.Fatalf("matches = %+v, want one high-similarity lead on \"prior\"", matches)
	}

	// The new report's own embedding must now be stored too.
	stored, err := s.EmbeddingsByRepo(ctx, "owner/repo", "prior")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := stored["new"]; !ok {
		t.Error("Dedupe must save the current report's own embedding for future comparisons")
	}
}

func TestServiceImplementsDeduper(t *testing.T) {
	var _ Deduper = (*Service)(nil)
}
