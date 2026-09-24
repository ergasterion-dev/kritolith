package dedupe

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
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
	savePrior(t, s, report.Report{ID: id, Repo: repo}, report.OutcomeInconclusive, claims)
}

// savePrior saves r (ReceivedAt filled in) with a verdict of outcome
// carrying claims, as pipeline.Run would have for an earlier report.
func savePrior(t *testing.T, s *store.Store, r report.Report, outcome report.Outcome, claims []report.Claim) {
	t.Helper()
	ctx := context.Background()
	r.ReceivedAt = time.Now()
	if err := s.SaveReport(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveVerdict(ctx, report.Verdict{ReportID: r.ID, Outcome: outcome, Claims: claims}); err != nil {
		t.Fatal(err)
	}
}

func TestServiceDedupeExactFingerprintMatch(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	defer s.Close()

	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*parser).peek", Verified: report.TriYes, DeclPkgDir: "yaml", DeclReceiver: "parser", DeclName: "peek"},
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
	if want := "fingerprint match: parser.peek (out-of-bounds read) in yaml"; matches[0].Evidence != want {
		t.Errorf("Evidence = %q, want %q", matches[0].Evidence, want)
	}
}

func TestServiceDedupeEmptyStoreNoMatch(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	defer s.Close()

	svc := NewService(s, nil)
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*T).M", Verified: report.TriYes},
		{Kind: report.ClaimVulnClass, Value: "race", Verified: report.TriUnknown},
	}
	matches, exact := svc.Dedupe(ctx, report.Report{ID: "first", Repo: "owner/repo"}, claims, "")
	if exact {
		t.Error("want exact = false when the store has no prior reports")
	}
	if len(matches) != 0 {
		t.Errorf("matches = %+v, want none", matches)
	}
}

func TestServiceDedupeUnresolvedClaimNeverMatches(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	defer s.Close()

	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "Read", Verified: report.TriYes}, // no Decl* fields: unresolved or ambiguous
		{Kind: report.ClaimVulnClass, Value: "race", Verified: report.TriUnknown},
	}
	saveReportWithClaims(t, s, "prior", "owner/repo", claims)

	svc := NewService(s, nil)
	matches, exact := svc.Dedupe(ctx, report.Report{ID: "new", Repo: "owner/repo"}, claims, "")
	if exact || len(matches) != 0 {
		t.Errorf("matches = %+v, exact = %v; two reports sharing a claim with no resolved declaration identity must never match", matches, exact)
	}
}

func TestServiceDedupeBareNameMatchesWhenUniquelyResolved(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	defer s.Close()

	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "isOriginAllowed", Verified: report.TriYes, DeclPkgDir: "rest/internal/cors", DeclName: "isOriginAllowed"},
		{Kind: report.ClaimVulnClass, Value: "CORS misconfiguration", Verified: report.TriUnknown},
	}
	saveReportWithClaims(t, s, "prior", "owner/repo", claims)

	svc := NewService(s, nil)
	matches, exact := svc.Dedupe(ctx, report.Report{ID: "new", Repo: "owner/repo"}, claims, "")
	if !exact || len(matches) != 1 || matches[0].ReportID != "prior" {
		t.Fatalf("matches = %+v, exact = %v; a bare-name claim resolved to one unambiguous declaration must fingerprint-match", matches, exact)
	}
}

func TestServiceDedupeDegradesOnClosedStore(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	s.Close() // force every query the Service makes to fail

	svc := NewService(s, nil)
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*T).M", Verified: report.TriYes, DeclPkgDir: "pkg", DeclReceiver: "T", DeclName: "M"},
		{Kind: report.ClaimVulnClass, Value: "race", Verified: report.TriUnknown},
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

	savePrior(t, s, report.Report{ID: "prior", Repo: "owner/repo"}, report.OutcomeInconclusive, nil)
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
	if want := "embedding similarity 1.00 (lead only)"; matches[0].Evidence != want {
		t.Errorf("Evidence = %q, want %q", matches[0].Evidence, want)
	}

	// The new report's own embedding must now be stored too.
	stored, err := s.EmbeddingsByRepo(ctx, "owner/repo", "prior", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := stored["new"]; !ok {
		t.Error("Dedupe must save the current report's own embedding for future comparisons")
	}
}

func TestServiceDedupeOSVBareNameNeverMatches(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	defer s.Close()

	// A bare-name symbol ("Read", no qualifier) in the OSV mirror. The
	// design spec (see fingerprint.go) treats a bare name as too easily
	// a stdlib or dependency symbol to anchor an identity claim on; the
	// OSV branch must apply the same guard the fingerprint branch does.
	raw := []byte(`{"affected":[{"ecosystem_specific":{"imports":[{"symbols":["Read"]}]}}]}`)
	if _, err := s.UpsertOSVEntry(ctx, "GHSA-osv-bare", "example.com/mod", "2024-01-01T00:00:00Z", raw); err != nil {
		t.Fatal(err)
	}

	svc := NewService(s, nil)
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "Read", Verified: report.TriYes},
	}
	matches, exact := svc.Dedupe(ctx, report.Report{ID: "new", Repo: "owner/repo"}, claims, "example.com/mod")
	if exact || len(matches) != 0 {
		t.Errorf("matches = %+v, exact = %v; a bare function name must never match an OSV symbol", matches, exact)
	}
}

const osvPeekAdvisory = `{"affected":[{"ecosystem_specific":{"imports":[{"symbols":["parser.peek"]}]}}]}`

func TestServiceDedupeOSVMatchIsLeadOnly(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	defer s.Close()

	if _, err := s.UpsertOSVEntry(ctx, "GO-2022-0603", "gopkg.in/yaml.v3", "2024-01-01T00:00:00Z", []byte(osvPeekAdvisory)); err != nil {
		t.Fatal(err)
	}

	svc := NewService(s, nil)
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*parser).peek", Verified: report.TriYes},
		{Kind: report.ClaimVulnClass, Value: "out-of-bounds read", Verified: report.TriUnknown},
	}
	matches, exact := svc.Dedupe(ctx, report.Report{ID: "new", Repo: "go-yaml/yaml"}, claims, "gopkg.in/yaml.v3")
	if exact {
		t.Error("an OSV symbol match alone must never set exact = true: it checks neither affected versions nor vuln_class")
	}
	if len(matches) != 1 || matches[0].AdvisoryID != "GO-2022-0603" || matches[0].ReportID != "" {
		t.Fatalf("matches = %+v, want one OSV lead on GO-2022-0603", matches)
	}
	if ev := matches[0].Evidence; !strings.Contains(ev, "OSV symbol match: parser.peek") || !strings.Contains(ev, "GO-2022-0603") {
		t.Errorf("Evidence = %q, want it to name the matched symbol and advisory", ev)
	}
}

func TestServiceDedupeFingerprintStillExactAlongsideOSVLead(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	defer s.Close()

	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*parser).peek", Verified: report.TriYes, DeclPkgDir: "yaml", DeclReceiver: "parser", DeclName: "peek"},
		{Kind: report.ClaimVulnClass, Value: "out-of-bounds read", Verified: report.TriUnknown},
	}
	saveReportWithClaims(t, s, "prior", "go-yaml/yaml", claims)
	if _, err := s.UpsertOSVEntry(ctx, "GO-2022-0603", "gopkg.in/yaml.v3", "2024-01-01T00:00:00Z", []byte(osvPeekAdvisory)); err != nil {
		t.Fatal(err)
	}

	svc := NewService(s, nil)
	matches, exact := svc.Dedupe(ctx, report.Report{ID: "new", Repo: "go-yaml/yaml"}, claims, "gopkg.in/yaml.v3")
	if !exact {
		t.Error("a fingerprint match must still set exact = true")
	}
	if len(matches) != 2 || matches[0].ReportID != "prior" || matches[1].AdvisoryID != "GO-2022-0603" {
		t.Fatalf("matches = %+v, want the exact fingerprint match ranked before the OSV lead", matches)
	}
}

func TestServiceDedupeCollapsesMatchesPerIdentity(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	defer s.Close()

	// 2 function claims x 2 vuln_class claims = 4 matching fingerprint
	// pairs against the same prior report, and 2 claims hitting the
	// same OSV advisory.
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*parser).peek", Verified: report.TriYes, DeclPkgDir: "yaml", DeclReceiver: "parser", DeclName: "peek"},
		{Kind: report.ClaimFunction, Value: "parser.peek", Verified: report.TriYes, DeclPkgDir: "yaml", DeclReceiver: "parser", DeclName: "peek"},
		{Kind: report.ClaimFunction, Value: "(*parser).advance", Verified: report.TriYes, DeclPkgDir: "yaml", DeclReceiver: "parser", DeclName: "advance"},
		{Kind: report.ClaimVulnClass, Value: "out-of-bounds read", Verified: report.TriUnknown},
		{Kind: report.ClaimVulnClass, Value: "panic", Verified: report.TriUnknown},
	}
	saveReportWithClaims(t, s, "prior", "go-yaml/yaml", claims)
	saveReportWithClaims(t, s, "other", "go-yaml/yaml", []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*parser).advance", Verified: report.TriYes, DeclPkgDir: "yaml", DeclReceiver: "parser", DeclName: "advance"},
		{Kind: report.ClaimVulnClass, Value: "panic", Verified: report.TriUnknown},
	})
	if _, err := s.UpsertOSVEntry(ctx, "GO-2022-0603", "gopkg.in/yaml.v3", "2024-01-01T00:00:00Z", []byte(osvPeekAdvisory)); err != nil {
		t.Fatal(err)
	}

	svc := NewService(s, nil)
	matches, exact := svc.Dedupe(ctx, report.Report{ID: "new", Repo: "go-yaml/yaml"}, claims, "gopkg.in/yaml.v3")
	if !exact {
		t.Fatal("want exact = true")
	}
	seen := map[string]int{}
	for _, m := range matches {
		seen[m.ReportID+"|"+m.AdvisoryID]++
	}
	if len(matches) != 3 || seen["prior|"] != 1 || seen["other|"] != 1 || seen["|GO-2022-0603"] != 1 {
		t.Fatalf("matches = %+v, want exactly one entry each for prior, other, and GO-2022-0603", matches)
	}
}

func TestServiceDedupeDeterministicOrder(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	defer s.Close()

	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*T).M", Verified: report.TriYes, DeclPkgDir: "pkg", DeclReceiver: "T", DeclName: "M"},
		{Kind: report.ClaimVulnClass, Value: "race", Verified: report.TriUnknown},
	}
	// Five equally-scored exact matches: which three survive, and in
	// what order, must not depend on map iteration order.
	for _, id := range []string{"e", "c", "a", "d", "b"} {
		saveReportWithClaims(t, s, id, "owner/repo", claims)
	}

	svc := NewService(s, nil)
	first, _ := svc.Dedupe(ctx, report.Report{ID: "new", Repo: "owner/repo"}, claims, "")
	if len(first) != 3 || first[0].ReportID != "a" || first[1].ReportID != "b" || first[2].ReportID != "c" {
		t.Fatalf("matches = %+v, want a, b, c (score tie broken by ID)", first)
	}
	for i := 0; i < 20; i++ {
		again, _ := svc.Dedupe(ctx, report.Report{ID: "new", Repo: "owner/repo"}, claims, "")
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("run %d: matches = %+v, want identical to first run %+v", i, again, first)
		}
	}
}

func TestServiceDedupeSameSourceRefNeverSelfMatches(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	defer s.Close()

	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*T).M", Verified: report.TriYes, DeclPkgDir: "pkg", DeclReceiver: "T", DeclName: "M"},
		{Kind: report.ClaimVulnClass, Value: "race", Verified: report.TriUnknown},
	}
	const path = "/corpus/real/a/report.md"
	savePrior(t, s, report.Report{ID: "first-run", Source: report.SourceFile, SourceRef: path, Repo: "owner/repo"}, report.OutcomeInconclusive, claims)

	svc := NewService(s, nil)
	matches, exact := svc.Dedupe(ctx, report.Report{ID: "second-run", Source: report.SourceFile, SourceRef: path, Repo: "owner/repo"}, claims, "")
	if exact || len(matches) != 0 {
		t.Errorf("matches = %+v, exact = %v; a re-run of the same report must never match its own earlier run", matches, exact)
	}
}

func TestServiceDedupeRejectedPriorNeverAnchors(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	defer s.Close()

	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*T).M", Verified: report.TriYes, DeclPkgDir: "pkg", DeclReceiver: "T", DeclName: "M"},
		{Kind: report.ClaimVulnClass, Value: "race", Verified: report.TriUnknown},
	}
	savePrior(t, s, report.Report{ID: "fabricated", Repo: "owner/repo"}, report.OutcomeGroundingFailed, claims)

	svc := NewService(s, nil)
	matches, exact := svc.Dedupe(ctx, report.Report{ID: "new", Repo: "owner/repo"}, claims, "")
	if exact || len(matches) != 0 {
		t.Errorf("matches = %+v, exact = %v; a GROUNDING_FAILED prior report must never anchor a duplicate match", matches, exact)
	}
}

func TestServiceImplementsDeduper(t *testing.T) {
	var _ Deduper = (*Service)(nil)
}
