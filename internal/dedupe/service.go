package dedupe

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sort"

	"github.com/ergasterion-dev/kritolith/internal/ground"
	"github.com/ergasterion-dev/kritolith/internal/llm"
	"github.com/ergasterion-dev/kritolith/internal/report"
	"github.com/ergasterion-dev/kritolith/internal/store"
)

// Deduper is what pipeline.Run needs from this package. It never
// returns an error: any failure (a store error, an embed provider
// error) degrades the affected signal to "no matches from it," the
// same never-fail contract as ground.Grounder.
type Deduper interface {
	// Dedupe finds likely duplicates of r among past reports and the
	// local OSV mirror, and — when an embed provider is configured —
	// also records r's own embedding so future reports can match
	// against it. module is grounding's resolved go.mod module path
	// (StageResults.Module), used only for the OSV-mirror signal; pass
	// "" when ungrounded. It returns up to the top 3 candidate matches
	// by score, and whether any of them is an exact-tier match (the
	// only signal strong enough to set Outcome to LIKELY_DUPLICATE).
	Dedupe(ctx context.Context, r report.Report, claims []report.Claim, module string) (matches []report.DupMatch, exactMatch bool)
}

// embeddingMatchThreshold is deliberately conservative: an embedding
// lead is always recorded for maintainer visibility, but it must clear
// a high bar even to appear as a lead, and — per the design spec — it
// never sets Outcome on its own regardless of how high it scores.
const embeddingMatchThreshold = 0.93

// Service finds duplicates using st's claims, embeddings, and OSV
// mirror tables. router is nil-able: with no router, or no "embed"
// task chain configured on it, embedding similarity is simply skipped
// — Kritolith must work with no LLM configured.
type Service struct {
	store  *store.Store
	router *llm.Router
}

// NewService returns a Service backed by st, using router (nil-able)
// for the "embed" task.
func NewService(st *store.Store, router *llm.Router) *Service {
	return &Service{store: st, router: router}
}

// Dedupe implements Deduper.
func (s *Service) Dedupe(ctx context.Context, r report.Report, claims []report.Claim, module string) ([]report.DupMatch, bool) {
	var candidates []report.DupMatch
	exact := false

	if mine := claimFingerprints(r.Repo, claims); len(mine) > 0 {
		if prior, err := s.store.ClaimsByRepo(ctx, r.Repo, r.ID); err != nil {
			slog.Default().Warn("dedupe: could not load prior claims, skipping fingerprint match",
				"report_id", r.ID, "error", err)
		} else {
			for reportID, cs := range prior {
				theirs := claimFingerprints(r.Repo, cs)
				for _, a := range mine {
					for _, b := range theirs {
						if a.matches(b) {
							candidates = append(candidates, report.DupMatch{ReportID: reportID, Score: 1.0})
							exact = true
						}
					}
				}
			}
		}
	}

	if module != "" {
		if entries, err := s.store.OSVEntriesByModule(ctx, module); err != nil {
			slog.Default().Warn("dedupe: could not load OSV entries, skipping OSV match",
				"report_id", r.ID, "module", module, "error", err)
		} else {
			for _, c := range claims {
				if c.Kind != report.ClaimFunction || c.Verified != report.TriYes {
					continue
				}
				qualifier, name := ground.SplitFunctionClaim(c.Value)
				if qualifier == "" || name == "" {
					continue
				}
				for _, e := range entries {
					if matchesOSVSymbol(e.Raw, qualifier, name) {
						candidates = append(candidates, report.DupMatch{AdvisoryID: e.ID, Score: 1.0})
						exact = true
					}
				}
			}
		}
	}

	if s.router != nil {
		text := r.Title + "\n\n" + r.Body
		vec, model, err := embedText(ctx, s.router, r.ID, r.Repo, text)
		if err != nil {
			slog.Default().Warn("dedupe: embedding failed, skipping embedding match", "report_id", r.ID, "error", err)
		} else {
			if others, err := s.store.EmbeddingsByRepo(ctx, r.Repo, r.ID); err != nil {
				slog.Default().Warn("dedupe: could not load prior embeddings, skipping embedding match",
					"report_id", r.ID, "error", err)
			} else {
				for reportID, other := range others {
					if len(other.Vector) != len(vec) {
						continue // different model/dims: not comparable
					}
					if score := cosineSimilarity(vec, other.Vector); score >= embeddingMatchThreshold {
						candidates = append(candidates, report.DupMatch{ReportID: reportID, Score: score})
					}
				}
			}
			if err := s.store.SaveEmbedding(ctx, r.ID, model, vec); err != nil {
				slog.Default().Warn("dedupe: could not save embedding", "report_id", r.ID, "error", err)
			}
		}
	}

	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Score > candidates[j].Score })
	if len(candidates) > 3 {
		candidates = candidates[:3]
	}
	return candidates, exact
}

// embedText tries each provider in router's "embed" chain in order,
// returning the first success's vector and the provider name it came
// from — recorded alongside the vector so a later comparison can skip
// vectors from an incomparable model (see router.Chain's own doc
// comment on why callers needing this iterate the chain themselves).
func embedText(ctx context.Context, router *llm.Router, reportID, repo, text string) ([]float32, string, error) {
	var lastErr error
	for _, p := range router.Chain("embed", reportID, repo) {
		vecs, err := p.Embed(ctx, []string{text})
		if err != nil {
			lastErr = err
			continue
		}
		if len(vecs) == 0 {
			lastErr = fmt.Errorf("dedupe: %s: embed returned no vectors", p.Name())
			continue
		}
		return vecs[0], p.Name(), nil
	}
	if lastErr == nil {
		lastErr = llm.ErrNoProvider
	}
	return nil, "", lastErr
}

// cosineSimilarity returns the cosine similarity of a and b, or 0 if
// either is a zero vector.
func cosineSimilarity(a, b []float32) float64 {
	var dot, magA, magB float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		magA += float64(a[i]) * float64(a[i])
		magB += float64(b[i]) * float64(b[i])
	}
	if magA == 0 || magB == 0 {
		return 0
	}
	return dot / (math.Sqrt(magA) * math.Sqrt(magB))
}
