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
	// by rank (one per matched report or advisory), and whether any
	// of them is an exact-tier match — a fingerprint match against a
	// prior report, the only signal strong enough to set Outcome to
	// LIKELY_DUPLICATE. OSV symbol and embedding matches are leads.
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

// osvLeadScore is the score of an OSV symbol lead. It's still a
// genuine exact textual symbol match, so it ranks alongside other
// strong leads — but candidate ranking puts every exact-tier
// (fingerprint) match ahead of it regardless of score.
const osvLeadScore = 1.0

// candidate is one DupMatch plus whether it came from the exact tier —
// used only for ranking, so an Outcome-setting fingerprint match always
// survives the top-3 cut ahead of a same-score lead.
type candidate struct {
	match report.DupMatch
	exact bool
}

// Dedupe implements Deduper.
func (s *Service) Dedupe(ctx context.Context, r report.Report, claims []report.Claim, module string) ([]report.DupMatch, bool) {
	var candidates []candidate
	exact := false

	if mine := claimFingerprints(r.Repo, claims); len(mine) > 0 {
		if prior, err := s.store.ClaimsByRepo(ctx, r.Repo, r.ID, r.SourceRef); err != nil {
			slog.Default().Warn("dedupe: could not load prior claims, skipping fingerprint match",
				"report_id", r.ID, "error", err)
		} else {
			for reportID, cs := range prior {
				theirs := claimFingerprints(r.Repo, cs)
				for _, a := range mine {
					for _, b := range theirs {
						if a.matches(b) {
							candidates = append(candidates, candidate{
								match: report.DupMatch{
									ReportID: reportID,
									Score:    1.0,
									Evidence: fmt.Sprintf("fingerprint match: %s.%s (%s)", func() string {
										if a.receiver != "" {
											return a.receiver
										}
										return a.pkgDir
									}(), a.name, a.vulnClass),
								},
								exact: true,
							})
							exact = true
						}
					}
				}
			}
		}
	}

	// An OSV symbol hit is a lead only, never exact: matchesOSVSymbol
	// checks neither the advisory's affected version ranges against
	// the claimed ref (a ref past the fix is a different bug by
	// definition) nor the vuln_class, and accepts a bare-name symbol
	// under any qualifier. Until it does, a public entry point that
	// merely appears in some advisory must not set Outcome.
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
						candidates = append(candidates, candidate{match: report.DupMatch{
							AdvisoryID: e.ID,
							Score:      osvLeadScore,
							Evidence: fmt.Sprintf("OSV symbol match: %s.%s (%s); lead only, affected versions not checked",
								qualifier, name, e.ID),
						}})
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
						candidates = append(candidates, candidate{match: report.DupMatch{
							ReportID: reportID,
							Score:    score,
							Evidence: fmt.Sprintf("embedding similarity %.2f (lead only)", score),
						}})
					}
				}
			}
			if err := s.store.SaveEmbedding(ctx, r.ID, model, vec); err != nil {
				slog.Default().Warn("dedupe: could not save embedding", "report_id", r.ID, "error", err)
			}
		}
	}

	return topMatches(candidates, 3), exact
}

// topMatches collapses candidates to one per identity (ReportID,
// AdvisoryID) — keeping the best-ranked entry, and its evidence — then
// returns at most n of them in rank order. Without the collapse, one
// prior report matching on several claim pairs could fill every slot
// and push out a genuinely different duplicate.
//
// Ranking is total, so identical inputs always yield identical output
// regardless of the map iteration order the candidates were built in:
// exact-tier first, then score descending, then ReportID, AdvisoryID
// and Evidence ascending.
func topMatches(candidates []candidate, n int) []report.DupMatch {
	type identity struct{ reportID, advisoryID string }
	best := map[identity]candidate{}
	for _, c := range candidates {
		id := identity{c.match.ReportID, c.match.AdvisoryID}
		if cur, ok := best[id]; !ok || rankBefore(c, cur) {
			best[id] = c
		}
	}
	unique := make([]candidate, 0, len(best))
	for _, c := range best {
		unique = append(unique, c)
	}
	sort.SliceStable(unique, func(i, j int) bool { return rankBefore(unique[i], unique[j]) })
	if len(unique) > n {
		unique = unique[:n]
	}
	var out []report.DupMatch
	for _, c := range unique {
		out = append(out, c.match)
	}
	return out
}

// rankBefore reports whether a ranks strictly ahead of b.
func rankBefore(a, b candidate) bool {
	if a.exact != b.exact {
		return a.exact
	}
	if a.match.Score != b.match.Score {
		return a.match.Score > b.match.Score
	}
	if a.match.ReportID != b.match.ReportID {
		return a.match.ReportID < b.match.ReportID
	}
	if a.match.AdvisoryID != b.match.AdvisoryID {
		return a.match.AdvisoryID < b.match.AdvisoryID
	}
	return a.match.Evidence < b.match.Evidence
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
