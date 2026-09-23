package ground

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// Grounder is what pipeline.Run needs from this package. It never
// returns an error: a grounding failure (unreachable repo, a
// clone/fetch error, a git error) degrades to refResolved=false, the
// same signal as a ref that simply never resolved — Compose already
// treats that as NEEDS_INFO, never a rejection.
type Grounder interface {
	Ground(ctx context.Context, r report.Report, claims []report.Claim) (grounded []report.Claim, refResolved bool, resolvedRef string)
}

// Service grounds reports against git mirrors rooted at dataDir,
// cloned from GitHub over HTTPS by default.
type Service struct {
	dataDir   string
	originURL func(repo string) string // overridable in tests; defaults to githubOriginURL
}

// NewService returns a Service that keeps its git mirrors under
// dataDir.
func NewService(dataDir string) *Service {
	return &Service{dataDir: dataDir, originURL: githubOriginURL}
}

// Ground implements Grounder. Any failure (a bad data dir, a
// clone/fetch error, a git error) is logged at Warn — with the report
// ID and repo, never claim content — and degrades to
// (claims unchanged, false, "") rather than surfacing as an error.
func (s *Service) Ground(ctx context.Context, r report.Report, claims []report.Claim) ([]report.Claim, bool, string) {
	m, err := OpenMirror(s.dataDir, r.Repo, s.originURL(r.Repo))
	if err != nil {
		slog.Default().Warn("grounding: could not open mirror, degrading to ungrounded claims",
			"report_id", r.ID, "repo", r.Repo, "error", err)
		return claims, false, ""
	}
	grounded, resolved, commit, err := groundClaims(ctx, m, r, claims)
	if err != nil {
		slog.Default().Warn("grounding failed, degrading to ungrounded claims",
			"report_id", r.ID, "repo", r.Repo, "error", err)
		return claims, false, ""
	}
	return grounded, resolved, commit
}

func githubOriginURL(repo string) string {
	return fmt.Sprintf("https://github.com/%s.git", repo)
}
