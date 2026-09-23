// Package pipeline runs a report through Kritolith's stages and stores
// the result. Later milestones add extract, ground, dedupe and sandbox
// between saving the report and composing the verdict.
package pipeline

import (
	"context"
	"fmt"

	"github.com/ergasterion-dev/kritolith/internal/report"
	"github.com/ergasterion-dev/kritolith/internal/verdict"
)

// Store is the persistence the pipeline needs.
type Store interface {
	SaveReport(ctx context.Context, r report.Report) error
	SaveVerdict(ctx context.Context, v report.Verdict) error
}

// Pipeline processes reports.
type Pipeline struct {
	store Store
}

// New returns a Pipeline that persists to s.
func New(s Store) *Pipeline { return &Pipeline{store: s} }

// Run stores the report, composes its verdict and stores that too.
func (p *Pipeline) Run(ctx context.Context, r report.Report) (report.Verdict, error) {
	if err := p.store.SaveReport(ctx, r); err != nil {
		return report.Verdict{}, fmt.Errorf("pipeline: %w", err)
	}
	v := verdict.Compose(r)
	if err := p.store.SaveVerdict(ctx, v); err != nil {
		return report.Verdict{}, fmt.Errorf("pipeline: %w", err)
	}
	return v, nil
}
