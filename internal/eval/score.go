package eval

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// CheckFunc runs one case through Kritolith and returns its outcome.
type CheckFunc func(ctx context.Context, c Case) (report.Outcome, error)

// Result is one case's outcome.
type Result struct {
	Case Case
	Got  report.Outcome
	Err  error
}

// Scoreboard summarizes an eval run.
type Scoreboard struct {
	Results []Result
}

// Run checks every case. A failing case is recorded, not fatal.
func Run(ctx context.Context, cases []Case, check CheckFunc) Scoreboard {
	var sb Scoreboard
	for _, c := range cases {
		got, err := check(ctx, c)
		sb.Results = append(sb.Results, Result{Case: c, Got: got, Err: err})
	}
	return sb
}

// Matches counts cases whose outcome equals the expected one.
func (s Scoreboard) Matches() int {
	n := 0
	for _, r := range s.Results {
		if r.Err == nil && r.Got == r.Case.Meta.Expected {
			n++
		}
	}
	return n
}

// RealGroundingFailures counts real reports wrongly marked
// GROUNDING_FAILED. The v1 requirement is zero.
func (s Scoreboard) RealGroundingFailures() int {
	n := 0
	for _, r := range s.Results {
		if r.Case.Kind == KindReal && r.Got == report.OutcomeGroundingFailed {
			n++
		}
	}
	return n
}

// RealLikelyDuplicates counts real reports wrongly marked
// LIKELY_DUPLICATE. The v1 requirement is zero, same discipline as
// RealGroundingFailures: a false duplicate flag is exactly as bad as a
// false grounding rejection.
func (s Scoreboard) RealLikelyDuplicates() int {
	n := 0
	for _, r := range s.Results {
		if r.Case.Kind == KindReal && r.Got == report.OutcomeLikelyDuplicate {
			n++
		}
	}
	return n
}

// FabricatedLikelyDuplicates counts fabricated cases that were NOT
// expecting LIKELY_DUPLICATE but got it anyway — a coincidental
// fingerprint or OSV collision between two unrelated fabricated cases,
// which would itself be a bug worth knowing about.
func (s Scoreboard) FabricatedLikelyDuplicates() int {
	n := 0
	for _, r := range s.Results {
		if r.Case.Kind == KindFabricated && r.Case.Meta.Expected != report.OutcomeLikelyDuplicate && r.Got == report.OutcomeLikelyDuplicate {
			n++
		}
	}
	return n
}

// FabricatedCaught returns how many fabricated cases expecting
// GROUNDING_FAILED got it, out of how many expected it.
func (s Scoreboard) FabricatedCaught() (caught, total int) {
	for _, r := range s.Results {
		if r.Case.Kind != KindFabricated || r.Case.Meta.Expected != report.OutcomeGroundingFailed {
			continue
		}
		total++
		if r.Got == report.OutcomeGroundingFailed {
			caught++
		}
	}
	return caught, total
}

// Errors counts cases that failed to run.
func (s Scoreboard) Errors() int {
	n := 0
	for _, r := range s.Results {
		if r.Err != nil {
			n++
		}
	}
	return n
}

// Failed reports whether the run breaks a hard requirement: any real
// report marked GROUNDING_FAILED, or any case that couldn't run.
// Ordinary mismatches are progress to track, not failures.
func (s Scoreboard) Failed() bool {
	return s.RealGroundingFailures() > 0 || s.RealLikelyDuplicates() > 0 || s.Errors() > 0
}

// Write prints the per-case table and the summary.
func (s Scoreboard) Write(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "KIND\tID\tEXPECTED\tGOT\t")
	for _, r := range s.Results {
		got, mark := string(r.Got), "✗"
		switch {
		case r.Err != nil:
			got = "error: " + report.Printable(r.Err.Error())
		case r.Got == r.Case.Meta.Expected:
			mark = "✓"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.Case.Kind, r.Case.ID, r.Case.Meta.Expected, got, mark)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	caught, total := s.FabricatedCaught()
	_, err := fmt.Fprintf(w, `
Summary
  cases:                                 %d
  exact matches:                         %d/%d
  real wrongly GROUNDING_FAILED:         %d (must be 0)
  real wrongly LIKELY_DUPLICATE:         %d (must be 0)
  fabricated caught by grounding:        %d/%d
  fabricated wrongly LIKELY_DUPLICATE:   %d
  errors:                                %d
`, len(s.Results), s.Matches(), len(s.Results), s.RealGroundingFailures(), s.RealLikelyDuplicates(), caught, total, s.FabricatedLikelyDuplicates(), s.Errors())
	return err
}
