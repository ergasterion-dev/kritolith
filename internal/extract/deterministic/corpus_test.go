package deterministic

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/eval"
	"github.com/ergasterion-dev/kritolith/internal/report"
)

// TestCorpusCoverage is deterministic extraction's baseline for Week
// 3: every fabricated case whose expected outcome is GROUNDING_FAILED
// names a fake file or function, and deterministic extraction must
// find at least one file or function claim in each of them, or
// grounding will have nothing concrete to check against git. Real
// cases are logged and required to clear a lower bar (60%, "most"),
// since a real report's prose is far less predictable than a
// fabricated one built to name a specific symbol.
func TestCorpusCoverage(t *testing.T) {
	cases, err := eval.LoadCorpus("../../../testdata/corpus")
	if err != nil {
		t.Fatal(err)
	}

	var realHit, realTotal int
	for _, c := range cases {
		body, err := os.ReadFile(filepath.Join(c.Dir, "report.md"))
		if err != nil {
			t.Fatal(err)
		}
		claims := Extract(string(body))
		hasFileOrFunc := hasKind(claims, report.ClaimFile) || hasKind(claims, report.ClaimFunction)

		if c.Kind == eval.KindFabricated && c.Meta.Expected == report.OutcomeGroundingFailed {
			if !hasFileOrFunc {
				t.Errorf("%s: expected GROUNDING_FAILED but deterministic extraction found no file/function claim", c.ID)
			}
		}
		if c.Kind == eval.KindReal {
			realTotal++
			if hasFileOrFunc {
				realHit++
			}
		}
	}

	t.Logf("real corpus: %d/%d cases yielded a file or function claim", realHit, realTotal)
	if realTotal > 0 && realHit*100/realTotal < 60 {
		t.Errorf("deterministic extraction found file/function claims in only %d/%d real cases, want at least 60%%", realHit, realTotal)
	}
}

func hasKind(claims []report.Claim, kind report.ClaimKind) bool {
	for _, c := range claims {
		if c.Kind == kind {
			return true
		}
	}
	return false
}
