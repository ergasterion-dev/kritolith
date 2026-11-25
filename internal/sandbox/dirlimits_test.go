package sandbox

import (
	"strings"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// lowerDirLimits makes the per-directory read limits small for a test.
func lowerDirLimits(t *testing.T, files int, bytes int64) {
	t.Helper()
	of, ob := maxGoFilesPerDir, maxDirSourceBytes
	maxGoFilesPerDir, maxDirSourceBytes = files, bytes
	t.Cleanup(func() { maxGoFilesPerDir, maxDirSourceBytes = of, ob })
}

// A package directory larger than what Kritolith reads must never make
// a claim or a fuzz target silently disappear: the run is INCONCLUSIVE
// (or, for placement, NEEDS_INFO asking for the PoC directory), and no
// container runs.
func TestDirReadLimitsAreExplicit(t *testing.T) {
	// Sorted before vuln.go, so they use up the budget first.
	big := withFiles(baseTree(), "vuln/a.go", "package vuln\n", "vuln/b.go", "package vuln\n", "vuln/c.go", "package vuln\n")
	fuzzSeed := []report.Artifact{{Name: "testdata/fuzz/FuzzParse/seed1", Content: []byte("go test fuzz v1\n")}}
	tests := []struct {
		name      string
		files     int
		bytes     int64
		tree      map[string]string
		poc       []report.Artifact
		claims    []report.Claim
		inconc    string
		needsInfo string
	}{
		{name: "claimed function past the file limit", files: 3, bytes: 1 << 20, tree: big, inconc: "more Go source"},
		{name: "claimed function past the byte budget", files: 100, bytes: 20, tree: big, inconc: "more Go source"},
		{name: "fuzz target past the file limit", files: 3, bytes: 1 << 20, tree: big, poc: fuzzSeed, inconc: "more Go source"},
		{name: "placement past the file limit", files: 2, bytes: 1 << 20, claims: []report.Claim{},
			tree: withFiles(baseTree(), "vuln/a.go", "not go", "vuln/b.go", "not go"), needsInfo: "supply the PoC directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lowerDirLimits(t, tt.files, tt.bytes)
			fx := newFixture(t, map[string]step{"ref/run": stepPanic})
			fx.src.trees[refSHA] = tt.tree
			res := fx.run(t, Request{Report: report.Report{PoC: tt.poc}, Claims: tt.claims})
			if tt.inconc != "" && !strings.Contains(res.Inconclusive, tt.inconc) {
				t.Fatalf("Inconclusive = %q, want %q (%s)", res.Inconclusive, tt.inconc, resText(res))
			}
			if tt.needsInfo != "" && !strings.Contains(res.NeedsInfo, tt.needsInfo) {
				t.Fatalf("NeedsInfo = %q, want %q (%s)", res.NeedsInfo, tt.needsInfo, resText(res))
			}
			if res.Passed || (res.Repro != nil && res.Repro.Reproduced) {
				t.Fatalf("a truncated read reproduced or passed: %s", resText(res))
			}
		})
	}
	// Within the limits the same tree reproduces.
	fx := newFixture(t, map[string]step{"ref/run": stepPanic, "head/run": stepPass})
	fx.src.trees[refSHA] = big
	if res := fx.run(t, Request{}); res.Repro == nil || !res.Repro.Reproduced {
		t.Fatalf("within limits: %s", resText(res))
	}
}
