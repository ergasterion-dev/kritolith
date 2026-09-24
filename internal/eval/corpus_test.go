package eval

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

const sha = "e1fcd82abba34df74614020343be8eb1fe85f0d9"

func writeCase(t *testing.T, root, kind, id, meta string) {
	t.Helper()
	dir := filepath.Join(root, kind, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte("# r"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte(meta), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadCorpus(t *testing.T) {
	root := t.TempDir()
	writeCase(t, root, "real", "go-2024-0001", `{"repo":"golang/net","ref":"`+sha+`","expected_outcome":"REPRODUCED_FIXED_AT_HEAD","source":"GO-2024-0001"}`)
	writeCase(t, root, "fabricated", "fab-001", `{"repo":"golang/net","ref":"`+sha+`","expected_outcome":"GROUNDING_FAILED","source":"fabricated"}`)
	writeCase(t, root, "fabricated", "fab-002", `{"repo":"golang/net","ref":"","expected_outcome":"NEEDS_INFO","source":"fabricated"}`)
	cases, err := LoadCorpus(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 3 || cases[0].Kind != KindReal || cases[1].ID != "fab-001" || cases[2].Meta.Expected != report.OutcomeNeedsInfo {
		t.Fatalf("cases = %+v", cases)
	}
}

func TestLoadCorpusRejects(t *testing.T) {
	tests := []struct {
		name, kind, id, meta, wantErr string
	}{
		{"unknown field", "fabricated", "f1", `{"repo":"a/b","ref":"` + sha + `","expected_outcome":"INCONCLUSIVE","source":"fabricated","extra":1}`, "unknown field"},
		{"bad id", "fabricated", "Bad_ID", `{"repo":"a/b","ref":"` + sha + `","expected_outcome":"INCONCLUSIVE","source":"fabricated"}`, "case id"},
		{"bad outcome", "fabricated", "f1", `{"repo":"a/b","ref":"` + sha + `","expected_outcome":"MAYBE","source":"fabricated"}`, "outcome"},
		{"short ref", "fabricated", "f1", `{"repo":"a/b","ref":"e1fcd82","expected_outcome":"INCONCLUSIVE","source":"fabricated"}`, "40-hex"},
		{"empty ref not needs-info", "fabricated", "f1", `{"repo":"a/b","ref":"","expected_outcome":"INCONCLUSIVE","source":"fabricated"}`, "NEEDS_INFO"},
		{"real with fabricated source", "real", "r1", `{"repo":"a/b","ref":"` + sha + `","expected_outcome":"REPRODUCED","source":"fabricated"}`, "GHSA-"},
		{"real expecting grounding failure", "real", "r1", `{"repo":"a/b","ref":"` + sha + `","expected_outcome":"GROUNDING_FAILED","source":"GO-2024-1"}`, "never"},
		{"fabricated with advisory source", "fabricated", "f1", `{"repo":"a/b","ref":"` + sha + `","expected_outcome":"INCONCLUSIVE","source":"GHSA-x"}`, "fabricated"},
		{"trailing data", "fabricated", "f1", `{"repo":"a/b","ref":"` + sha + `","expected_outcome":"INCONCLUSIVE","source":"fabricated"}{"repo":"a/b"}`, "trailing data"},
		{"expected_duplicate_of not LIKELY_DUPLICATE", "fabricated", "f1", `{"repo":"a/b","ref":"` + sha + `","expected_outcome":"INCONCLUSIVE","source":"fabricated","expected_duplicate_of":"go-2024-0001"}`, "only meaningful"},
		{"expected_duplicate_of bad id shape", "fabricated", "f1", `{"repo":"a/b","ref":"` + sha + `","expected_outcome":"LIKELY_DUPLICATE","source":"fabricated","expected_duplicate_of":"Bad_ID"}`, "valid case id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeCase(t, root, tt.kind, tt.id, tt.meta)
			_, err := LoadCorpus(root)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadCorpusRejectsUnknownExpectedDuplicateOf(t *testing.T) {
	root := t.TempDir()
	writeCase(t, root, "fabricated", "f1", `{"repo":"a/b","ref":"`+sha+`","expected_outcome":"LIKELY_DUPLICATE","source":"fabricated","expected_duplicate_of":"no-such-case"}`)
	_, err := LoadCorpus(root)
	if err == nil || !strings.Contains(err.Error(), "does not match any loaded case id") {
		t.Fatalf("err = %v, want it to reject an expected_duplicate_of naming no loaded case", err)
	}
}

func TestLoadCorpusAcceptsExpectedDuplicateOf(t *testing.T) {
	root := t.TempDir()
	writeCase(t, root, "real", "go-2024-0001", `{"repo":"golang/net","ref":"`+sha+`","expected_outcome":"REPRODUCED","source":"GO-2024-0001"}`)
	writeCase(t, root, "fabricated", "f1", `{"repo":"golang/net","ref":"`+sha+`","expected_outcome":"LIKELY_DUPLICATE","source":"fabricated","expected_duplicate_of":"go-2024-0001"}`)
	cases, err := LoadCorpus(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 2 || cases[1].Meta.ExpectedDuplicateOf != "go-2024-0001" {
		t.Fatalf("cases = %+v", cases)
	}
}

func TestLoadCorpusMissingReport(t *testing.T) {
	root := t.TempDir()
	writeCase(t, root, "fabricated", "f1", `{"repo":"a/b","ref":"`+sha+`","expected_outcome":"INCONCLUSIVE","source":"fabricated"}`)
	os.Remove(filepath.Join(root, "fabricated", "f1", "report.md"))
	if _, err := LoadCorpus(root); err == nil || !strings.Contains(err.Error(), "report.md") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadCorpusMissingRoot(t *testing.T) {
	if _, err := LoadCorpus(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("want error")
	}
}

// The checked-in corpus must always be valid.
func TestRepoCorpusIsValid(t *testing.T) {
	cases, err := LoadCorpus("../../testdata/corpus")
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) < 40 {
		t.Fatalf("corpus has %d cases, want at least 40", len(cases))
	}
}
