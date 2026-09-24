package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvalOnRepoCorpus(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"eval", "--corpus", "../../testdata/corpus"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code = %d\nstdout: %s\nstderr: %s", code, out.String(), errOut.String())
	}
	for _, want := range []string{"fab-001-invented-method", "INCONCLUSIVE", "must be 0"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}
}

func TestEvalBadCorpus(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"eval", "--corpus", t.TempDir() + "/nope"}, &out, &errOut); code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
}

func TestEvalWithConfig(t *testing.T) {
	// This test's job is only to prove that --config is accepted and wired
	// into the pipeline (an empty {} config means no LLM providers, so
	// extraction stays deterministic-only). It does not need the full
	// testdata/corpus for that: TestEvalOnRepoCorpus already exercises the
	// full corpus, including real GitHub clones. Grounding now runs
	// unconditionally (see check.go/eval.go), so pointing this test at the
	// full corpus would turn a fast unit test into a slow, network-heavy
	// one. Use a tiny corpus subset made of two fabricated cases that
	// target placeholder repos (example/widgets, example/pipeline): the
	// clone attempt fails fast and grounding degrades gracefully, so the
	// eval pipeline still runs end to end without any real network clone.
	corpus := t.TempDir()
	for _, id := range []string{"fab-018-needs-info", "fab-019-needs-info"} {
		src := filepath.Join("..", "..", "testdata", "corpus", "fabricated", id)
		dst := filepath.Join(corpus, "fabricated", id)
		if err := os.MkdirAll(dst, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
			t.Fatal(err)
		}
	}

	cfgPath := filepath.Join(t.TempDir(), "kritolith.json")
	if err := os.WriteFile(cfgPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"eval", "--corpus", corpus, "--config", cfgPath}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code = %d\nstdout: %s\nstderr: %s", code, out.String(), errOut.String())
	}
}

func TestEvalBadConfig(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"eval", "--corpus", "../../testdata/corpus", "--config", filepath.Join(t.TempDir(), "missing.json")}, &out, &errOut)
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
}
