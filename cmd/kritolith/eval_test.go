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
	cfgPath := filepath.Join(t.TempDir(), "kritolith.json")
	if err := os.WriteFile(cfgPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"eval", "--corpus", "../../testdata/corpus", "--config", cfgPath}, &out, &errOut)
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
