package main

import (
	"bytes"
	"context"
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
