package llm

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

type fakeProvider struct {
	name        string
	local       bool
	completeErr error
	text        string
}

func (f *fakeProvider) Complete(ctx context.Context, req CompleteRequest) (CompleteResponse, error) {
	if f.completeErr != nil {
		return CompleteResponse{}, f.completeErr
	}
	return CompleteResponse{Text: f.text}, nil
}
func (f *fakeProvider) Embed(ctx context.Context, texts []string) ([][]float32, error) { return nil, nil }
func (f *fakeProvider) Name() string  { return f.name }
func (f *fakeProvider) IsLocal() bool { return f.local }

func TestRouterSkipsCloudWithoutAllow(t *testing.T) {
	local := &fakeProvider{name: "local", local: true, text: "ok"}
	cloud := &fakeProvider{name: "cloud", local: false, text: "cloud-ok"}
	r := NewRouter(
		map[string]Provider{"local": local, "cloud": cloud},
		map[string][]string{"extract": {"cloud", "local"}},
		func(string) bool { return false },
		nil,
	)
	chain := r.Chain("extract", "R1", "a/b")
	if len(chain) != 1 || chain[0].Name() != "local" {
		t.Fatalf("chain = %v, want only local", chain)
	}
}

func TestRouterAllowsCloudWhenOptedIn(t *testing.T) {
	cloud := &fakeProvider{name: "cloud", local: false}
	r := NewRouter(
		map[string]Provider{"cloud": cloud},
		map[string][]string{"extract": {"cloud"}},
		func(repo string) bool { return repo == "a/b" },
		nil,
	)
	chain := r.Chain("extract", "R1", "a/b")
	if len(chain) != 1 || chain[0].Name() != "cloud" {
		t.Fatalf("chain = %v, want cloud allowed", chain)
	}
	if chain2 := r.Chain("extract", "R1", "other/repo"); len(chain2) != 0 {
		t.Fatalf("chain for unauthorized repo = %v, want empty", chain2)
	}
}

func TestRouterDeniesCloudForUnknownRepo(t *testing.T) {
	cloud := &fakeProvider{name: "cloud", local: false}
	r := NewRouter(
		map[string]Provider{"cloud": cloud},
		map[string][]string{"extract": {"cloud"}},
		func(repo string) bool { return repo == "known/repo" },
		nil,
	)
	if chain := r.Chain("extract", "R1", "totally/unknown"); len(chain) != 0 {
		t.Fatalf("chain = %v, want cloud blocked for a repo absent from config entirely", chain)
	}
}

func TestRouterLogsCloudCall(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	cloud := &fakeProvider{name: "cloud", local: false}
	r := NewRouter(
		map[string]Provider{"cloud": cloud},
		map[string][]string{"extract": {"cloud"}},
		func(string) bool { return true },
		logger,
	)
	r.Chain("extract", "R42", "a/b")
	out := buf.String()
	if !strings.Contains(out, "cloud LLM call") || !strings.Contains(out, "R42") {
		t.Fatalf("log missing cloud call warning with report id: %q", out)
	}
}

func TestRouterCompleteFallsThrough(t *testing.T) {
	bad := &fakeProvider{name: "bad", local: true, completeErr: errors.New("timeout")}
	good := &fakeProvider{name: "good", local: true, text: "result"}
	r := NewRouter(
		map[string]Provider{"bad": bad, "good": good},
		map[string][]string{"extract": {"bad", "good"}},
		nil, nil,
	)
	resp, err := r.Complete(context.Background(), "extract", "R1", "a/b", CompleteRequest{})
	if err != nil || resp.Text != "result" {
		t.Fatalf("Complete = %+v, %v", resp, err)
	}
}

func TestRouterCompleteExhausted(t *testing.T) {
	bad := &fakeProvider{name: "bad", local: true, completeErr: errors.New("timeout")}
	r := NewRouter(map[string]Provider{"bad": bad}, map[string][]string{"extract": {"bad"}}, nil, nil)
	if _, err := r.Complete(context.Background(), "extract", "R1", "a/b", CompleteRequest{}); err == nil {
		t.Fatal("want error when chain is exhausted")
	}
}

func TestRouterEmptyChainIsNotError(t *testing.T) {
	r := NewRouter(nil, nil, nil, nil)
	if chain := r.Chain("extract", "R1", "a/b"); len(chain) != 0 {
		t.Fatalf("chain = %v, want empty", chain)
	}
}
