package anthropic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/llm"
)

func TestCompleteSuccess(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("x-api-key"); got != "secret" {
			t.Errorf("x-api-key = %q", got)
		}
		if got := r.Header.Get("anthropic-version"); got != apiVersion {
			t.Errorf("anthropic-version = %q", got)
		}
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"hello there"}],"model":"m","stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":3}}`))
	}))
	defer srv.Close()

	a := New(Options{Name: "test", BaseURL: srv.URL, Model: "m", APIKey: "secret"})
	resp, err := a.Complete(context.Background(), llm.CompleteRequest{
		Messages: []llm.Message{{Role: "system", Content: "be terse"}, {Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Text != "hello there" {
		t.Errorf("Text = %q", resp.Text)
	}
	if gotBody["system"] != "be terse" {
		t.Errorf("system field = %v", gotBody["system"])
	}
	msgs, _ := gotBody["messages"].([]any)
	if len(msgs) != 1 {
		t.Errorf("messages after lifting system out = %v", gotBody["messages"])
	}
}

func TestCompleteTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer srv.Close()

	a := New(Options{Name: "test", BaseURL: srv.URL, Model: "m", Timeout: 20 * time.Millisecond})
	if _, err := a.Complete(context.Background(), llm.CompleteRequest{}); err == nil {
		t.Fatal("want timeout error")
	}
}

func TestCompleteServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()

	a := New(Options{Name: "test", BaseURL: srv.URL, Model: "m"})
	_, err := a.Complete(context.Background(), llm.CompleteRequest{})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v, want it to mention 500", err)
	}
}

func TestCompleteMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"content": [`))
	}))
	defer srv.Close()

	a := New(Options{Name: "test", BaseURL: srv.URL, Model: "m"})
	if _, err := a.Complete(context.Background(), llm.CompleteRequest{}); err == nil {
		t.Fatal("want decode error")
	}
}

func TestEmbedUnsupported(t *testing.T) {
	a := New(Options{Name: "test", BaseURL: "https://api.anthropic.com", Model: "m"})
	if _, err := a.Embed(context.Background(), []string{"x"}); err == nil {
		t.Fatal("want error: anthropic has no embeddings API")
	}
}

func TestIsLocalAlwaysFalse(t *testing.T) {
	a := New(Options{Name: "test", BaseURL: "http://127.0.0.1:8080", Model: "m"})
	if a.IsLocal() {
		t.Error("want IsLocal always false for the anthropic adapter")
	}
}

// TestCompleteDoesNotFollowRedirect proves a 307 from the configured
// endpoint is not followed, so the request (with its x-api-key header
// and report-derived body) is never resent to a redirect target.
func TestCompleteDoesNotFollowRedirect(t *testing.T) {
	var evilHit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		evilHit = true
	}))
	defer evil.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	a := New(Options{Name: "test", BaseURL: srv.URL, Model: "m"})
	if _, err := a.Complete(context.Background(), llm.CompleteRequest{}); err == nil {
		t.Fatal("want an error: a 307 has no usable response body")
	}
	if evilHit {
		t.Fatal("redirect target was hit; client followed the redirect")
	}
}
