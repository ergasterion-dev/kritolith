package openaicompat

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
	var gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if got := r.Header.Get("Authorization"); got != "Bearer secret" {
			t.Errorf("Authorization header = %q", got)
		}
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"x","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"hi there"}}],"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}`))
	}))
	defer srv.Close()

	a, err := New(Options{Name: "test", BaseURL: srv.URL, Model: "m", APIKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.Complete(context.Background(), llm.CompleteRequest{Messages: []llm.Message{{Role: "user", Content: "hello"}}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Text != "hi there" {
		t.Errorf("Text = %q", resp.Text)
	}
	if gotPath != "/chat/completions" {
		t.Errorf("path = %q", gotPath)
	}
	if gotBody["model"] != "m" {
		t.Errorf("request body model = %v", gotBody["model"])
	}
}

func TestCompleteTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer srv.Close()

	a, err := New(Options{Name: "test", BaseURL: srv.URL, Model: "m", Timeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Complete(context.Background(), llm.CompleteRequest{}); err == nil {
		t.Fatal("want timeout error")
	}
}

func TestCompleteServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error":"rate limited"}`))
	}))
	defer srv.Close()

	a, err := New(Options{Name: "test", BaseURL: srv.URL, Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Complete(context.Background(), llm.CompleteRequest{})
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("err = %v, want it to mention 429", err)
	}
}

func TestCompleteMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"choices": [`))
	}))
	defer srv.Close()

	a, err := New(Options{Name: "test", BaseURL: srv.URL, Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Complete(context.Background(), llm.CompleteRequest{}); err == nil {
		t.Fatal("want decode error")
	}
}

func TestEmbedSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"object":"list","data":[{"object":"embedding","embedding":[0.1,0.2],"index":0},{"object":"embedding","embedding":[0.3,0.4],"index":1}],"model":"m","usage":{"prompt_tokens":2,"total_tokens":2}}`))
	}))
	defer srv.Close()

	a, err := New(Options{Name: "test", BaseURL: srv.URL, Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	vecs, err := a.Embed(context.Background(), []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(vecs) != 2 || vecs[0][0] != 0.1 || vecs[1][0] != 0.3 {
		t.Errorf("vecs = %v", vecs)
	}
}

func TestIsLocalFromBaseURL(t *testing.T) {
	a, err := New(Options{Name: "local", BaseURL: "http://127.0.0.1:11434/v1", Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if !a.IsLocal() {
		t.Error("want IsLocal true for loopback base_url")
	}
	b, err := New(Options{Name: "cloud", BaseURL: "https://api.openai.com/v1", Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if b.IsLocal() {
		t.Error("want IsLocal false for public base_url")
	}
}

func TestNewRejectsInvalidBaseURL(t *testing.T) {
	if _, err := New(Options{Name: "bad", BaseURL: "not a url", Model: "m"}); err == nil {
		t.Fatal("want error for invalid base_url")
	}
}
