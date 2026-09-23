package gemini

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/llm"
)

func TestCompleteSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/models/gemini-test:generateContent") {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.URL.Query().Get("key") != "secret" {
			t.Errorf("key query param = %q", r.URL.Query().Get("key"))
		}
		w.Write([]byte(`{"candidates":[{"content":{"role":"model","parts":[{"text":"hi there"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":2,"totalTokenCount":3}}`))
	}))
	defer srv.Close()

	a := New(Options{Name: "test", BaseURL: srv.URL, Model: "gemini-test", APIKey: "secret"})
	resp, err := a.Complete(context.Background(), llm.CompleteRequest{
		Messages: []llm.Message{{Role: "system", Content: "be terse"}, {Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Text != "hi there" {
		t.Errorf("Text = %q", resp.Text)
	}
}

func TestCompleteForwardsGenerationConfig(t *testing.T) {
	var capturedReq generateRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if err := json.Unmarshal(body, &capturedReq); err != nil {
			t.Fatalf("unmarshal request: %v", err)
		}
		w.Write([]byte(`{"candidates":[{"content":{"role":"model","parts":[{"text":"ok"}]},"finishReason":"STOP"}]}`))
	}))
	defer srv.Close()

	a := New(Options{Name: "test", BaseURL: srv.URL, Model: "m", APIKey: "key"})
	_, err := a.Complete(context.Background(), llm.CompleteRequest{
		Temperature: 0.5,
		MaxTokens:   100,
		Messages:    []llm.Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if capturedReq.GenerationConfig == nil {
		t.Fatal("generationConfig is nil")
	}
	if capturedReq.GenerationConfig.Temperature != 0.5 {
		t.Errorf("temperature = %v, want 0.5", capturedReq.GenerationConfig.Temperature)
	}
	if capturedReq.GenerationConfig.MaxOutputTokens != 100 {
		t.Errorf("maxOutputTokens = %d, want 100", capturedReq.GenerationConfig.MaxOutputTokens)
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
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"unavailable"}`))
	}))
	defer srv.Close()

	a := New(Options{Name: "test", BaseURL: srv.URL, Model: "m"})
	_, err := a.Complete(context.Background(), llm.CompleteRequest{})
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("err = %v, want it to mention 503", err)
	}
}

func TestCompleteMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"candidates": [`))
	}))
	defer srv.Close()

	a := New(Options{Name: "test", BaseURL: srv.URL, Model: "m"})
	if _, err := a.Complete(context.Background(), llm.CompleteRequest{}); err == nil {
		t.Fatal("want decode error")
	}
}

func TestEmbedCallsPerText(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Write([]byte(`{"embedding":{"values":[0.1,0.2]}}`))
	}))
	defer srv.Close()

	a := New(Options{Name: "test", BaseURL: srv.URL, Model: "m"})
	vecs, err := a.Embed(context.Background(), []string{"a", "b", "c"})
	if err != nil {
		t.Fatal(err)
	}
	if len(vecs) != 3 || atomic.LoadInt32(&calls) != 3 {
		t.Errorf("vecs = %v, calls = %d", vecs, calls)
	}
}

func TestIsLocalAlwaysFalse(t *testing.T) {
	a := New(Options{Name: "test", BaseURL: "http://127.0.0.1:8080", Model: "m"})
	if a.IsLocal() {
		t.Error("want IsLocal always false for the gemini adapter")
	}
}
