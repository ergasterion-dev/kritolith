package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/config"
	"github.com/ergasterion-dev/kritolith/internal/report"
	"github.com/ergasterion-dev/kritolith/internal/store"
)

const testSecret = "0123456789abcdef-test-secret"

func signBody(body string) string {
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func reportedBody(repo, id string) string {
	return fmt.Sprintf(`{"action":"reported","repository":{"full_name":%q},"repository_advisory":{"ghsa_id":%q}}`, repo, id)
}

type fakeQueue struct {
	mu   sync.Mutex
	jobs []string
	err  error
}

func (q *fakeQueue) EnqueueIntake(ctx context.Context, source, repo, id string, now time.Time) (bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.err != nil {
		return false, q.err
	}
	key := source + " " + repo + " " + id
	for _, j := range q.jobs {
		if j == key {
			return false, nil
		}
	}
	q.jobs = append(q.jobs, key)
	return true, nil
}

func TestWebhookHandler(t *testing.T) {
	cfg := config.Config{Projects: []config.Project{{Repo: "Owner/Name"}}}
	q := &fakeQueue{}
	wakes := 0
	var logs bytes.Buffer
	h := newServeMux([]byte(testSecret), cfg, q, func() { wakes++ }, slog.New(slog.NewTextHandler(&logs, nil)))
	post := func(event, body, sig string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, webhookPath, strings.NewReader(body))
		req.Header.Set("X-GitHub-Event", event)
		if sig != "" {
			req.Header.Set("X-Hub-Signature-256", sig)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	good := reportedBody("owner/name", "GHSA-mh63-6h87-95cp")

	// Unsigned and wrongly signed deliveries get nothing, and say nothing.
	for name, sig := range map[string]string{"unsigned": "", "wrong": signBody(good + " "), "garbage": "sha256=zz"} {
		if rec := post("repository_advisory", good, sig); rec.Code != http.StatusUnauthorized || strings.Contains(rec.Body.String(), "GHSA") {
			t.Errorf("%s: code %d, body %q", name, rec.Code, rec.Body.String())
		}
	}
	if len(q.jobs) != 0 || wakes != 0 {
		t.Fatalf("an unverified delivery was queued: %v", q.jobs)
	}

	// A new report is queued once, under the project's configured
	// spelling; a redelivery is accepted and does nothing.
	if rec := post("repository_advisory", good, signBody(good)); rec.Code != http.StatusAccepted {
		t.Fatalf("new report: code %d", rec.Code)
	}
	if rec := post("repository_advisory", good, signBody(good)); rec.Code != http.StatusAccepted {
		t.Fatalf("redelivery: code %d", rec.Code)
	}
	if len(q.jobs) != 1 || q.jobs[0] != "github Owner/Name GHSA-mh63-6h87-95cp" || wakes != 1 {
		t.Fatalf("jobs = %v, wakes = %d", q.jobs, wakes)
	}

	// Signed, but nothing to do.
	other := reportedBody("someone/else", "GHSA-mh63-6h87-95cp")
	published := strings.Replace(good, "reported", "published", 1)
	for name, tc := range map[string]struct{ event, body string }{
		"ping":              {"ping", `{"zen":"x"}`},
		"other event":       {"push", good},
		"published":         {"repository_advisory", published},
		"unconfigured repo": {"repository_advisory", other},
	} {
		if rec := post(tc.event, tc.body, signBody(tc.body)); rec.Code != http.StatusNoContent {
			t.Errorf("%s: code %d", name, rec.Code)
		}
	}
	bad := reportedBody("owner/name", "GHSA-nope")
	if rec := post("repository_advisory", bad, signBody(bad)); rec.Code != http.StatusBadRequest {
		t.Errorf("bad id: code %d", rec.Code)
	}
	if len(q.jobs) != 1 {
		t.Fatalf("jobs = %v", q.jobs)
	}

	// Too large, wrong method, wrong path, health.
	big := strings.Repeat("a", 6<<20)
	if rec := post("repository_advisory", big, signBody(big)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized: code %d", rec.Code)
	}
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, webhookPath, http.StatusMethodNotAllowed},
		{http.MethodPost, "/other", http.StatusNotFound},
		{http.MethodGet, "/healthz", http.StatusOK},
		{http.MethodGet, "/", http.StatusNotFound},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != tc.want {
			t.Errorf("%s %s: code %d, want %d", tc.method, tc.path, rec.Code, tc.want)
		}
	}

	// A queue failure is a 500, so GitHub shows the delivery as failed.
	q.err = fmt.Errorf("disk full")
	fresh := reportedBody("owner/name", "GHSA-2222-3333-4444")
	if rec := post("repository_advisory", fresh, signBody(fresh)); rec.Code != http.StatusInternalServerError {
		t.Errorf("queue failure: code %d", rec.Code)
	}
	if strings.Contains(logs.String(), testSecret) {
		t.Error("the webhook secret was logged")
	}
}

// syncBuffer is a bytes.Buffer safe to write from one goroutine and
// read from another.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

var listenRe = regexp.MustCompile(`listening on (http://[0-9.:]+/webhook/github)`)

func TestServeEndToEnd(t *testing.T) {
	const ghsa = "GHSA-mh63-6h87-95cp"
	var apiAuth string
	var apiMu sync.Mutex
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiMu.Lock()
		apiAuth = r.Header.Get("Authorization")
		apiMu.Unlock()
		if r.URL.Path != "/repos/a/b/security-advisories/"+ghsa {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, `{"ghsa_id":"`+ghsa+`","summary":"Over-read in the parser","description":"The function parser.readAll in parser.go overflows.","state":"triage"}`)
	}))
	defer api.Close()
	sink := newMailSink(t)

	dataDir := filepath.Join(t.TempDir(), "data")
	cfg := writeConfigFile(t, fmt.Sprintf(`{
		"projects": [{"repo": "a/b", "notify": ["sec@example.org"]}],
		"github": {"webhook_secret_env": "KRITOLITH_TEST_WEBHOOK_SECRET", "token_env": "KRITOLITH_TEST_GH_TOKEN", "api_url": %q},
		"smtp": {"addr": %q, "from": "kritolith@example.org"}
	}`, api.URL, sink.ln.Addr().String()))
	t.Setenv("KRITOLITH_TEST_WEBHOOK_SECRET", testSecret)
	t.Setenv("KRITOLITH_TEST_GH_TOKEN", "tok_serve")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, errOut syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"serve", "--config", cfg, "--data-dir", dataDir, "--listen", "127.0.0.1:0", "--notify"}, &out, &errOut)
	}()
	var url string
	waitFor(t, "the server to start", func() bool {
		m := listenRe.FindStringSubmatch(out.String())
		if m != nil {
			url = m[1]
		}
		return m != nil
	}, &errOut)

	body := reportedBody("a/b", ghsa)
	for i := 0; i < 2; i++ { // the second is a redelivery
		req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
		req.Header.Set("X-GitHub-Event", "repository_advisory")
		req.Header.Set("X-Hub-Signature-256", signBody(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("delivery %d: status %d", i, resp.StatusCode)
		}
	}
	waitFor(t, "the verdict email", func() bool { _, data := sink.received(); return data != "" }, &errOut)
	waitFor(t, "the job to be marked done", func() bool { return strings.Contains(errOut.String(), "intake: done") }, &errOut)

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve exited %d: %s", code, errOut.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("serve did not stop")
	}

	apiMu.Lock()
	if apiAuth != "Bearer tok_serve" {
		t.Errorf("API Authorization = %q", apiAuth)
	}
	apiMu.Unlock()
	if strings.Contains(out.String()+errOut.String(), "tok_serve") || strings.Contains(out.String()+errOut.String(), testSecret) {
		t.Error("a secret was printed")
	}
	if strings.Contains(errOut.String(), "parser.readAll") || strings.Contains(errOut.String(), "Over-read") {
		t.Errorf("report content was logged:\n%s", errOut.String())
	}
	rcpt, data := sink.received()
	if len(rcpt) != 1 || !strings.Contains(data, "NEEDS_INFO") {
		t.Errorf("mail: rcpt %q\n%s", rcpt, data)
	}

	// Exactly one report was stored, for all the redelivering.
	st, err := store.Open(context.Background(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	job, err := st.GetIntake(context.Background(), 1)
	if err != nil || job.State != store.IntakeDone || job.Attempts != 1 || job.ReportID == "" {
		t.Fatalf("job = %+v, %v", job, err)
	}
	if _, err := st.GetIntake(context.Background(), 2); err == nil {
		t.Error("the redelivery created a second job")
	}
	r, err := st.GetReport(context.Background(), job.ReportID)
	if err != nil || r.Source != report.SourceGitHubPVR || r.SourceRef != ghsa {
		t.Fatalf("stored report = %+v, %v", r, err)
	}
}

func waitFor(t *testing.T, what string, cond func() bool, errOut *syncBuffer) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s; stderr:\n%s", what, errOut.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestServeStartupErrors(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	t.Setenv("KRITOLITH_TEST_WEBHOOK_SECRET", testSecret)
	t.Setenv("KRITOLITH_TEST_SHORT", "short")
	t.Setenv("KRITOLITH_TEST_GH_TOKEN", "tok")
	t.Setenv("KRITOLITH_TEST_EMPTY", "")
	gh := func(secretEnv, tokenEnv string) string {
		return fmt.Sprintf(`"github":{"webhook_secret_env":%q,"token_env":%q}`, secretEnv, tokenEnv)
	}
	ok := gh("KRITOLITH_TEST_WEBHOOK_SECRET", "KRITOLITH_TEST_GH_TOKEN")
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
	}{
		{"no config", []string{"serve"}, 2, "Usage: kritolith serve"},
		{"no projects", []string{"serve", "--data-dir", dataDir, "--config", writeConfigFile(t, `{`+ok+`}`)}, 1, "lists no projects"},
		{"no secret configured", []string{"serve", "--data-dir", dataDir, "--config", writeConfigFile(t, `{"projects":[{"repo":"a/b"}]}`)}, 1, "webhook_secret_env"},
		{"short secret", []string{"serve", "--data-dir", dataDir, "--config", writeConfigFile(t, `{"projects":[{"repo":"a/b"}],`+gh("KRITOLITH_TEST_SHORT", "KRITOLITH_TEST_GH_TOKEN")+`}`)}, 1, "at least 16 characters"},
		{"no token", []string{"serve", "--data-dir", dataDir, "--config", writeConfigFile(t, `{"projects":[{"repo":"a/b"}],`+gh("KRITOLITH_TEST_WEBHOOK_SECRET", "KRITOLITH_TEST_EMPTY")+`}`)}, 1, "must hold a GitHub token"},
		{"notify without smtp", []string{"serve", "--notify", "--data-dir", dataDir, "--config", writeConfigFile(t, `{"projects":[{"repo":"a/b","notify":["s@example.org"]}],`+ok+`}`)}, 1, "smtp section"},
		{"address in use or invalid", []string{"serve", "--listen", "256.0.0.1:1", "--data-dir", dataDir, "--config", writeConfigFile(t, `{"projects":[{"repo":"a/b"}],`+ok+`}`)}, 1, "serve:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := run(context.Background(), tt.args, &out, &errOut)
			if code != tt.wantCode || !strings.Contains(errOut.String(), tt.wantErr) {
				t.Fatalf("code = %d (want %d), stderr = %q (want %q)", code, tt.wantCode, errOut.String(), tt.wantErr)
			}
		})
	}
}
