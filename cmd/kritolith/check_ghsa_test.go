package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/report"
	"github.com/ergasterion-dev/kritolith/internal/store"
)

const testGHSA = "GHSA-mh63-6h87-95cp"

func TestCheckGHSA(t *testing.T) {
	var auth, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, path = r.Header.Get("Authorization"), r.URL.Path
		_, _ = w.Write([]byte(`{"ghsa_id": "` + testGHSA + `", "summary": "Over-read in the parser", "description": "The function parser.readAll in parser.go overflows.", "state": "triage"}`))
	}))
	defer srv.Close()
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "tok_from_gh")

	dataDir := filepath.Join(t.TempDir(), "data")
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"check", "--json", "--repo", "a/b", "--ghsa", testGHSA, "--github-api-url", srv.URL, "--data-dir", dataDir}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code = %d, stderr: %s", code, errOut.String())
	}
	if auth != "Bearer tok_from_gh" || path != "/repos/a/b/security-advisories/"+testGHSA {
		t.Errorf("request: Authorization %q, path %q", auth, path)
	}
	if strings.Contains(out.String()+errOut.String(), "tok_from_gh") {
		t.Error("the token was printed")
	}
	var v report.Verdict
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out.String())
	}
	// No commit is known for an advisory unless --ref is given.
	if v.Outcome != report.OutcomeNeedsInfo {
		t.Errorf("outcome = %s, want NEEDS_INFO", v.Outcome)
	}
	found := false
	for _, c := range v.Claims {
		if c.Kind == report.ClaimFunction && c.Value == "parser.readAll" {
			found = true
		}
	}
	if !found {
		t.Errorf("claims = %+v, missing the function named in the advisory", v.Claims)
	}

	s, err := store.Open(context.Background(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r, err := s.GetReport(context.Background(), v.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if r.Source != report.SourceGitHubPVR || r.SourceRef != testGHSA || r.Title != "Over-read in the parser" {
		t.Errorf("stored report = %+v", r)
	}
}

func TestCheckGHSAPrefersGitHubToken(t *testing.T) {
	got, err := githubToken(func(name string) string {
		return map[string]string{"GITHUB_TOKEN": "a", "GH_TOKEN": "b"}[name]
	})
	if err != nil || got != "a" {
		t.Fatalf("githubToken = %q, %v", got, err)
	}
	if _, err := githubToken(func(string) string { return "" }); err == nil {
		t.Fatal("want an error with no token set")
	}
}

func TestCheckGHSAErrors(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	p := writeReport(t, "report")
	dataDir := filepath.Join(t.TempDir(), "data")
	tests := []struct {
		name     string
		token    string
		args     []string
		wantCode int
		wantErr  string
		wantCall bool
	}{
		{"file and advisory", "tok", []string{"check", "--repo", "a/b", "--ghsa", testGHSA, p}, 2, "Usage: kritolith check", false},
		{"poc with advisory", "tok", []string{"check", "--repo", "a/b", "--ghsa", testGHSA, "--poc", t.TempDir()}, 2, "--poc cannot be combined", false},
		{"missing repo", "tok", []string{"check", "--ghsa", testGHSA}, 2, "Usage: kritolith check", false},
		{"no token", "", []string{"check", "--repo", "a/b", "--ghsa", testGHSA, "--data-dir", dataDir, "--github-api-url", srv.URL}, 1, "GITHUB_TOKEN or GH_TOKEN", false},
		{"bad id", "tok", []string{"check", "--repo", "a/b", "--ghsa", "GHSA-nope", "--data-dir", dataDir, "--github-api-url", srv.URL}, 1, "invalid advisory ID", false},
		{"plain http api", "tok", []string{"check", "--repo", "a/b", "--ghsa", testGHSA, "--data-dir", dataDir, "--github-api-url", "http://api.github.example"}, 1, "must use https", false},
		{"not found", "tok", []string{"check", "--repo", "a/b", "--ghsa", testGHSA, "--data-dir", dataDir, "--github-api-url", srv.URL}, 1, "not found (404)", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called = false
			t.Setenv("GITHUB_TOKEN", tt.token)
			t.Setenv("GH_TOKEN", "")
			var out, errOut bytes.Buffer
			code := run(context.Background(), tt.args, &out, &errOut)
			if code != tt.wantCode || !strings.Contains(errOut.String(), tt.wantErr) {
				t.Fatalf("code = %d (want %d), stderr = %q (want %q)", code, tt.wantCode, errOut.String(), tt.wantErr)
			}
			if called != tt.wantCall {
				t.Fatalf("API called = %v, want %v", called, tt.wantCall)
			}
			if out.Len() != 0 {
				t.Fatalf("stdout = %q, want nothing on failure", out.String())
			}
		})
	}
}
