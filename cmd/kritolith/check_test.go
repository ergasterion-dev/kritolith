package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/config"
	"github.com/ergasterion-dev/kritolith/internal/report"
	"github.com/ergasterion-dev/kritolith/internal/store"
)

const netSHA = "e1fcd82abba34df74614020343be8eb1fe85f0d9"

func writeReport(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "report.md")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeConfigFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kritolith.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseInterspersed(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	repo := fs.String("repo", "", "")
	poc := fs.String("poc", "", "")
	pos, err := parseInterspersed(fs, []string{"--repo", "a/b", "report.md", "--poc", "dir"})
	if err != nil {
		t.Fatal(err)
	}
	if *repo != "a/b" || *poc != "dir" || !reflect.DeepEqual(pos, []string{"report.md"}) {
		t.Fatalf("repo=%q poc=%q pos=%v", *repo, *poc, pos)
	}
}

func TestCheckEndToEnd(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	p := writeReport(t, "# Over-read in http2\n\nDetails.")
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"check", "--repo", "golang/net", "--ref", netSHA, "--data-dir", dataDir, p}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code = %d, stderr: %s", code, errOut.String())
	}
	if !strings.HasPrefix(out.String(), "Kritolith: INCONCLUSIVE at e1fcd82abba3\n") {
		t.Fatalf("stdout = %q", out.String())
	}
}

func TestCheckJSONStoresVerdict(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	p := writeReport(t, "no ref report")
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"check", "--json", "--repo", "a/b", "--data-dir", dataDir, p}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code = %d, stderr: %s", code, errOut.String())
	}
	var v report.Verdict
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out.String())
	}
	if v.Outcome != report.OutcomeNeedsInfo {
		t.Fatalf("outcome = %s", v.Outcome)
	}
	s, err := store.Open(context.Background(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.GetVerdict(context.Background(), v.ReportID); err != nil {
		t.Fatalf("verdict not stored: %v", err)
	}
}

func TestCheckErrors(t *testing.T) {
	p := writeReport(t, "report")
	dataDir := filepath.Join(t.TempDir(), "data")
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
	}{
		{"missing repo", []string{"check", p}, 2, "Usage: kritolith check"},
		{"missing report", []string{"check", "--repo", "a/b"}, 2, "Usage: kritolith check"},
		{"two reports", []string{"check", "--repo", "a/b", p, p}, 2, "Usage: kritolith check"},
		{"help", []string{"check", "-h"}, 0, "Usage: kritolith check"},
		{"bad repo", []string{"check", "--repo", "nope", "--data-dir", dataDir, p}, 1, "invalid repo"},
		{"option-like ref", []string{"check", "--repo", "a/b", "--ref=--upload-pack=x", "--data-dir", dataDir, p}, 1, "invalid ref"},
		{"bad config", []string{"check", "--repo", "a/b", "--config", filepath.Join(t.TempDir(), "missing.json"), p}, 1, "config"},
		// Regression: --data-dir must not shortcut past a broken --config.
		{"data-dir set but config missing", []string{"check", "--repo", "a/b", "--data-dir", dataDir, "--config", filepath.Join(t.TempDir(), "missing2.json"), p}, 1, "config"},
		{"repo not a configured project", []string{"check", "--repo", "other/repo", "--data-dir", dataDir, "--config", writeConfigFile(t, `{"projects":[{"repo":"a/b"}]}`), p}, 1, "not one of the configured projects"},
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

// TestCheckSanitizesPoCSymlinkError verifies that a hostile PoC filename
// (a reporter-controlled symlink name carrying terminal escape bytes)
// never reaches stderr unsanitized.
func TestCheckSanitizesPoCSymlinkError(t *testing.T) {
	dir := t.TempDir()
	p := writeReport(t, "report")
	poc := filepath.Join(dir, "poc")
	if err := os.MkdirAll(poc, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	evilName := "a\x1b]0;PWNED\x07\x1b[31mred"
	if err := os.Symlink(target, filepath.Join(poc, evilName)); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(t.TempDir(), "data")
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"check", "--repo", "a/b", "--data-dir", dataDir, "--poc", poc, p}, &out, &errOut)
	if code != 1 {
		t.Fatalf("code = %d, want 1; stderr: %s", code, errOut.String())
	}
	if strings.Contains(errOut.String(), "\x1b") {
		t.Fatalf("stderr contains a raw ESC byte: %q", errOut.String())
	}
}

func TestResolveDataDir(t *testing.T) {
	cfg := &config.Config{DataDir: "/from/config"}
	t.Setenv("XDG_DATA_HOME", "/xdg")
	tests := []struct {
		flagDir string
		cfg     *config.Config
		want    string
	}{
		{"/from/flag", cfg, "/from/flag"},
		{"", cfg, "/from/config"},
		{"", nil, "/xdg/kritolith"},
	}
	for _, tt := range tests {
		got, err := resolveDataDir(tt.flagDir, tt.cfg)
		if err != nil || got != tt.want {
			t.Errorf("resolveDataDir(%q, %v) = %q, %v; want %q", tt.flagDir, tt.cfg, got, err, tt.want)
		}
	}
}

func TestRequireConfiguredProject(t *testing.T) {
	cfg := config.Config{Projects: []config.Project{{Repo: "a/b"}, {Repo: "c/d"}}}
	if err := requireConfiguredProject(cfg, "A/B"); err != nil {
		t.Errorf("case-insensitive match failed: %v", err)
	}
	if err := requireConfiguredProject(cfg, "x/y"); err == nil {
		t.Error("want error for unconfigured repo")
	}
}

func TestCheckWithLLMConfigured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"claims\": [{\"kind\": \"vuln_class\", \"value\": \"dos\", \"evidence\": \"resource exhaustion\"}]}"}}]}`))
	}))
	defer srv.Close()

	cfgBody := fmt.Sprintf(`{
		"projects": [{"repo": "a/b", "allow_cloud": false}],
		"llm": {
			"providers": {"local": {"type": "openaicompat", "base_url": %q, "model": "m"}},
			"tasks": {"extract": ["local"]}
		}
	}`, srv.URL)
	cfgPath := writeConfigFile(t, cfgBody)

	dataDir := filepath.Join(t.TempDir(), "data")
	p := writeReport(t, "See internal/hpack/decode.go:412 for the bug.")
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"check", "--json", "--repo", "a/b", "--ref", netSHA, "--data-dir", dataDir, "--config", cfgPath, p}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code = %d, stderr: %s", code, errOut.String())
	}
	var v report.Verdict
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out.String())
	}
	var hasDeterministic, hasLLM bool
	for _, c := range v.Claims {
		if c.Source == "deterministic" {
			hasDeterministic = true
		}
		if c.Source == "llm:local" {
			hasLLM = true
		}
	}
	if !hasDeterministic {
		t.Errorf("claims = %+v, missing deterministic claim", v.Claims)
	}
	if !hasLLM {
		t.Errorf("claims = %+v, missing LLM claim", v.Claims)
	}
}

func TestCheckBlocksCloudWithoutAllowCloud(t *testing.T) {
	cfgBody := `{
		"projects": [{"repo": "a/b", "allow_cloud": false}],
		"llm": {
			"providers": {"claude": {"type": "anthropic", "api_key_env": "KRITOLITH_TEST_UNSET_KEY", "model": "m"}},
			"tasks": {"extract": ["claude"]}
		}
	}`
	cfgPath := writeConfigFile(t, cfgBody)
	dataDir := filepath.Join(t.TempDir(), "data")
	p := writeReport(t, "See a.go for the bug.")
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"check", "--json", "--repo", "a/b", "--ref", netSHA, "--data-dir", dataDir, "--config", cfgPath, p}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code = %d, stderr: %s", code, errOut.String())
	}
	var v report.Verdict
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
	for _, c := range v.Claims {
		if strings.HasPrefix(c.Source, "llm:") {
			t.Errorf("claims = %+v, cloud provider should have been blocked (no real network call happens either way)", v.Claims)
		}
	}
}
