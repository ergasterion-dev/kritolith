package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

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

func TestResolveDataDir(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "k.json")
	if err := os.WriteFile(cfg, []byte(`{"data_dir":"/from/config"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_DATA_HOME", "/xdg")
	tests := []struct{ flagDir, cfg, want string }{
		{"/from/flag", cfg, "/from/flag"},
		{"", cfg, "/from/config"},
		{"", "", "/xdg/kritolith"},
	}
	for _, tt := range tests {
		got, err := resolveDataDir(tt.flagDir, tt.cfg)
		if err != nil || got != tt.want {
			t.Errorf("resolveDataDir(%q, %q) = %q, %v; want %q", tt.flagDir, tt.cfg, got, err, tt.want)
		}
	}
}
