package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/report"
	"github.com/ergasterion-dev/kritolith/internal/store"
)

const testMessage = "From: someone@example.org\r\n" +
	"Subject: Over-read in the parser\r\n" +
	"Message-ID: <ingest-test@example.org>\r\n" +
	"Content-Type: multipart/mixed; boundary=B\r\n\r\n" +
	"--B\r\nContent-Type: text/plain\r\n\r\nThe function parser.readAll in parser.go overflows.\r\n" +
	"--B\r\nContent-Disposition: attachment; filename=\"poc_test.go\"\r\n\r\npackage p\r\n--B--\r\n"

func TestIngestEMLFromStdin(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	var out, errOut bytes.Buffer
	code := runIO(context.Background(), []string{"ingest", "--eml", "--json", "--repo", "a/b", "--data-dir", dataDir},
		strings.NewReader(testMessage), &out, &errOut)
	if code != 0 {
		t.Fatalf("code = %d, stderr: %s", code, errOut.String())
	}
	var v report.Verdict
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out.String())
	}
	if v.Outcome != report.OutcomeNeedsInfo {
		t.Errorf("outcome = %s, want NEEDS_INFO for a message with no ref", v.Outcome)
	}
	found := false
	for _, c := range v.Claims {
		if c.Kind == report.ClaimFunction && c.Value == "parser.readAll" {
			found = true
		}
	}
	if !found {
		t.Errorf("claims = %+v, missing the function named in the message", v.Claims)
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
	if r.Source != report.SourceEML || r.SourceRef != "<ingest-test@example.org>" || r.Title != "Over-read in the parser" {
		t.Errorf("stored report = %+v", r)
	}
	if len(r.PoC) != 1 || r.PoC[0].Name != "poc_test.go" {
		t.Errorf("stored PoC = %+v", r.PoC)
	}
}

func TestIngestEMLFromFileAndConfig(t *testing.T) {
	msg := filepath.Join(t.TempDir(), "m.eml")
	if err := os.WriteFile(msg, []byte(testMessage), 0o600); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(t.TempDir(), "data")
	// --repo is taken from a config that names exactly one project.
	cfg := writeConfigFile(t, `{"projects":[{"repo":"a/b"}]}`)
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"ingest", "--eml", "--config", cfg, "--data-dir", dataDir, msg}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code = %d, stderr: %s", code, errOut.String())
	}
	if !strings.HasPrefix(out.String(), "Kritolith: NEEDS_INFO") || !strings.Contains(out.String(), "(a/b)") {
		t.Errorf("stdout = %q", out.String())
	}
}

func TestIngestErrors(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	two := writeConfigFile(t, `{"projects":[{"repo":"a/b"},{"repo":"c/d"}]}`)
	tests := []struct {
		name     string
		args     []string
		stdin    string
		wantCode int
		wantErr  string
	}{
		{"no format", []string{"ingest", "--repo", "a/b"}, testMessage, 2, "Usage: kritolith ingest"},
		{"no repo", []string{"ingest", "--eml"}, testMessage, 2, "Usage: kritolith ingest"},
		{"two projects, no repo", []string{"ingest", "--eml", "--config", two, "--data-dir", dataDir}, testMessage, 2, "Usage: kritolith ingest"},
		{"repo not configured", []string{"ingest", "--eml", "--repo", "x/y", "--config", two, "--data-dir", dataDir}, testMessage, 1, "not one of the configured projects"},
		{"two files", []string{"ingest", "--eml", "--repo", "a/b", "one", "two"}, "", 2, "Usage: kritolith ingest"},
		{"help", []string{"ingest", "-h"}, "", 0, "Usage: kritolith ingest"},
		{"empty stdin", []string{"ingest", "--eml", "--repo", "a/b", "--data-dir", dataDir}, "", 1, "empty message"},
		{"not mail", []string{"ingest", "--eml", "--repo", "a/b", "--data-dir", dataDir}, "hello\nworld\n", 1, "not a mail message"},
		{"missing file", []string{"ingest", "--eml", "--repo", "a/b", "--data-dir", dataDir, filepath.Join(t.TempDir(), "nope.eml")}, "", 1, "no such file"},
		{"bad ref", []string{"ingest", "--eml", "--repo", "a/b", "--ref=--x", "--data-dir", dataDir}, testMessage, 1, "invalid ref"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := runIO(context.Background(), tt.args, strings.NewReader(tt.stdin), &out, &errOut)
			if code != tt.wantCode || !strings.Contains(errOut.String(), tt.wantErr) {
				t.Fatalf("code = %d (want %d), stderr = %q (want %q)", code, tt.wantCode, errOut.String(), tt.wantErr)
			}
		})
	}
}
