package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kritolith.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadExample(t *testing.T) {
	c, err := Load("../../kritolith.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if c.DataDir != "/var/lib/kritolith" || len(c.Projects) != 1 || c.Projects[0].Repo != "owner/name" {
		t.Fatalf("unexpected config: %+v", c)
	}
	if len(c.LLM) == 0 || len(c.Sandbox) == 0 {
		t.Fatal("llm/sandbox sections were dropped")
	}
}

func TestLoadRejects(t *testing.T) {
	tests := []struct {
		name, body, wantErr string
	}{
		{"unknown field", `{"data_dir":"/x","colour":"blue"}`, "unknown field"},
		{"relative data dir", `{"data_dir":"data"}`, "absolute"},
		{"bad repo", `{"projects":[{"repo":"nope"}]}`, "invalid repo"},
		{"duplicate repo", `{"projects":[{"repo":"a/b"},{"repo":"A/B"}]}`, "duplicate"},
		{"bad email", `{"projects":[{"repo":"a/b","notify":["not an email"]}]}`, "notify"},
		{"trailing data", `{"data_dir":"/x"} {"data_dir":"/y"}`, "trailing"},
		{"not json", `data_dir = "/x"`, "parse"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tt.body))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("want error for missing file")
	}
}

func TestDefaultDataDir(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/xdg")
	got, err := DefaultDataDir()
	if err != nil || got != "/xdg/kritolith" {
		t.Fatalf("with XDG: %q, %v", got, err)
	}
	t.Setenv("XDG_DATA_HOME", "relative/ignored")
	t.Setenv("HOME", "/home/k")
	got, err = DefaultDataDir()
	if err != nil || got != "/home/k/.local/share/kritolith" {
		t.Fatalf("without XDG: %q, %v", got, err)
	}
}
