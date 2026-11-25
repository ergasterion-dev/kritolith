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
	if len(c.LLM.Providers) == 0 || len(c.LLM.Tasks) == 0 || c.Sandbox.Runtime == "" {
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

func TestSandboxDefaults(t *testing.T) {
	c, err := Load(writeConfig(t, `{"sandbox":{"rootfs":"/x"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Sandbox.Enabled() {
		t.Fatal("rootfs set: want Enabled")
	}
	want := Sandbox{
		Runtime: "runsc", Rootfs: "/x", GoProxy: "https://proxy.golang.org",
		FetchTimeoutSeconds: 300, BuildTimeoutSeconds: 300, RunTimeoutSeconds: 120,
		MemoryMB: 2048, CPUs: 2, PIDs: 512, OutputLimitKB: 1024,
	}
	if got := c.Sandbox.WithDefaults(); got != want {
		t.Fatalf("WithDefaults = %+v, want %+v", got, want)
	}
	custom := Sandbox{Runtime: "r", MemoryMB: 7}.WithDefaults()
	if custom.Runtime != "r" || custom.MemoryMB != 7 || custom.CPUs != 2 {
		t.Fatalf("WithDefaults overwrote set values: %+v", custom)
	}
}

func TestSandboxDisabledWhenEmpty(t *testing.T) {
	for _, body := range []string{`{}`, `{"sandbox":{}}`} {
		c, err := Load(writeConfig(t, body))
		if err != nil {
			t.Fatal(err)
		}
		if c.Sandbox.Enabled() {
			t.Fatalf("%s: want not Enabled", body)
		}
	}
}

func TestSandboxRejects(t *testing.T) {
	tests := []struct{ name, body, wantErr string }{
		{"unknown key", `{"sandbox":{"rootfs":"/x","bogus":1}}`, "unknown field"},
		{"negative memory", `{"sandbox":{"memory_mb":-1}}`, "memory_mb"},
		{"negative cpus", `{"sandbox":{"cpus":-1}}`, "cpus"},
		{"negative pids", `{"sandbox":{"pids":-1}}`, "pids"},
		{"negative fetch", `{"sandbox":{"fetch_timeout_seconds":-1}}`, "fetch_timeout_seconds"},
		{"negative build", `{"sandbox":{"build_timeout_seconds":-1}}`, "build_timeout_seconds"},
		{"negative run", `{"sandbox":{"run_timeout_seconds":-1}}`, "run_timeout_seconds"},
		{"negative output", `{"sandbox":{"output_limit_kb":-1}}`, "output_limit_kb"},
		{"relative rootfs", `{"sandbox":{"rootfs":"rootfs"}}`, "rootfs"},
		{"http remote proxy", `{"sandbox":{"goproxy":"http://example.org"}}`, "goproxy"},
		{"ftp proxy", `{"sandbox":{"goproxy":"ftp://example.org"}}`, "goproxy"},
		{"no scheme proxy", `{"sandbox":{"goproxy":"proxy.golang.org"}}`, "goproxy"},
		{"proxy no host", `{"sandbox":{"goproxy":"https://"}}`, "goproxy"},
		{"proxy list with direct", `{"sandbox":{"goproxy":"https://p.org/x,direct"}}`, "goproxy"},
		{"proxy pipe list", `{"sandbox":{"goproxy":"https://p.org|https://q.org"}}`, "goproxy"},
		{"proxy keyword direct", `{"sandbox":{"goproxy":"direct"}}`, "goproxy"},
		{"proxy keyword off", `{"sandbox":{"goproxy":"off"}}`, "goproxy"},
		{"proxy file url", `{"sandbox":{"goproxy":"file:///var/cache"}}`, "goproxy"},
		{"proxy whitespace", `{"sandbox":{"goproxy":"https://p.org/ x"}}`, "goproxy"},
		{"proxy userinfo", `{"sandbox":{"goproxy":"https://u:p@host"}}`, "goproxy"},
		{"proxy query", `{"sandbox":{"goproxy":"https://host/x?y"}}`, "goproxy"},
		{"proxy empty query", `{"sandbox":{"goproxy":"https://host/x?"}}`, "goproxy"},
		{"proxy fragment", `{"sandbox":{"goproxy":"https://host/x#f"}}`, "goproxy"},
		{"proxy loopback-looking host", `{"sandbox":{"goproxy":"http://127.0.0.1.evil.com"}}`, "goproxy"},
		{"proxy localhost-looking host", `{"sandbox":{"goproxy":"http://localhost.evil.com"}}`, "goproxy"},
		{"proxy loopback userinfo", `{"sandbox":{"goproxy":"http://127.0.0.1@evil.com"}}`, "goproxy"},
		{"rootfs not clean", `{"sandbox":{"rootfs":"/x/../y"}}`, "rootfs"},
		{"rootfs trailing slash", `{"sandbox":{"rootfs":"/x/"}}`, "rootfs"},
		{"relative work_dir", `{"sandbox":{"work_dir":"work"}}`, "work_dir"},
		{"work_dir not clean", `{"sandbox":{"work_dir":"/x/../y"}}`, "work_dir"},
		{"work_dir trailing slash", `{"sandbox":{"work_dir":"/x/y/"}}`, "work_dir"},
		{"work_dir root", `{"sandbox":{"work_dir":"/"}}`, "work_dir"},
		{"work_dir NUL", `{"sandbox":{"work_dir":"/x/\u0000y"}}`, "work_dir"},
		{"rootfs inside work_dir", `{"sandbox":{"rootfs":"/var/lib/kritolith-rootfs/go1.26.0","work_dir":"/var/lib"}}`, "work_dir"},
		{"rootfs equals work_dir", `{"sandbox":{"rootfs":"/srv/k","work_dir":"/srv/k"}}`, "work_dir"},
		{"rootfs contains work_dir", `{"sandbox":{"rootfs":"/srv/k","work_dir":"/srv/k/work"}}`, "work_dir"},
		{"ignore_cgroups not bool", `{"sandbox":{"ignore_cgroups":"yes"}}`, "ignore_cgroups"},
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

func TestSandboxWorkDirAndCgroups(t *testing.T) {
	c, err := Load(writeConfig(t, `{"sandbox":{"rootfs":"/x","work_dir":"/var/lib/kritolith-sandbox","ignore_cgroups":true}}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Sandbox.WorkDir != "/var/lib/kritolith-sandbox" || !c.Sandbox.IgnoreCgroups {
		t.Fatalf("sandbox = %+v", c.Sandbox)
	}
	d := c.Sandbox.WithDefaults()
	if d.WorkDir != c.Sandbox.WorkDir || !d.IgnoreCgroups {
		t.Fatalf("WithDefaults changed work_dir/ignore_cgroups: %+v", d)
	}
	c, err = Load(writeConfig(t, `{"sandbox":{"rootfs":"/x"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Sandbox.WorkDir != "" || c.Sandbox.IgnoreCgroups {
		t.Fatalf("defaults: %+v; want no work_dir (the caller derives it) and cgroups on", c.Sandbox)
	}
}

func TestSandboxAcceptsProxies(t *testing.T) {
	for _, u := range []string{"https://proxy.golang.org", "https://goproxy.example.org/mirror/", "http://127.0.0.1:3000", "http://localhost:3000", "http://[::1]:3000"} {
		if _, err := Load(writeConfig(t, `{"sandbox":{"goproxy":"`+u+`"}}`)); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
}

func TestValidateGoProxy(t *testing.T) {
	for _, u := range []string{"https://proxy.golang.org", "http://127.0.0.1:3000"} {
		if err := ValidateGoProxy(u); err != nil {
			t.Errorf("ValidateGoProxy(%q) = %v, want nil", u, err)
		}
	}
	for _, u := range []string{"", "https://p.org/x,direct", "direct", "off", "file:///x", "https://u:p@host", "https://host/x?y", "http://127.0.0.1@evil.com", " https://p.org"} {
		if err := ValidateGoProxy(u); err == nil {
			t.Errorf("ValidateGoProxy(%q) = nil, want an error", u)
		}
	}
}
