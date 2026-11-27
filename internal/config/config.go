// Package config loads and validates kritolith.json.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/ergasterion-dev/kritolith/internal/llm"
	"github.com/ergasterion-dev/kritolith/internal/notify"
	"github.com/ergasterion-dev/kritolith/internal/report"
)

const maxConfigBytes = 1 << 20

// Project is one repository Kritolith handles reports for.
type Project struct {
	Repo       string   `json:"repo"`
	AllowCloud bool     `json:"allow_cloud"`
	Notify     []string `json:"notify"`
}

// Config is the parsed kritolith.json.
type Config struct {
	DataDir  string     `json:"data_dir"`
	Projects []Project  `json:"projects"`
	LLM      llm.Config `json:"llm,omitempty"`
	// SMTP says how verdicts are emailed to a project's notify
	// addresses. Without it, --notify is an error.
	SMTP notify.Config `json:"smtp,omitempty"`
	// GitHub configures `kritolith serve`.
	GitHub GitHub `json:"github,omitempty"`
	// Sandbox configures the gVisor PoC sandbox. Without a rootfs it is
	// disabled.
	Sandbox Sandbox `json:"sandbox,omitempty"`
}

// Sandbox is the "sandbox" section. Zero numeric and string values mean
// "use the default"; see WithDefaults.
type Sandbox struct {
	Runtime             string `json:"runtime,omitempty"`
	Rootfs              string `json:"rootfs,omitempty"`
	GoProxy             string `json:"goproxy,omitempty"`
	FetchTimeoutSeconds int    `json:"fetch_timeout_seconds,omitempty"`
	BuildTimeoutSeconds int    `json:"build_timeout_seconds,omitempty"`
	RunTimeoutSeconds   int    `json:"run_timeout_seconds,omitempty"`
	MemoryMB            int    `json:"memory_mb,omitempty"`
	CPUs                int    `json:"cpus,omitempty"`
	PIDs                int    `json:"pids,omitempty"`
	OutputLimitKB       int    `json:"output_limit_kb,omitempty"`
	// WorkDir holds the sandbox's scratch directories, bundles and
	// runtime state. Empty means a sibling of the data dir named
	// "<data_dir>-sandbox". It must neither be, contain, nor lie inside
	// the data dir: the data dir and its keys stay outside anything the
	// sandbox could mount.
	WorkDir string `json:"work_dir,omitempty"`
	// IgnoreCgroups runs the runtime with --ignore-cgroups, so memory,
	// CPU and process limits are NOT enforced by cgroups (rlimits and
	// the wall clock still apply). Only for nested dev setups (runsc in
	// a container) where cgroups cannot be configured; never in
	// production. Kritolith warns loudly at startup when it is set.
	IgnoreCgroups bool `json:"ignore_cgroups,omitempty"`
	// LogRetentionDays bounds how long a report's kept sandbox logs
	// stay under <data_dir>/sandbox-logs/. 0, the default, keeps them
	// forever: the signed verdict carries each log's SHA-256, so
	// removing logs removes evidence and is the operator's choice.
	LogRetentionDays int `json:"log_retention_days,omitempty"`
}

// MaxLogRetentionDays is the largest sandbox.log_retention_days: 100
// years, far below what a time.Duration can hold.
const MaxLogRetentionDays = 36500

// Enabled reports whether a rootfs is configured.
func (s Sandbox) Enabled() bool { return s.Rootfs != "" }

// WithDefaults returns s with every zero field set to its default.
func (s Sandbox) WithDefaults() Sandbox {
	if s.Runtime == "" {
		s.Runtime = "runsc"
	}
	if s.GoProxy == "" {
		s.GoProxy = "https://proxy.golang.org"
	}
	for _, f := range []struct {
		v   *int
		def int
	}{
		{&s.FetchTimeoutSeconds, 900}, {&s.BuildTimeoutSeconds, 900},
		{&s.RunTimeoutSeconds, 120}, {&s.MemoryMB, 2048}, {&s.CPUs, 2},
		{&s.PIDs, 512}, {&s.OutputLimitKB, 1024},
	} {
		if *f.v == 0 {
			*f.v = f.def
		}
	}
	return s
}

// Validate checks the sandbox section's values.
func (s Sandbox) Validate() error {
	for _, f := range []struct {
		name string
		v    int
	}{
		{"fetch_timeout_seconds", s.FetchTimeoutSeconds},
		{"build_timeout_seconds", s.BuildTimeoutSeconds},
		{"run_timeout_seconds", s.RunTimeoutSeconds},
		{"memory_mb", s.MemoryMB}, {"cpus", s.CPUs}, {"pids", s.PIDs},
		{"output_limit_kb", s.OutputLimitKB},
	} {
		if f.v < 0 {
			return fmt.Errorf("sandbox.%s must not be negative", f.name)
		}
	}
	if s.LogRetentionDays < 0 {
		return fmt.Errorf("sandbox.log_retention_days must not be negative")
	}
	if s.LogRetentionDays > MaxLogRetentionDays {
		return fmt.Errorf("sandbox.log_retention_days must be at most %d", MaxLogRetentionDays)
	}
	if s.Rootfs != "" && !filepath.IsAbs(s.Rootfs) {
		return fmt.Errorf("sandbox.rootfs %q must be an absolute path", s.Rootfs)
	}
	if s.Rootfs != "" && filepath.Clean(s.Rootfs) != s.Rootfs {
		return fmt.Errorf("sandbox.rootfs %q must be a clean path (no .., no trailing slash)", s.Rootfs)
	}
	if s.WorkDir != "" {
		switch {
		case strings.ContainsRune(s.WorkDir, 0) || !filepath.IsAbs(s.WorkDir):
			return fmt.Errorf("sandbox.work_dir %q must be an absolute path", s.WorkDir)
		case filepath.Clean(s.WorkDir) != s.WorkDir:
			return fmt.Errorf("sandbox.work_dir %q must be a clean path (no .., no trailing slash)", s.WorkDir)
		case s.WorkDir == "/":
			return fmt.Errorf("sandbox.work_dir must not be /")
		case s.Rootfs != "" && (pathWithin(s.Rootfs, s.WorkDir) || pathWithin(s.WorkDir, s.Rootfs)):
			// The sandbox deletes what it left in its work dir: the work
			// dir must be a directory of its own, never the rootfs's parent.
			return fmt.Errorf("sandbox.work_dir %q and sandbox.rootfs %q must not overlap; use a dedicated, empty directory as the work dir", s.WorkDir, s.Rootfs)
		}
	}
	if s.GoProxy != "" {
		if err := ValidateGoProxy(s.GoProxy); err != nil {
			return fmt.Errorf("sandbox.goproxy: %w", err)
		}
	}
	return nil
}

// ValidateGoProxy checks a GOPROXY value for the sandbox's fetch phase:
// exactly one proxy URL, never a list (',' or '|'), never the keywords
// "direct" or "off", never file://; https, or http only to a loopback
// host; no userinfo, query or fragment. A list could fall back to
// "direct", which would let `go mod download` reach any VCS host.
func ValidateGoProxy(p string) error {
	if p == "" || strings.ContainsAny(p, ",|") || strings.IndexFunc(p, unicode.IsSpace) >= 0 {
		return fmt.Errorf("%q must be a single proxy URL (no list, no whitespace)", p)
	}
	if p == "direct" || p == "off" {
		return fmt.Errorf("%q: the sandbox needs a proxy, not %q", p, p)
	}
	u, err := url.Parse(p)
	if err != nil || u.Hostname() == "" || u.Opaque != "" {
		return fmt.Errorf("%q is not a valid URL", p)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(p, "#") {
		return fmt.Errorf("%q must not carry userinfo, a query or a fragment", p)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return fmt.Errorf("%q: http is only allowed for loopback hosts", p)
		}
	default:
		return fmt.Errorf("%q must be https:// (or http:// to loopback)", p)
	}
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// GitHub is the "github" section: how `kritolith serve` authenticates
// webhook deliveries and reads the reports they announce. Both secrets
// are named by environment variable and never written in the file.
type GitHub struct {
	// WebhookSecretEnv names the variable holding the webhook secret
	// configured on GitHub.
	WebhookSecretEnv string `json:"webhook_secret_env,omitempty"`
	// TokenEnv names the variable holding a token that can read the
	// projects' security advisories. Empty means GITHUB_TOKEN.
	TokenEnv string `json:"token_env,omitempty"`
	// APIURL is the REST API base URL. Empty means github.com.
	APIURL string `json:"api_url,omitempty"`
}

// Load reads, strictly decodes and validates the config at path.
func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	defer f.Close()

	dec := json.NewDecoder(io.LimitReader(f, maxConfigBytes))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("config: parse %s: trailing data after the JSON object", path)
	}
	if err := c.Validate(); err != nil {
		return Config{}, fmt.Errorf("config: %s: %w", path, err)
	}
	return c, nil
}

// Validate checks field values that JSON decoding can't.
func (c Config) Validate() error {
	if c.DataDir != "" && !filepath.IsAbs(c.DataDir) {
		return fmt.Errorf("data_dir %q must be an absolute path", c.DataDir)
	}
	seen := make(map[string]bool, len(c.Projects))
	for i, p := range c.Projects {
		if err := report.ValidateRepo(p.Repo); err != nil {
			return fmt.Errorf("projects[%d]: %w", i, err)
		}
		key := strings.ToLower(p.Repo)
		if seen[key] {
			return fmt.Errorf("projects[%d]: duplicate repo %q", i, p.Repo)
		}
		seen[key] = true
		for _, addr := range p.Notify {
			if _, err := mail.ParseAddress(addr); err != nil {
				return fmt.Errorf("projects[%d].notify: %q: %w", i, addr, err)
			}
		}
	}
	if err := c.LLM.Validate(); err != nil {
		return err
	}
	if err := c.SMTP.Validate(); err != nil {
		return err
	}
	return c.Sandbox.Validate()
}

// DefaultDataDir is $XDG_DATA_HOME/kritolith, or ~/.local/share/kritolith.
func DefaultDataDir() (string, error) {
	if x := os.Getenv("XDG_DATA_HOME"); x != "" && filepath.IsAbs(x) {
		return filepath.Join(x, "kritolith"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("config: default data dir: %w", err)
	}
	return filepath.Join(home, ".local", "share", "kritolith"), nil
}

// NotifyAddresses returns the notify list of the project matching
// repo (case-insensitive), or nil.
func (c Config) NotifyAddresses(repo string) []string {
	for _, p := range c.Projects {
		if strings.EqualFold(p.Repo, repo) {
			return p.Notify
		}
	}
	return nil
}

// pathWithin reports whether p is dir or lies inside it. Both are
// clean absolute paths.
func pathWithin(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}
