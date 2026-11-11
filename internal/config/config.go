// Package config loads and validates kritolith.json.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"os"
	"path/filepath"
	"strings"

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
	// Sandbox is parsed by a later milestone. Kept raw so documented
	// config files stay valid today.
	Sandbox json.RawMessage `json:"sandbox,omitempty"`
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
	return nil
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
