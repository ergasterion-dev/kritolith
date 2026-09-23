package llm

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
)

// ProviderType is a supported adapter kind.
type ProviderType string

const (
	ProviderOpenAICompat ProviderType = "openaicompat"
	ProviderAnthropic    ProviderType = "anthropic"
	ProviderGemini       ProviderType = "gemini"
)

// ProviderConfig is one entry under llm.providers in kritolith.json.
type ProviderConfig struct {
	Type      ProviderType `json:"type"`
	BaseURL   string       `json:"base_url,omitempty"`
	Model     string       `json:"model"`
	APIKeyEnv string       `json:"api_key_env,omitempty"`
}

// Config is the parsed llm section of kritolith.json.
type Config struct {
	Providers map[string]ProviderConfig `json:"providers,omitempty"`
	Tasks     map[string][]string       `json:"tasks,omitempty"`
}

var validTasks = map[string]bool{"extract": true, "embed": true, "draft": true}

// Validate checks field values JSON decoding can't: known provider
// types, well-formed base URLs, task chains that only name configured
// providers, and known task names. An empty Config (no LLM configured)
// is valid.
func (c Config) Validate() error {
	names := make([]string, 0, len(c.Providers))
	for name := range c.Providers {
		names = append(names, name)
	}
	sort.Strings(names)
	known := make(map[string]bool, len(names))
	for _, name := range names {
		p := c.Providers[name]
		known[name] = true
		switch p.Type {
		case ProviderOpenAICompat:
			if p.BaseURL == "" {
				return fmt.Errorf("llm: providers[%q]: base_url is required for type %q", name, p.Type)
			}
		case ProviderAnthropic, ProviderGemini:
			// base_url is optional: the adapter defaults to the
			// provider's public endpoint when empty.
		default:
			return fmt.Errorf("llm: providers[%q]: unknown type %q", name, p.Type)
		}
		if p.BaseURL != "" {
			u, err := url.Parse(p.BaseURL)
			if err != nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") {
				return fmt.Errorf("llm: providers[%q]: base_url %q must be an absolute http(s) URL", name, p.BaseURL)
			}
		}
		if p.Model == "" {
			return fmt.Errorf("llm: providers[%q]: model is required", name)
		}
	}

	taskNames := make([]string, 0, len(c.Tasks))
	for t := range c.Tasks {
		taskNames = append(taskNames, t)
	}
	sort.Strings(taskNames)
	for _, t := range taskNames {
		if !validTasks[t] {
			return fmt.Errorf("llm: tasks[%q]: unknown task", t)
		}
		for _, p := range c.Tasks[t] {
			if !known[p] {
				return fmt.Errorf("llm: tasks[%q]: unknown provider %q", t, p)
			}
		}
	}
	return nil
}

// IsLocalHost reports whether host (from a base_url) resolves to
// loopback, RFC1918/link-local, or a literal "localhost"/".local"
// name. It never performs a network DNS lookup: only literal IPs and
// the "localhost"/".local" hostnames are treated as local, so a
// rebindable public hostname is never mistaken for local. This is what
// decides whether a report's embargoed text can leave the host, so it
// fails closed on anything it can't prove is local.
func IsLocalHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}
