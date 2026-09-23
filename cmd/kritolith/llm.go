package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/ergasterion-dev/kritolith/internal/config"
	"github.com/ergasterion-dev/kritolith/internal/llm"
	"github.com/ergasterion-dev/kritolith/internal/llm/anthropic"
	"github.com/ergasterion-dev/kritolith/internal/llm/gemini"
	"github.com/ergasterion-dev/kritolith/internal/llm/openaicompat"
)

// buildRouter turns cfg's LLM section into a live router, or returns a
// nil router if no providers are configured. Kritolith must work with
// no LLM configured, so an empty llm.Config is not an error here.
func buildRouter(cfg config.Config, logger *slog.Logger) (*llm.Router, error) {
	if len(cfg.LLM.Providers) == 0 {
		return nil, nil
	}
	providers := make(map[string]llm.Provider, len(cfg.LLM.Providers))
	for name, pc := range cfg.LLM.Providers {
		apiKey := ""
		if pc.APIKeyEnv != "" {
			apiKey = os.Getenv(pc.APIKeyEnv)
		}
		switch pc.Type {
		case llm.ProviderOpenAICompat:
			a, err := openaicompat.New(openaicompat.Options{Name: name, BaseURL: pc.BaseURL, Model: pc.Model, APIKey: apiKey})
			if err != nil {
				return nil, fmt.Errorf("llm: providers[%q]: %w", name, err)
			}
			providers[name] = a
		case llm.ProviderAnthropic:
			providers[name] = anthropic.New(anthropic.Options{Name: name, BaseURL: pc.BaseURL, Model: pc.Model, APIKey: apiKey})
		case llm.ProviderGemini:
			providers[name] = gemini.New(gemini.Options{Name: name, BaseURL: pc.BaseURL, Model: pc.Model, APIKey: apiKey})
		default:
			return nil, fmt.Errorf("llm: providers[%q]: unknown type %q", name, pc.Type)
		}
	}
	allowCloud := func(repo string) bool {
		for _, p := range cfg.Projects {
			if strings.EqualFold(p.Repo, repo) {
				return p.AllowCloud
			}
		}
		return false
	}
	return llm.NewRouter(providers, cfg.LLM.Tasks, allowCloud, logger), nil
}
