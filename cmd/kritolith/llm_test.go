package main

import (
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/config"
	"github.com/ergasterion-dev/kritolith/internal/llm"
)

// TestBuildRouterDeniesCloudForRepoAbsentFromProjects closes a
// coverage gap flagged in Task 9's review: cmd/kritolith/check.go
// calls requireConfiguredProject before buildRouter, so a repo
// entirely absent from cfg.Projects never reaches buildRouter's
// allowCloud closure through that path. But eval.go's runEval calls
// buildRouter directly, with no equivalent requireConfiguredProject
// call, so an absent-repo case CAN reach the closure there. This test
// exercises buildRouter's allowCloud closure directly, independent of
// either CLI command, and proves it denies a repo that isn't present
// in cfg.Projects at all -- not just one present with
// "allow_cloud": false explicitly.
func TestBuildRouterDeniesCloudForRepoAbsentFromProjects(t *testing.T) {
	cfg := config.Config{
		Projects: []config.Project{
			{Repo: "known/repo", AllowCloud: true},
		},
		LLM: llm.Config{
			Providers: map[string]llm.ProviderConfig{
				"claude": {Type: llm.ProviderAnthropic, Model: "m"},
			},
			Tasks: map[string][]string{"extract": {"claude"}},
		},
	}
	router, err := buildRouter(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if router == nil {
		t.Fatal("router is nil, want a configured router")
	}

	// A repo present in cfg.Projects with allow_cloud: true must be
	// allowed, proving the router is wired correctly before we assert
	// on the absent-repo case.
	if chain := router.Chain("extract", "R1", "known/repo"); len(chain) == 0 {
		t.Fatal("chain for known/repo with allow_cloud true = empty, want the cloud provider present")
	}

	// The actual regression case: a repo that never appears in
	// cfg.Projects at all (not "allow_cloud": false, just absent).
	if chain := router.Chain("extract", "R1", "totally/unconfigured"); len(chain) != 0 {
		t.Fatalf("chain for a repo absent from cfg.Projects = %v, want empty (cloud must be denied by default)", chain)
	}
}
