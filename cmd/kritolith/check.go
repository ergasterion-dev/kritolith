package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ergasterion-dev/kritolith/internal/config"
	"github.com/ergasterion-dev/kritolith/internal/dedupe"
	"github.com/ergasterion-dev/kritolith/internal/ground"
	"github.com/ergasterion-dev/kritolith/internal/intake/file"
	"github.com/ergasterion-dev/kritolith/internal/intake/github"
	"github.com/ergasterion-dev/kritolith/internal/llm"
	"github.com/ergasterion-dev/kritolith/internal/pipeline"
	"github.com/ergasterion-dev/kritolith/internal/report"
	"github.com/ergasterion-dev/kritolith/internal/store"
	"github.com/ergasterion-dev/kritolith/internal/verdict"
)

func runCheck(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	repo := fs.String("repo", "", "repository as owner/name (required)")
	ref := fs.String("ref", "", "commit SHA or tag the reporter tested")
	poc := fs.String("poc", "", "directory containing PoC files")
	cfgPath := fs.String("config", "", "path to kritolith.json")
	dataDir := fs.String("data-dir", "", "data directory (overrides config)")
	asJSON := fs.Bool("json", false, "print the verdict as JSON")
	ghsa := fs.String("ghsa", "", "read the report from this GitHub security advisory (GHSA-xxxx-xxxx-xxxx) instead of a file; needs a token in GITHUB_TOKEN or GH_TOKEN")
	apiURL := fs.String("github-api-url", github.DefaultAPIURL, "GitHub REST API base URL (GitHub Enterprise Server: https://host/api/v3)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: kritolith check --repo owner/name [--ref sha] [--poc dir] report.md")
		fmt.Fprintln(stderr, "       kritolith check --repo owner/name [--ref sha] --ghsa GHSA-xxxx-xxxx-xxxx")
		fs.PrintDefaults()
	}

	pos, err := parseInterspersed(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		return 2
	}
	if *repo == "" || (*ghsa == "" && len(pos) != 1) || (*ghsa != "" && len(pos) != 0) {
		fs.Usage()
		return 2
	}
	if *ghsa != "" && *poc != "" {
		fmt.Fprintln(stderr, "kritolith: --poc cannot be combined with --ghsa: an advisory carries no PoC files")
		return 2
	}

	// --config is always loaded when given, even if --data-dir is also
	// given: a broken --config must never be silently ignored.
	var cfg *config.Config
	if *cfgPath != "" {
		c, err := config.Load(*cfgPath)
		if err != nil {
			return fail(stderr, err)
		}
		cfg = &c
	}
	if cfg != nil && len(cfg.Projects) > 0 {
		if err := requireConfiguredProject(*cfg, *repo); err != nil {
			return fail(stderr, err)
		}
	}
	dir, err := resolveDataDir(*dataDir, cfg)
	if err != nil {
		return fail(stderr, err)
	}
	var r report.Report
	if *ghsa != "" {
		token, err := githubToken(os.Getenv)
		if err != nil {
			return fail(stderr, err)
		}
		r, err = github.Load(ctx, github.Options{Repo: *repo, GHSAID: *ghsa, Ref: *ref, Token: token, APIURL: *apiURL})
		if err != nil {
			return fail(stderr, err)
		}
	} else {
		r, err = file.Load(file.Options{Repo: *repo, Ref: *ref, ReportPath: pos[0], PoCDir: *poc})
		if err != nil {
			return fail(stderr, err)
		}
	}
	return runReport(ctx, r, cfg, dir, *asJSON, stdout, stderr)
}

// runReport sends one report through the pipeline and prints its
// verdict. Every intake command ends here, so a report is handled the
// same way however it arrived.
func runReport(ctx context.Context, r report.Report, cfg *config.Config, dir string, asJSON bool, stdout, stderr io.Writer) int {
	st, err := store.Open(ctx, dir)
	if err != nil {
		return fail(stderr, err)
	}
	defer st.Close()

	var router *llm.Router
	if cfg != nil {
		router, err = buildRouter(*cfg, nil)
		if err != nil {
			return fail(stderr, err)
		}
	}
	p := pipeline.New(st).WithGround(ground.NewService(dir)).WithDedupe(dedupe.NewService(st, router))
	if router != nil {
		p = p.WithLLM(router)
	}

	v, err := p.Run(ctx, r)
	if err != nil {
		return fail(stderr, err)
	}
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(v); err != nil {
			return fail(stderr, err)
		}
		return 0
	}
	fmt.Fprint(stdout, verdict.Render(r, v))
	return 0
}

// githubToken reads the token for --ghsa from the environment:
// GITHUB_TOKEN, then GH_TOKEN (the names the GitHub CLI uses). There
// is deliberately no flag for it: a command line is visible to every
// user on the machine and is saved in shell history.
func githubToken(getenv func(string) string) (string, error) {
	for _, name := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		if v := getenv(name); v != "" {
			return v, nil
		}
	}
	return "", errors.New("--ghsa needs a GitHub token in GITHUB_TOKEN or GH_TOKEN; it must be able to read the repository's security advisories")
}
