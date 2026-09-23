package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/ergasterion-dev/kritolith/internal/config"
	"github.com/ergasterion-dev/kritolith/internal/intake/file"
	"github.com/ergasterion-dev/kritolith/internal/pipeline"
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
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: kritolith check --repo owner/name [--ref sha] [--poc dir] report.md")
		fs.PrintDefaults()
	}

	pos, err := parseInterspersed(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		return 2
	}
	if len(pos) != 1 || *repo == "" {
		fs.Usage()
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
	dir, err := resolveDataDir(*dataDir, cfg)
	if err != nil {
		return fail(stderr, err)
	}
	r, err := file.Load(file.Options{Repo: *repo, Ref: *ref, ReportPath: pos[0], PoCDir: *poc})
	if err != nil {
		return fail(stderr, err)
	}
	st, err := store.Open(ctx, dir)
	if err != nil {
		return fail(stderr, err)
	}
	defer st.Close()

	v, err := pipeline.New(st).Run(ctx, r)
	if err != nil {
		return fail(stderr, err)
	}
	if *asJSON {
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
