package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

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

	dir, err := resolveDataDir(*dataDir, *cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "kritolith: %v\n", err)
		return 1
	}
	r, err := file.Load(file.Options{Repo: *repo, Ref: *ref, ReportPath: pos[0], PoCDir: *poc})
	if err != nil {
		fmt.Fprintf(stderr, "kritolith: %v\n", err)
		return 1
	}
	st, err := store.Open(ctx, dir)
	if err != nil {
		fmt.Fprintf(stderr, "kritolith: %v\n", err)
		return 1
	}
	defer st.Close()

	v, err := pipeline.New(st).Run(ctx, r)
	if err != nil {
		fmt.Fprintf(stderr, "kritolith: %v\n", err)
		return 1
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(v); err != nil {
			fmt.Fprintf(stderr, "kritolith: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprint(stdout, verdict.Render(r, v))
	return 0
}
