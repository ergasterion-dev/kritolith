package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ergasterion-dev/kritolith/internal/config"
	"github.com/ergasterion-dev/kritolith/internal/intake/eml"
)

// runIngest reads one report in a wire format and verifies it. The
// only format today is a raw email message.
func runIngest(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ingest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	isEML := fs.Bool("eml", false, "the input is a raw email message (RFC 5322); required")
	repo := fs.String("repo", "", "repository as owner/name (required; with --config naming one project, that project)")
	ref := fs.String("ref", "", "commit SHA or tag the reporter tested, if known")
	cfgPath := fs.String("config", "", "path to kritolith.json")
	dataDir := fs.String("data-dir", "", "data directory (overrides config)")
	asJSON := fs.Bool("json", false, "print the verdict as JSON")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: kritolith ingest --eml --repo owner/name [--ref sha] < message.eml")
		fmt.Fprintln(stderr, "       kritolith ingest --eml --repo owner/name [--ref sha] message.eml")
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		return 2
	}
	if !*isEML || len(pos) > 1 {
		fs.Usage()
		return 2
	}

	var cfg *config.Config
	if *cfgPath != "" {
		c, err := config.Load(*cfgPath)
		if err != nil {
			return fail(stderr, err)
		}
		cfg = &c
	}
	// A mail pipe is set up once per mailbox, and a mailbox belongs to
	// one project, so a config that names exactly one project says
	// which repository the message is about.
	if *repo == "" && cfg != nil && len(cfg.Projects) == 1 {
		*repo = cfg.Projects[0].Repo
	}
	if *repo == "" {
		fs.Usage()
		return 2
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

	in := stdin
	if len(pos) == 1 && pos[0] != "-" {
		f, err := os.Open(pos[0])
		if err != nil {
			return fail(stderr, err)
		}
		defer f.Close()
		in = f
	}
	r, err := eml.Load(in, eml.Options{Repo: *repo, Ref: *ref})
	if err != nil {
		return fail(stderr, err)
	}
	return runReport(ctx, r, cfg, dir, *asJSON, stdout, stderr)
}
