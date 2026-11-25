package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ergasterion-dev/kritolith/internal/config"
	"github.com/ergasterion-dev/kritolith/internal/eval"
	"github.com/ergasterion-dev/kritolith/internal/intake/file"
)

func runEval(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	fs.SetOutput(stderr)
	corpus := fs.String("corpus", "testdata/corpus", "corpus directory")
	dataDir := fs.String("data-dir", "", "keep results in this data dir (default: a temporary dir, removed afterwards)")
	cfgPath := fs.String("config", "", "path to kritolith.json (runs extraction and LLM routing over the corpus)")
	only := fs.String("case", "", "run only these corpus cases, by id, comma-separated (a near-duplicate case also runs the case it duplicates)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: kritolith eval [--corpus dir] [--case id[,id]] [--data-dir dir] [--config file]")
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		return 2
	}
	if len(pos) != 0 {
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

	cases, err := eval.LoadCorpus(*corpus)
	if err != nil {
		return fail(stderr, err)
	}
	if *only != "" {
		if cases, err = eval.Select(cases, strings.Split(*only, ",")); err != nil {
			return fail(stderr, err)
		}
	}
	dir := *dataDir
	if dir != "" {
		if dir, err = filepath.Abs(dir); err != nil {
			return fail(stderr, err)
		}
	} else {
		tmp, err := os.MkdirTemp("", "kritolith-eval-")
		if err != nil {
			return fail(stderr, err)
		}
		defer os.RemoveAll(tmp)
		// The data dir sits one level down so the sandbox's default work
		// dir (a sibling, "<data>-sandbox") is inside tmp and is removed
		// with it.
		dir = filepath.Join(tmp, "data")
	}
	// The same construction as `check`: with --config, the LLM router
	// and (when configured) the sandbox; without it, deterministic
	// extraction, grounding and dedupe only.
	pr, err := newProcessor(ctx, cfg, dir, stderr)
	if err != nil {
		return fail(stderr, err)
	}
	defer pr.close()

	sb := eval.Run(ctx, cases, func(ctx context.Context, c eval.Case) (eval.CheckResult, error) {
		opts := file.Options{Repo: c.Meta.Repo, Ref: c.Meta.Ref, ReportPath: filepath.Join(c.Dir, "report.md")}
		if c.HasPoC {
			opts.PoCDir = filepath.Join(c.Dir, "poc")
		}
		r, err := file.Load(opts)
		if err != nil {
			return eval.CheckResult{}, err
		}
		r.PoCDir = c.Meta.PoCDir
		v, err := pr.run(ctx, r)
		if err != nil {
			return eval.CheckResult{}, err
		}
		return eval.CheckResult{Outcome: v.Outcome, ReportID: r.ID, Duplicates: v.Duplicates}, nil
	})
	sb.SandboxConfigured = pr.sandbox != nil
	if err := sb.Write(stdout); err != nil {
		return fail(stderr, err)
	}
	if sb.Failed() {
		fmt.Fprintf(stderr, "kritolith: eval failed: %d real reports marked GROUNDING_FAILED, %d real reports marked LIKELY_DUPLICATE, %d errors\n",
			sb.RealGroundingFailures(), sb.RealLikelyDuplicates(), sb.Errors())
		return 1
	}
	return 0
}
