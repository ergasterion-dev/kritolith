package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ergasterion-dev/kritolith/internal/config"
	"github.com/ergasterion-dev/kritolith/internal/eval"
	"github.com/ergasterion-dev/kritolith/internal/intake/file"
	"github.com/ergasterion-dev/kritolith/internal/pipeline"
	"github.com/ergasterion-dev/kritolith/internal/report"
	"github.com/ergasterion-dev/kritolith/internal/store"
)

func runEval(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	fs.SetOutput(stderr)
	corpus := fs.String("corpus", "testdata/corpus", "corpus directory")
	dataDir := fs.String("data-dir", "", "keep results in this data dir (default: a temporary dir, removed afterwards)")
	cfgPath := fs.String("config", "", "path to kritolith.json (runs extraction and LLM routing over the corpus)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: kritolith eval [--corpus dir] [--data-dir dir] [--config file]")
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
		dir = tmp
	}
	st, err := store.Open(ctx, dir)
	if err != nil {
		return fail(stderr, err)
	}
	defer st.Close()
	p := pipeline.New(st)
	if cfg != nil {
		router, err := buildRouter(*cfg, nil)
		if err != nil {
			return fail(stderr, err)
		}
		if router != nil {
			p = p.WithLLM(router)
		}
	}

	sb := eval.Run(ctx, cases, func(ctx context.Context, c eval.Case) (report.Outcome, error) {
		opts := file.Options{Repo: c.Meta.Repo, Ref: c.Meta.Ref, ReportPath: filepath.Join(c.Dir, "report.md")}
		if st, err := os.Stat(filepath.Join(c.Dir, "poc")); err == nil && st.IsDir() {
			opts.PoCDir = filepath.Join(c.Dir, "poc")
		}
		r, err := file.Load(opts)
		if err != nil {
			return "", err
		}
		v, err := p.Run(ctx, r)
		if err != nil {
			return "", err
		}
		return v.Outcome, nil
	})
	if err := sb.Write(stdout); err != nil {
		return fail(stderr, err)
	}
	if sb.Failed() {
		fmt.Fprintf(stderr, "kritolith: eval failed: %d real reports marked GROUNDING_FAILED, %d errors\n",
			sb.RealGroundingFailures(), sb.Errors())
		return 1
	}
	return 0
}
