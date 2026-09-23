package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

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
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: kritolith eval [--corpus dir] [--data-dir dir]")
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil || len(pos) != 0 {
		return 2
	}

	cases, err := eval.LoadCorpus(*corpus)
	if err != nil {
		fmt.Fprintf(stderr, "kritolith: %v\n", err)
		return 1
	}
	dir := *dataDir
	if dir == "" {
		tmp, err := os.MkdirTemp("", "kritolith-eval-")
		if err != nil {
			fmt.Fprintf(stderr, "kritolith: %v\n", err)
			return 1
		}
		defer os.RemoveAll(tmp)
		dir = tmp
	}
	st, err := store.Open(ctx, dir)
	if err != nil {
		fmt.Fprintf(stderr, "kritolith: %v\n", err)
		return 1
	}
	defer st.Close()
	p := pipeline.New(st)

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
		fmt.Fprintf(stderr, "kritolith: %v\n", err)
		return 1
	}
	if sb.Failed() {
		return 1
	}
	return 0
}
