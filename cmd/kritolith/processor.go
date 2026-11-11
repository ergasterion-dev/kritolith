package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/ergasterion-dev/kritolith/internal/config"
	"github.com/ergasterion-dev/kritolith/internal/dedupe"
	"github.com/ergasterion-dev/kritolith/internal/ground"
	"github.com/ergasterion-dev/kritolith/internal/llm"
	"github.com/ergasterion-dev/kritolith/internal/notify"
	"github.com/ergasterion-dev/kritolith/internal/pipeline"
	"github.com/ergasterion-dev/kritolith/internal/report"
	"github.com/ergasterion-dev/kritolith/internal/store"
	"github.com/ergasterion-dev/kritolith/internal/verdict"
)

// processor is everything needed to take a report to a stored verdict
// and, if asked, to the maintainers' inboxes: the store, the pipeline,
// the signing key if there is one, and the mail settings. The one-shot
// commands build one per run; `serve` builds one and keeps it.
type processor struct {
	cfg      *config.Config
	st       *store.Store
	pipeline *pipeline.Pipeline
	signer   *verdict.Signer // nil until `kritolith keygen` has been run
}

func newProcessor(ctx context.Context, cfg *config.Config, dir string) (*processor, error) {
	st, err := store.Open(ctx, dir)
	if err != nil {
		return nil, err
	}
	pr := &processor{cfg: cfg, st: st}
	// Signing is on once a key exists. A key that exists but can't be
	// used is an error, never a reason to carry on unsigned.
	key, haveKey, err := verdict.LoadKey(dir)
	if err != nil {
		st.Close()
		return nil, err
	}
	if haveKey {
		if pr.signer, err = verdict.NewSigner(key, nil); err != nil {
			st.Close()
			return nil, err
		}
	}
	var router *llm.Router
	if cfg != nil {
		if router, err = buildRouter(*cfg, nil); err != nil {
			st.Close()
			return nil, err
		}
	}
	p := pipeline.New(st).WithGround(ground.NewService(dir)).WithDedupe(dedupe.NewService(st, router))
	if router != nil {
		p = p.WithLLM(router)
	}
	if pr.signer != nil {
		p = p.WithSigner(pr.signer)
	}
	pr.pipeline = p
	return pr, nil
}

func (pr *processor) close() { pr.st.Close() }

// run takes r through the pipeline and returns its stored verdict.
func (pr *processor) run(ctx context.Context, r report.Report) (report.Verdict, error) {
	return pr.pipeline.Run(ctx, r)
}

// canNotify reports why a verdict for repo could not be emailed, or
// nil if it can.
func (pr *processor) canNotify(repo string) error {
	if pr.cfg == nil || !pr.cfg.SMTP.Configured() {
		return errors.New("needs --config with an smtp section")
	}
	if len(pr.cfg.NotifyAddresses(repo)) == 0 {
		return fmt.Errorf("project %s has no notify addresses in the config", repo)
	}
	_, err := notify.NewSender(pr.cfg.SMTP, os.Getenv)
	return err
}

// notify emails the verdict, with its bundle if it is signed, to the
// project's notify addresses.
func (pr *processor) notify(ctx context.Context, r report.Report, v report.Verdict) error {
	if err := pr.canNotify(r.Repo); err != nil {
		return err
	}
	sender, err := notify.NewSender(pr.cfg.SMTP, os.Getenv)
	if err != nil {
		return err
	}
	m := notify.Message{To: pr.cfg.NotifyAddresses(r.Repo), Report: r, Verdict: v, Text: verdict.Render(r, v)}
	if pr.signer != nil {
		var buf bytes.Buffer
		if err := verdict.WriteBundle(&buf, r, v, pr.signer.PublicKey()); err != nil {
			return err
		}
		m.Bundle = buf.Bytes()
	}
	return sender.Send(ctx, m)
}
