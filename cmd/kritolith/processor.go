package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

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
	sandbox  sandboxRunner   // nil when the sandbox is off or unavailable

	closeOnce sync.Once
}

// processorOption changes how newProcessor builds a processor.
type processorOption func(*processorOptions)

type processorOptions struct {
	noSandbox bool
}

// withoutSandbox makes newProcessor leave a configured sandbox alone:
// no startup sweep, no runner and no work dir lock. It is for a command
// that never runs a PoC, so that another kritolith process on the host
// can use the sandbox meanwhile.
func withoutSandbox() processorOption {
	return func(o *processorOptions) { o.noSandbox = true }
}

// newProcessor opens the store under dir and builds the pipeline. With
// a sandbox section in cfg it also builds the sandbox (see
// buildSandbox), unless withoutSandbox is given; an unavailable sandbox
// is reported on stderr and the processor carries on without it.
func newProcessor(ctx context.Context, cfg *config.Config, dir string, stderr io.Writer, opts ...processorOption) (*processor, error) {
	var o processorOptions
	for _, opt := range opts {
		opt(&o)
	}
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
	gs := ground.NewService(dir)
	p := pipeline.New(st).WithGround(gs).WithDedupe(dedupe.NewService(st, router))
	if router != nil {
		p = p.WithLLM(router)
	}
	if pr.signer != nil {
		p = p.WithSigner(pr.signer)
	}
	if cfg != nil && cfg.Sandbox.Enabled() && !o.noSandbox {
		sb, err := buildSandbox(cfg.Sandbox, gs, dir, stderr)
		if err != nil {
			st.Close()
			return nil, err
		}
		if sb != nil {
			pr.sandbox = sb
			p = p.WithSandbox(sb).WithSandboxLogs(newSandboxLogSink(dir, cfg.Sandbox.LogRetentionDays, time.Now))
		}
	}
	pr.pipeline = p
	return pr, nil
}

// close releases the sandbox (its work dir lock) and the store. The
// sandbox's Close first waits for an in-flight run to finish its
// cleanup (the run sees the cancelled context, so that is bounded by
// the driver's worst case, about 65s per container). It is safe to call
// more than once.
func (pr *processor) close() {
	pr.closeOnce.Do(func() {
		if pr.sandbox != nil {
			if err := pr.sandbox.Close(); err != nil {
				slog.Default().Warn("sandbox: close", "error", err)
			}
		}
		pr.st.Close()
	})
}

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
