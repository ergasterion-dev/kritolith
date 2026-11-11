package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/config"
	"github.com/ergasterion-dev/kritolith/internal/intake/github"
	"github.com/ergasterion-dev/kritolith/internal/jobs"
	"github.com/ergasterion-dev/kritolith/internal/store"
)

const (
	defaultListen    = "127.0.0.1:8787"
	minWebhookSecret = 16 // bytes; GitHub suggests a long random string
	webhookPath      = "/webhook/github"
)

func runServe(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to kritolith.json (required)")
	dataDir := fs.String("data-dir", "", "data directory (overrides config)")
	listen := fs.String("listen", defaultListen, "address to listen on; put a TLS-terminating proxy in front of it")
	doNotify := fs.Bool("notify", false, "email each verdict to the project's notify addresses (needs smtp in the config)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: kritolith serve --config kritolith.json [--listen addr] [--notify]")
		fmt.Fprintln(stderr, "Receives GitHub repository_advisory webhooks at "+webhookPath+" and verifies each new private report.")
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		return 2
	}
	if len(pos) != 0 || *cfgPath == "" {
		fs.Usage()
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fail(stderr, err)
	}
	if len(cfg.Projects) == 0 {
		return fail(stderr, errors.New("serve: the config lists no projects; a webhook for an unlisted repository is ignored, so there would be nothing to do"))
	}
	if cfg.GitHub.WebhookSecretEnv == "" {
		return fail(stderr, errors.New("serve: set github.webhook_secret_env in the config; without the secret no delivery can be trusted"))
	}
	secret := os.Getenv(cfg.GitHub.WebhookSecretEnv)
	if len(secret) < minWebhookSecret {
		return fail(stderr, fmt.Errorf("serve: environment variable %s (github.webhook_secret_env) must hold a secret of at least %d characters", cfg.GitHub.WebhookSecretEnv, minWebhookSecret))
	}
	tokenEnv := cfg.GitHub.TokenEnv
	if tokenEnv == "" {
		tokenEnv = "GITHUB_TOKEN"
	}
	token := os.Getenv(tokenEnv)
	if token == "" {
		return fail(stderr, fmt.Errorf("serve: environment variable %s must hold a GitHub token that can read the projects' security advisories", tokenEnv))
	}
	dir, err := resolveDataDir(*dataDir, &cfg)
	if err != nil {
		return fail(stderr, err)
	}
	pr, err := newProcessor(ctx, &cfg, dir)
	if err != nil {
		return fail(stderr, err)
	}
	defer pr.close()
	if *doNotify {
		for _, p := range cfg.Projects {
			if err := pr.canNotify(p.Repo); err != nil {
				return fail(stderr, fmt.Errorf("serve: --notify: %w", err))
			}
		}
	}

	logger := slog.New(slog.NewTextHandler(stderr, nil))
	process := func(ctx context.Context, job store.IntakeJob) (string, error) {
		r, err := github.Load(ctx, github.Options{Repo: job.Repo, GHSAID: job.ExternalID, Token: token, APIURL: cfg.GitHub.APIURL})
		if err != nil {
			return "", err
		}
		v, err := pr.run(ctx, r)
		if err != nil {
			return "", err
		}
		logger.Info("verdict", "report_id", r.ID, "repo", r.Repo, "id", job.ExternalID, "outcome", string(v.Outcome), "signed", len(v.Signature) > 0)
		if *doNotify {
			if err := pr.notify(ctx, r, v); err != nil {
				// The job is retried, so the maintainers do get the
				// verdict once mail works; the report is processed
				// again then.
				return "", fmt.Errorf("verdict stored as %s, but emailing it failed: %w", r.ID, err)
			}
		}
		return r.ID, nil
	}
	worker := jobs.NewWorker(pr.st, process, logger)

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fail(stderr, fmt.Errorf("serve: %w", err))
	}
	srv := &http.Server{
		Handler:           newServeMux([]byte(secret), cfg, pr.st, worker.Wake, logger),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	fmt.Fprintf(stdout, "kritolith: listening on http://%s%s for %d project(s)\n", ln.Addr(), webhookPath, len(cfg.Projects))

	workerDone := make(chan error, 1)
	go func() { workerDone <- worker.Run(ctx) }()
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(ln) }()

	code := 0
	select {
	case <-ctx.Done():
	case err := <-serveDone:
		code = fail(stderr, fmt.Errorf("serve: %w", err))
	case err := <-workerDone:
		code = fail(stderr, fmt.Errorf("serve: worker stopped: %v", err))
		workerDone = nil
	}
	// Stop taking deliveries, then let the worker give back whatever
	// it was doing. ctx is already done in the normal case, which is
	// what tells the worker to stop.
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	if workerDone != nil && ctx.Err() != nil {
		select {
		case <-workerDone:
		case <-time.After(30 * time.Second):
			fmt.Fprintln(stderr, "kritolith: the worker did not stop in time; its job will be picked up again at the next start")
		}
	}
	return code
}

// intakeQueue is what the webhook handler needs from the store.
type intakeQueue interface {
	EnqueueIntake(ctx context.Context, source, repo, externalID string, now time.Time) (bool, error)
}

// newServeMux builds the HTTP handler: the webhook endpoint and a
// health check. Nothing else is served.
func newServeMux(secret []byte, cfg config.Config, q intakeQueue, wake func(), logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("POST "+webhookPath, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, github.MaxWebhookBytes))
		if err != nil {
			http.Error(w, "body too large or unreadable", http.StatusRequestEntityTooLarge)
			return
		}
		// Nothing in the body is looked at until the signature has
		// been checked, and a failure says nothing about why.
		if !github.VerifyWebhook(secret, body, r.Header.Get("X-Hub-Signature-256")) {
			logger.Warn("webhook: signature does not verify; dropped", "remote", r.RemoteAddr)
			http.Error(w, "signature required", http.StatusUnauthorized)
			return
		}
		rep, err := github.ParseWebhook(r.Header.Get("X-GitHub-Event"), body)
		if errors.Is(err, github.ErrNotANewReport) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err != nil {
			logger.Warn("webhook: signed delivery could not be used", "reason", err.Error())
			http.Error(w, "unusable delivery", http.StatusBadRequest)
			return
		}
		// A webhook can be pointed here from any repository whose
		// owner knows the secret; only the configured projects are
		// worked on.
		repo := ""
		for _, p := range cfg.Projects {
			if strings.EqualFold(p.Repo, rep.Repo) {
				repo = p.Repo
			}
		}
		if repo == "" {
			logger.Warn("webhook: repository is not a configured project; ignored", "repo", rep.Repo)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		created, err := q.EnqueueIntake(r.Context(), "github", repo, rep.GHSAID, time.Now())
		if err != nil {
			logger.Error("webhook: could not queue the report", "repo", repo, "id", rep.GHSAID, "error", err)
			// 500 makes GitHub show the delivery as failed, so it can
			// be redelivered by hand.
			http.Error(w, "could not queue", http.StatusInternalServerError)
			return
		}
		if created {
			logger.Info("webhook: queued", "repo", repo, "id", rep.GHSAID)
			wake()
		}
		w.WriteHeader(http.StatusAccepted)
	})
	return mux
}
