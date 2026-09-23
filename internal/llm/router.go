package llm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
)

// ErrNoProvider means every provider in a task's chain was skipped or
// failed.
var ErrNoProvider = errors.New("llm: no provider available")

// AllowCloud reports whether cloud (non-local) providers may run for a
// given project's repo. The router looks this up per call, never from
// process-global state, and treats a nil AllowCloud as "deny all".
type AllowCloud func(repo string) bool

// Router holds one ordered provider chain per task and decides, per
// call, whether a chain's non-local providers may run.
type Router struct {
	providers  map[string]Provider
	tasks      map[string][]string
	allowCloud AllowCloud
	logger     *slog.Logger
}

// NewRouter builds a Router. providers maps provider name to an
// implementation; tasks maps task name to an ordered chain of those
// names, most preferred first. A nil logger uses slog.Default(); a nil
// allowCloud denies all cloud calls.
func NewRouter(providers map[string]Provider, tasks map[string][]string, allowCloud AllowCloud, logger *slog.Logger) *Router {
	if logger == nil {
		logger = slog.Default()
	}
	if allowCloud == nil {
		allowCloud = func(string) bool { return false }
	}
	return &Router{providers: providers, tasks: tasks, allowCloud: allowCloud, logger: logger}
}

// Chain returns the runnable providers for task, in preference order,
// skipping any unknown provider name and any non-local provider the
// project hasn't opted into via allow_cloud. Callers that need to fall
// through past an application-level failure (e.g. a schema violation,
// not just a transport error) iterate the returned providers
// themselves; Complete and Embed cover the simpler case of
// transport-level fallthrough only.
func (r *Router) Chain(task, reportID, repo string) []Provider {
	var out []Provider
	for _, name := range r.tasks[task] {
		p, ok := r.providers[name]
		if !ok {
			continue
		}
		if !p.IsLocal() {
			if !r.allowCloud(repo) {
				continue
			}
			r.logger.Warn("cloud LLM call", "task", task, "provider", p.Name(), "report_id", reportID)
		}
		out = append(out, p)
	}
	return out
}

// Complete tries each provider in task's chain in order, returning the
// first success.
func (r *Router) Complete(ctx context.Context, task, reportID, repo string, req CompleteRequest) (CompleteResponse, error) {
	var lastErr error
	for _, p := range r.Chain(task, reportID, repo) {
		resp, err := p.Complete(ctx, req)
		if err != nil {
			lastErr = err
			continue
		}
		return resp, nil
	}
	return CompleteResponse{}, fmt.Errorf("llm: %s: %w: %v", task, ErrNoProvider, lastErr)
}

// Embed tries each provider in task's chain in order, returning the
// first success.
func (r *Router) Embed(ctx context.Context, task, reportID, repo string, texts []string) ([][]float32, error) {
	var lastErr error
	for _, p := range r.Chain(task, reportID, repo) {
		vecs, err := p.Embed(ctx, texts)
		if err != nil {
			lastErr = err
			continue
		}
		return vecs, nil
	}
	return nil, fmt.Errorf("llm: %s: %w: %v", task, ErrNoProvider, lastErr)
}
