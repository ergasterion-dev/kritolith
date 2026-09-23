package ground

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

const (
	maxGoFiles      = 5000 // bound the work on pathologically large repos
	maxFallbackRefs = 20   // bound how many ClaimVersion values become ref candidates
)

// groundClaims checks r's claimed ref (falling back to any
// ClaimVersion values already in claims) and grounds every
// file/function/line claim against the resolved commit. It returns
// the same claims with Verified and Evidence updated, plus whether a
// ref resolved and which commit it resolved to. An error here means
// the mirror itself couldn't be used (clone/fetch failure); callers
// must degrade to "not resolved" rather than propagate it as a
// pipeline failure (see Task 5's Service).
func groundClaims(ctx context.Context, m *Mirror, r report.Report, claims []report.Claim) (grounded []report.Claim, refResolved bool, resolvedCommit string, err error) {
	var versions []string
	for _, c := range claims {
		if c.Kind == report.ClaimVersion {
			versions = append(versions, c.Value)
			if len(versions) >= maxFallbackRefs {
				break
			}
		}
	}
	commit, resolved, err := m.EnsureAndResolve(ctx, r.ClaimedRef, versions)
	if err != nil {
		return claims, false, "", err
	}
	if !resolved {
		return claims, false, "", nil
	}

	var decls []declaration
	var declsLoaded bool
	loadDecls := func() []declaration {
		if declsLoaded {
			return decls
		}
		declsLoaded = true
		files, err := m.ListGoFiles(ctx, commit)
		if err != nil {
			return nil
		}
		if len(files) > maxGoFiles {
			files = files[:maxGoFiles]
		}
		for _, f := range files {
			content, ok, err := m.ReadFile(ctx, commit, f)
			if err != nil || !ok {
				continue
			}
			decls = append(decls, parseDeclarations(f, content)...)
		}
		return decls
	}

	out := make([]report.Claim, len(claims))
	copy(out, claims)
	for i := range out {
		switch out[i].Kind {
		case report.ClaimFile:
			groundFileClaim(ctx, m, commit, &out[i])
		case report.ClaimFunction:
			groundFunctionClaim(&out[i], loadDecls())
		case report.ClaimLine:
			groundLineClaim(ctx, m, commit, &out[i], loadDecls())
		}
	}
	return out, true, commit, nil
}

func groundFileClaim(ctx context.Context, m *Mirror, commit string, c *report.Claim) {
	ok, err := m.FileExists(ctx, commit, c.Value)
	short := shortSHA(commit)
	if err != nil {
		return // leave Verified/Evidence as extraction left them
	}
	if ok {
		c.Verified = report.TriYes
		c.Evidence = fmt.Sprintf("file exists at %s", short)
	} else {
		c.Verified = report.TriNo
		c.Evidence = fmt.Sprintf("not found at %s", short)
	}
}

func groundFunctionClaim(c *report.Claim, decls []declaration) {
	if d := findDeclaration(decls, c.Value); d != nil {
		c.Verified = report.TriYes
		c.Evidence = fmt.Sprintf("declared at %s:%d", report.Printable(d.file), d.line)
		return
	}
	c.Verified = report.TriNo
	if closest := closestDeclaration(decls, c.Value); closest != nil {
		c.Evidence = fmt.Sprintf("not declared in the repository; closest match: %s (%s:%d)",
			report.Printable(closest.name), report.Printable(closest.file), closest.line)
	} else {
		c.Evidence = "not declared in the repository"
	}
}

func groundLineClaim(ctx context.Context, m *Mirror, commit string, c *report.Claim, decls []declaration) {
	file, lineNum, ok := splitFileLine(c.Value)
	if !ok {
		return
	}
	content, exists, err := m.ReadFile(ctx, commit, file)
	if err != nil || !exists {
		c.Verified = report.TriNo
		c.Evidence = "file not found"
		return
	}
	total := strings.Count(string(content), "\n") + 1
	if lineNum < 1 || lineNum > total {
		c.Verified = report.TriNo
		c.Evidence = fmt.Sprintf("file has %d lines", total)
		return
	}
	for _, d := range decls {
		if d.file == file && lineNum >= d.line && lineNum <= d.endLine {
			c.Verified = report.TriYes
			c.Evidence = fmt.Sprintf("inside %s (%s:%d-%d)", report.Printable(d.name), report.Printable(d.file), d.line, d.endLine)
			return
		}
	}
	c.Verified = report.TriYes
	c.Evidence = fmt.Sprintf("line exists (file has %d lines)", total)
}

// splitFileLine parses a claim value shaped "file.go:123" — the exact
// shape deterministic.lineClaims produces.
func splitFileLine(value string) (file string, line int, ok bool) {
	idx := strings.LastIndexByte(value, ':')
	if idx < 0 {
		return "", 0, false
	}
	n, err := strconv.Atoi(value[idx+1:])
	if err != nil || n < 1 {
		return "", 0, false
	}
	return value[:idx], n, true
}

func shortSHA(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}
