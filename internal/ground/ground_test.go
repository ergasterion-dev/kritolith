package ground

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/report"
	"github.com/ergasterion-dev/kritolith/internal/verdict"
)

func newGroundTestOrigin(t *testing.T) (dir, commit string) {
	t.Helper()
	dir = t.TempDir()
	run := func(args ...string) string {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q", "-b", "main")
	run("config", "user.email", "test@test.example")
	run("config", "user.name", "test")
	files := map[string]string{
		"internal/http2/frame.go": "package http2\n\nfunc parseHeaders() {}\n",
		"main.go":                 "package main\n\nfunc main() {}\n",
	}
	for name, content := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("add", ".")
	run("commit", "-q", "-m", "init")
	commit = run("rev-parse", "HEAD")
	return dir, commit
}

func TestGroundClaimsFileAndFunction(t *testing.T) {
	origin, commit := newGroundTestOrigin(t)
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	r := report.Report{ID: "R1", Repo: "owner/name", ClaimedRef: commit}
	claims := []report.Claim{
		{Kind: report.ClaimFile, Value: "internal/http2/frame.go"},
		{Kind: report.ClaimFile, Value: "internal/http2/missing.go"}, // real directory, invented file
		{Kind: report.ClaimFile, Value: "does/not/exist.go"},         // directory absent too: may be an external path
		{Kind: report.ClaimFunction, Value: "http2.parseHeaders"},
		{Kind: report.ClaimFunction, Value: "http2.parseHeader"}, // invented, close to parseHeaders
	}
	grounded, resolved, resolvedCommit, _, _, err := groundClaims(context.Background(), m, r, claims)
	if err != nil {
		t.Fatal(err)
	}
	if !resolved || resolvedCommit != commit {
		t.Fatalf("resolved = %v, commit = %q, want true, %q", resolved, resolvedCommit, commit)
	}
	byValue := map[string]report.Claim{}
	for _, c := range grounded {
		byValue[c.Value] = c
	}
	if byValue["internal/http2/frame.go"].Verified != report.TriYes {
		t.Errorf("existing file claim = %+v, want Verified: yes", byValue["internal/http2/frame.go"])
	}
	if byValue["internal/http2/missing.go"].Verified != report.TriNo {
		t.Errorf("missing file claim = %+v, want Verified: no", byValue["internal/http2/missing.go"])
	}
	if byValue["does/not/exist.go"].Verified != report.TriUnknown {
		t.Errorf("missing file in a missing directory = %+v, want Verified: unknown", byValue["does/not/exist.go"])
	}
	if byValue["http2.parseHeaders"].Verified != report.TriYes {
		t.Errorf("existing function claim = %+v, want Verified: yes", byValue["http2.parseHeaders"])
	}
	invented := byValue["http2.parseHeader"]
	if invented.Verified != report.TriNo {
		t.Errorf("invented function claim = %+v, want Verified: no", invented)
	}
	if !strings.Contains(invented.Evidence, "parseHeaders") {
		t.Errorf("invented function claim evidence = %q, want it to mention the closest match", invented.Evidence)
	}
	parsed := byValue["http2.parseHeaders"]
	if parsed.DeclPkgDir != "internal/http2" || parsed.DeclReceiver != "" || parsed.DeclName != "parseHeaders" {
		t.Errorf("existing function claim = %+v, want resolved declaration identity (internal/http2, \"\", parseHeaders)", parsed)
	}
	if invented.DeclPkgDir != "" || invented.DeclName != "" {
		t.Errorf("invented function claim = %+v, want no declaration identity", invented)
	}
}

func TestGroundClaimsRefDoesNotResolve(t *testing.T) {
	origin, _ := newGroundTestOrigin(t)
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	r := report.Report{ID: "R1", Repo: "owner/name", ClaimedRef: "totally-unknown"}
	grounded, resolved, _, _, _, err := groundClaims(context.Background(), m, r, []report.Claim{{Kind: report.ClaimFile, Value: "main.go", Verified: report.TriUnknown}})
	if err != nil {
		t.Fatal(err)
	}
	if resolved {
		t.Fatal("want resolved = false")
	}
	if grounded[0].Verified != report.TriUnknown {
		t.Errorf("claim = %+v, want unchanged/unverified when the ref never resolved", grounded[0])
	}
}

func TestGroundClaimsLineClaim(t *testing.T) {
	origin, commit := newGroundTestOrigin(t)
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	r := report.Report{ID: "R1", Repo: "owner/name", ClaimedRef: commit}
	claims := []report.Claim{
		{Kind: report.ClaimLine, Value: "main.go:3"},    // inside func main
		{Kind: report.ClaimLine, Value: "main.go:9999"}, // out of range
	}
	grounded, _, _, _, _, err := groundClaims(context.Background(), m, r, claims)
	if err != nil {
		t.Fatal(err)
	}
	if grounded[0].Verified != report.TriYes {
		t.Errorf("in-range line claim = %+v, want Verified: yes", grounded[0])
	}
	if grounded[1].Verified != report.TriNo {
		t.Errorf("out-of-range line claim = %+v, want Verified: no", grounded[1])
	}
	// A line claim is soft: whether it fails never contributes to
	// GROUNDING_FAILED. That precedence is Task 6's concern (Compose),
	// not groundClaims's — this test only checks Verified/Evidence.
}

func TestGroundClaimsFallsBackToVersionClaims(t *testing.T) {
	origin, commit := newGroundTestOrigin(t)
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = origin
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("tag", "v2.0.0")
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	r := report.Report{ID: "R1", Repo: "owner/name", ClaimedRef: "does-not-resolve"}
	claims := []report.Claim{{Kind: report.ClaimVersion, Value: "v2.0.0"}}
	_, resolved, resolvedCommit, viaFallback, _, err := groundClaims(context.Background(), m, r, claims)
	if err != nil {
		t.Fatal(err)
	}
	if !resolved || resolvedCommit != commit || !viaFallback {
		t.Fatalf("resolved = %v, commit = %q, viaFallback = %v, want true, %q, true", resolved, resolvedCommit, viaFallback, commit)
	}
}

// Final-review I3, end to end: the claimed ref doesn't resolve, a
// fallback version does, and a hard claim is genuinely missing at that
// fallback commit. The verdict must be INCONCLUSIVE, not
// GROUNDING_FAILED; the same claim at a directly resolved ref still
// fails grounding.
func TestServiceGroundFallbackCapsGroundingFailed(t *testing.T) {
	origin, commit := newGroundTestOrigin(t)
	gitIn(t, origin, "tag", "v2.0.0")
	s := NewService(t.TempDir())
	s.originURL = func(string) string { return origin }
	claims := func() []report.Claim {
		return []report.Claim{
			{Kind: report.ClaimFile, Value: "internal/http2/missing.go", Verified: report.TriUnknown},
			{Kind: report.ClaimVersion, Value: "v2.0.0"},
		}
	}
	ctx := context.Background()

	fb := report.Report{ID: "R1", Repo: "owner/name", ClaimedRef: strings.Repeat("f", 40)}
	gr := s.Ground(ctx, fb, claims())
	if !gr.RefResolved || gr.ResolvedRef != commit || !gr.ViaFallback {
		t.Fatalf("fallback Ground = %v, %q, %v, want true, %q, true", gr.RefResolved, gr.ResolvedRef, gr.ViaFallback, commit)
	}
	if gr.Claims[0].Verified != report.TriNo {
		t.Fatalf("missing file at the fallback commit: Verified = %s, want no", gr.Claims[0].Verified)
	}
	v := verdict.Compose(fb, verdict.StageResults{Claims: gr.Claims, GroundingRan: true, RefResolved: gr.RefResolved, ResolvedRef: gr.ResolvedRef, ResolvedViaFallback: gr.ViaFallback})
	if v.Outcome != report.OutcomeInconclusive {
		t.Errorf("fallback Outcome = %s, want INCONCLUSIVE", v.Outcome)
	}

	direct := report.Report{ID: "R2", Repo: "owner/name", ClaimedRef: commit}
	gr = s.Ground(ctx, direct, claims())
	if !gr.RefResolved || gr.ViaFallback {
		t.Fatalf("direct Ground = %v, %v, want true, false", gr.RefResolved, gr.ViaFallback)
	}
	v = verdict.Compose(direct, verdict.StageResults{Claims: gr.Claims, GroundingRan: true, RefResolved: gr.RefResolved, ResolvedRef: gr.ResolvedRef, ResolvedViaFallback: gr.ViaFallback})
	if v.Outcome != report.OutcomeGroundingFailed {
		t.Errorf("direct Outcome = %s, want GROUNDING_FAILED", v.Outcome)
	}
}

func TestGroundClaimsAmbiguousFunctionClaimNeverGetsDeclIdentity(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) string {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q", "-b", "main")
	run("config", "user.email", "test@test.example")
	run("config", "user.name", "test")
	files := map[string]string{
		"pkg1/a.go": "package pkg1\n\ntype T struct{}\n\nfunc (t *T) M() {}\n",
		"pkg2/b.go": "package pkg2\n\ntype T struct{}\n\nfunc (t *T) M() {}\n",
	}
	for name, content := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("add", ".")
	run("commit", "-q", "-m", "init")
	commit := run("rev-parse", "HEAD")

	m, err := OpenMirror(t.TempDir(), "owner/name", dir)
	if err != nil {
		t.Fatal(err)
	}
	r := report.Report{ID: "R1", Repo: "owner/name", ClaimedRef: commit}
	claims := []report.Claim{{Kind: report.ClaimFunction, Value: "(*T).M"}}
	grounded, resolved, _, _, _, err := groundClaims(context.Background(), m, r, claims)
	if err != nil {
		t.Fatal(err)
	}
	if !resolved {
		t.Fatal("want resolved = true")
	}
	c := grounded[0]
	if c.Verified != report.TriYes {
		t.Fatalf("claim = %+v, want Verified: yes (findDeclaration still finds a match)", c)
	}
	if c.DeclPkgDir != "" || c.DeclReceiver != "" || c.DeclName != "" {
		t.Errorf("claim = %+v, want no declaration identity for an ambiguous (name, receiver)", c)
	}
	if !strings.Contains(c.Evidence, "ambiguous") {
		t.Errorf("Evidence = %q, want it to mention the ambiguity", c.Evidence)
	}
}

func TestGroundClaimsLeavesOtherKindsAlone(t *testing.T) {
	origin, commit := newGroundTestOrigin(t)
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	r := report.Report{ID: "R1", Repo: "owner/name", ClaimedRef: commit}
	claims := []report.Claim{{Kind: report.ClaimVulnClass, Value: "dos", Verified: report.TriUnknown}}
	grounded, _, _, _, _, err := groundClaims(context.Background(), m, r, claims)
	if err != nil {
		t.Fatal(err)
	}
	if grounded[0].Verified != report.TriUnknown {
		t.Errorf("vuln_class claim = %+v, want Verified unchanged (unknown)", grounded[0])
	}
}
