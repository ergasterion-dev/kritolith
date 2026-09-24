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

// newOriginWithFiles creates a one-commit git repo with files and
// returns its path and commit.
func newOriginWithFiles(t *testing.T, files map[string]string) (dir, commit string) {
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
	return dir, run("rev-parse", "HEAD")
}

// disproveFixture reproduces, in miniature, the shapes seen in the
// real and fabricated eval corpus (see task-8b-report.md).
var disproveFixture = map[string]string{
	"go.mod": "module example.com/widgets\n\ngo 1.22\n",
	"http2/frame.go": `package http2

import "google.golang.org/protobuf/encoding/protowire"

// Framer has a closed method set: no embedding.
type Framer struct{ buf []byte }

func (f *Framer) ReadFrame() error {
	_, n := protowire.ConsumeVarint(f.buf)
	paddingLength := n
	_ = paddingLength
	return nil
}

func parseHeaders() {}
`,
	"util/limit.go": `package util

import (
	"strings"
	"sync"
)

const MaxBitLen = 256

var ErrTokenExpired = error(nil)

type MessageLimit struct{ ChunkSize int }

type LegacyDec struct{ i int }

func (d LegacyDec) AddMut() {}

// Wrapper embeds sync.Mutex, so it has promoted methods (Lock,
// Unlock) that are declared nowhere in this repository.
type Wrapper struct{ sync.Mutex }

var pool sync.Pool

func trim(s string) bool { return strings.HasPrefix(s, "x") }
`,
	// A repo package named like a stdlib package it also imports.
	"internal/http/http.go": `package http

import nethttp "net/http"

var _ = nethttp.StatusOK
`,
	"stdhttp/client.go": `package http

import "net/http"

var _ = http.StatusOK
`,
}

func TestGroundFunctionClaimsDisproveOnlyWhenProvable(t *testing.T) {
	origin, commit := newOriginWithFiles(t, disproveFixture)
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		value string
		want  report.Tri
		why   string
	}{
		// Real-corpus false-positive shapes: must never be "no".
		{"protowire.ConsumeVarint", report.TriUnknown, "dependency function the repo calls (go-2022-0422)"},
		{"ChunkSize", report.TriUnknown, "struct field (go-2022-0528)"},
		{"MaxBitLen", report.TriUnknown, "const (go-2024-3279)"},
		{"LegacyDec", report.TriUnknown, "type (go-2024-3279)"},
		{"ErrTokenExpired", report.TriUnknown, "var (go-2024-3250)"},
		{"paddingLength", report.TriUnknown, "local variable (go-2025-3748)"},
		{"sync.Pool", report.TriUnknown, "stdlib type (go-2023-2328)"},
		{"strings.HasSuffix", report.TriUnknown, "stdlib func the repo never uses: qualified exported names are never disproved"},
		{"f.buf", report.TriUnknown, "field access; buf appears as an identifier"},
		{"sync.pool", report.TriUnknown, "no package sync declared in the repo"},
		{"http.readRequest", report.TriUnknown, "repo declares package http but also imports net/http"},
		{"TrustForwardedHost", report.TriUnknown, "bare exported names may belong to another package"},
		{"(*Wrapper).TryLockUnsafe", report.TriUnknown, "Wrapper embeds a type, so the method may be promoted"},
		{"(*Request).Missing", report.TriUnknown, "receiver type not declared in the repo"},
		{"(*Framer).ReadFrame2", report.TriNo, "closed type, name nowhere in the repo"},
		// Declared: yes.
		{"AddMut", report.TriYes, "bare method name (go-2024-3279)"},
		{"(*Framer).ReadFrame", report.TriYes, "declared method"},
		{"http2.parseHeaders", report.TriYes, "declared function"},
		// Fabricated-corpus shapes: must stay "no".
		{"(*Framer).ReadContinuationUnsafe", report.TriNo, "invented method on a closed repo type (fab-001)"},
		{"lexInlineTableDeep", report.TriNo, "invented bare unexported function (fab-007)"},
		{"http2.parseHeader", report.TriNo, "invented unexported function in a repo package (CLAUDE.md example)"},
	}
	var claims []report.Claim
	for _, tt := range tests {
		claims = append(claims, report.Claim{Kind: report.ClaimFunction, Value: tt.value, Verified: report.TriUnknown})
	}
	r := report.Report{ID: "R1", Repo: "owner/name", ClaimedRef: commit}
	grounded, resolved, _, err := groundClaims(context.Background(), m, r, claims)
	if err != nil || !resolved {
		t.Fatalf("groundClaims: resolved=%v err=%v", resolved, err)
	}
	for i, tt := range tests {
		if got := grounded[i]; got.Verified != tt.want {
			t.Errorf("%s (%s): Verified = %s, want %s; evidence: %s", tt.value, tt.why, got.Verified, tt.want, got.Evidence)
		} else if tt.want == report.TriUnknown && got.Evidence == "" {
			t.Errorf("%s: unknown with no evidence, want the reason recorded", tt.value)
		}
	}
}

func TestGroundFileClaimPathSuffix(t *testing.T) {
	origin, commit := newOriginWithFiles(t, disproveFixture)
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	claims := []report.Claim{
		{Kind: report.ClaimFile, Value: "frame.go"},        // real file, cited relative to its package dir
		{Kind: report.ClaimFile, Value: "shell_expand.go"}, // invented (fab-002)
		{Kind: report.ClaimFile, Value: "http2/frame.go"},  // exact
	}
	r := report.Report{ID: "R1", Repo: "owner/name", ClaimedRef: commit}
	grounded, _, _, err := groundClaims(context.Background(), m, r, claims)
	if err != nil {
		t.Fatal(err)
	}
	want := []report.Tri{report.TriUnknown, report.TriNo, report.TriYes}
	for i := range want {
		if grounded[i].Verified != want[i] {
			t.Errorf("%s: Verified = %s, want %s; evidence: %s", grounded[i].Value, grounded[i].Verified, want[i], grounded[i].Evidence)
		}
	}
	if !strings.Contains(grounded[0].Evidence, "http2/frame.go") {
		t.Errorf("suffix-match evidence = %q, want it to name the real path", grounded[0].Evidence)
	}
}

func TestGroundFunctionClaimIncompleteScanNeverDisproves(t *testing.T) {
	origin, commit := newOriginWithFiles(t, disproveFixture)
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	old := maxReadBytes
	maxReadBytes = 16 // every file is "too large": the scan is incomplete
	defer func() { maxReadBytes = old }()
	claims := []report.Claim{{Kind: report.ClaimFunction, Value: "lexInlineTableDeep"}}
	r := report.Report{ID: "R1", Repo: "owner/name", ClaimedRef: commit}
	grounded, _, _, err := groundClaims(context.Background(), m, r, claims)
	if err != nil {
		t.Fatal(err)
	}
	if grounded[0].Verified != report.TriUnknown {
		t.Errorf("Verified = %s, want unknown when the scan was incomplete; evidence: %s", grounded[0].Verified, grounded[0].Evidence)
	}
}

// TestComposeOnCorpusShapes checks the end result maintainers see:
// a report whose only unmatched claims are real-but-not-a-local-function
// shapes stays INCONCLUSIVE, and one naming an invented method on a
// real type is GROUNDING_FAILED.
func TestComposeOnCorpusShapes(t *testing.T) {
	origin, commit := newOriginWithFiles(t, disproveFixture)
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		claims []string
		want   report.Outcome
	}{
		{"real-shaped", []string{"(*Framer).ReadFrame", "protowire.ConsumeVarint", "ChunkSize", "sync.Pool", "paddingLength"}, report.OutcomeInconclusive},
		{"fabricated-shaped", []string{"(*Framer).ReadFrame", "(*Framer).ReadContinuationUnsafe"}, report.OutcomeGroundingFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var claims []report.Claim
			for _, v := range tt.claims {
				claims = append(claims, report.Claim{Kind: report.ClaimFunction, Value: v, Verified: report.TriUnknown})
			}
			r := report.Report{ID: "R1", Repo: "owner/name", ClaimedRef: commit}
			grounded, resolved, ref, err := groundClaims(context.Background(), m, r, claims)
			if err != nil {
				t.Fatal(err)
			}
			v := verdict.Compose(r, verdict.StageResults{Claims: grounded, GroundingRan: true, RefResolved: resolved, ResolvedRef: ref})
			if v.Outcome != tt.want {
				t.Errorf("Outcome = %s, want %s; claims: %+v", v.Outcome, tt.want, grounded)
			}
		})
	}
}

func TestGroundFunctionClaimUnparseableFile(t *testing.T) {
	files := map[string]string{}
	for k, v := range disproveFixture {
		files[k] = v
	}
	// An unparseable file could hide a same-named type that embeds,
	// a package clause, or an import; its identifiers still count.
	files["testdata/broken.go"] = "package broken\n\nfunc ( {{{ mentionedInBrokenFile\n"
	origin, commit := newOriginWithFiles(t, files)
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		value string
		want  report.Tri
	}{
		{"(*Framer).ReadContinuationUnsafe", report.TriUnknown},
		{"http2.parseHeader", report.TriUnknown},
		{"mentionedInBrokenFile", report.TriUnknown},
		{"lexInlineTableDeep", report.TriNo}, // bare-name disproof only needs identifiers
	}
	var claims []report.Claim
	for _, tt := range tests {
		claims = append(claims, report.Claim{Kind: report.ClaimFunction, Value: tt.value})
	}
	r := report.Report{ID: "R1", Repo: "owner/name", ClaimedRef: commit}
	grounded, _, _, err := groundClaims(context.Background(), m, r, claims)
	if err != nil {
		t.Fatal(err)
	}
	for i, tt := range tests {
		if grounded[i].Verified != tt.want {
			t.Errorf("%s: Verified = %s, want %s; evidence: %s", tt.value, grounded[i].Verified, tt.want, grounded[i].Evidence)
		}
	}
}

// gitIn runs git in dir, failing the test on error.
func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func groundValues(t *testing.T, files map[string]string, kind report.ClaimKind, values []string, setup func(origin string) string) []report.Claim {
	t.Helper()
	origin, commit := newOriginWithFiles(t, files)
	if setup != nil {
		commit = setup(origin)
	}
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	var claims []report.Claim
	for _, v := range values {
		claims = append(claims, report.Claim{Kind: kind, Value: v, Verified: report.TriUnknown})
	}
	r := report.Report{ID: "R1", Repo: "owner/name", ClaimedRef: commit}
	grounded, resolved, _, err := groundClaims(context.Background(), m, r, claims)
	if err != nil || !resolved {
		t.Fatalf("groundClaims: resolved=%v err=%v", resolved, err)
	}
	return grounded
}

func withFiles(extra map[string]string) map[string]string {
	files := map[string]string{}
	for k, v := range disproveFixture {
		files[k] = v
	}
	for k, v := range extra {
		files[k] = v
	}
	return files
}

func checkVerified(t *testing.T, grounded []report.Claim, want map[string]report.Tri) {
	t.Helper()
	for _, c := range grounded {
		if w, ok := want[c.Value]; ok && c.Verified != w {
			t.Errorf("%s: Verified = %s, want %s; evidence: %s", c.Value, c.Verified, w, c.Evidence)
		}
	}
}

// Review fix #1: a name used only in a string literal, a struct tag,
// or a non-Go file is real, so it must not be disproved.
func TestGroundFunctionClaimNameOnlyInNonIdentifierText(t *testing.T) {
	files := withFiles(map[string]string{
		"web/config.go":     "package web\n\ntype Config struct {\n\tAllow bool `json:\"allowPrivileged\" yaml:\"readTimeout\"`\n}\n\nconst sink = \"el.innerHTML = x\"\n",
		"web/static/app.js": "window.location = params.redirectUrl;\nel.innerHTML = msg;\n",
	})
	grounded := groundValues(t, files, report.ClaimFunction,
		[]string{"allowPrivileged", "readTimeout", "innerHTML", "redirectUrl", "lexInlineTableDeep"}, nil)
	checkVerified(t, grounded, map[string]report.Tri{
		"allowPrivileged":    report.TriUnknown,
		"readTimeout":        report.TriUnknown,
		"innerHTML":          report.TriUnknown,
		"redirectUrl":        report.TriUnknown,
		"lexInlineTableDeep": report.TriNo, // genuinely absent from all tracked text
	})
}

// Review fix #1: ContainsWord must report a git failure as an error,
// never as "not found".
func TestContainsWordErrorIsNotAbsence(t *testing.T) {
	origin, commit := newOriginWithFiles(t, disproveFixture)
	m, err := OpenMirror(t.TempDir(), "owner/name", origin)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, _, err := m.EnsureAndResolve(ctx, commit, nil); err != nil {
		t.Fatal(err)
	}
	if found, err := m.ContainsWord(ctx, commit, "ReadFrame"); err != nil || !found {
		t.Errorf("ContainsWord(ReadFrame) = %v, %v, want true, nil", found, err)
	}
	if found, err := m.ContainsWord(ctx, commit, "ReadFrameX"); err != nil || found {
		t.Errorf("ContainsWord(ReadFrameX) = %v, %v, want false, nil", found, err)
	}
	if found, err := m.ContainsWord(ctx, strings.Repeat("0", 40), "anything"); err == nil {
		t.Errorf("ContainsWord at a missing commit = %v, nil, want an error", found)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if found, err := m.ContainsWord(cancelled, commit, "anything"); err == nil {
		t.Errorf("ContainsWord with a cancelled context = %v, nil, want an error", found)
	}
}

// Review fix #2: keywords and predeclared identifiers are never
// "absent", even though go/scanner never reports keywords as
// identifiers.
func TestGroundFunctionClaimKeywordsAndPredeclared(t *testing.T) {
	values := []string{"recover", "defer", "error", "min", "clear", "go", "iota", "nil"}
	grounded := groundValues(t, disproveFixture, report.ClaimFunction, values, nil)
	want := map[string]report.Tri{}
	for _, v := range values {
		want[v] = report.TriUnknown
	}
	checkVerified(t, grounded, want)
}

// Review fix #3: an unaliased import whose package name differs from
// its last path element ("github.com/foo/go-yaml" is package yaml)
// must still count as an out-of-module binding for "yaml.x".
func TestGroundFunctionClaimDifferentlyNamedImport(t *testing.T) {
	files := withFiles(map[string]string{
		"yaml/yaml.go":   "package yaml\n\nfunc Local() {}\n",
		"render/emit.go": "package render\n\nimport \"github.com/foo/go-yaml\"\n\nvar _ = yaml.Marshal\n",
	})
	grounded := groundValues(t, files, report.ClaimFunction,
		[]string{"yaml.unmarshalNode", "http2.parseHeader"}, nil)
	checkVerified(t, grounded, map[string]report.Tri{
		"yaml.unmarshalNode": report.TriUnknown,
		"http2.parseHeader":  report.TriNo, // unchanged: repo package, bound exactly, name absent
	})
}

// Review fix #4: a submodule's contents are invisible to ls-tree, so
// the scan is incomplete and nothing may be disproved.
func TestGroundClaimsSubmoduleMakesScanIncomplete(t *testing.T) {
	setup := func(origin string) string {
		gitIn(t, origin, "update-index", "--add", "--cacheinfo", "160000,"+strings.Repeat("a", 40)+",third_party/lib")
		gitIn(t, origin, "commit", "-q", "-m", "add submodule")
		return gitIn(t, origin, "rev-parse", "HEAD")
	}
	grounded := groundValues(t, disproveFixture, report.ClaimFunction,
		[]string{"lexInlineTableDeep", "(*Framer).ReadContinuationUnsafe", "http2.parseHeader", "(*Framer).ReadFrame"}, setup)
	checkVerified(t, grounded, map[string]report.Tri{
		"lexInlineTableDeep":               report.TriUnknown,
		"(*Framer).ReadContinuationUnsafe": report.TriUnknown,
		"http2.parseHeader":                report.TriUnknown,
		"(*Framer).ReadFrame":              report.TriYes,
	})
	files := groundValues(t, disproveFixture, report.ClaimFile, []string{"http2/missing.go", "missing.go"}, setup)
	checkVerified(t, files, map[string]report.Tri{"http2/missing.go": report.TriUnknown, "missing.go": report.TriUnknown})
}

// Review fix #5: a file path whose directory doesn't exist in the
// repository (a stdlib path, or a module-cache path from a stack trace)
// isn't a claim about this repository's layout.
func TestGroundFileClaimExternalLookingPaths(t *testing.T) {
	grounded := groundValues(t, disproveFixture, report.ClaimFile, []string{
		"net/http/server.go",    // stdlib file mentioned in prose
		"v1.0.0/baz/qux.go",     // extracted from /root/go/pkg/mod/github.com/foo/bar@v1.0.0/baz/qux.go:123
		"http2/missing.go",      // real directory, invented file
		"repo/http2/missing.go", // directory matches as a suffix... of nothing: "repo/http2" isn't a dir
		"missing.go",            // bare filename
		"http2/frame.go",        // exact
		"frame.go",              // suffix of a real file
	}, nil)
	checkVerified(t, grounded, map[string]report.Tri{
		"net/http/server.go":    report.TriUnknown,
		"v1.0.0/baz/qux.go":     report.TriUnknown,
		"http2/missing.go":      report.TriNo,
		"repo/http2/missing.go": report.TriUnknown,
		"missing.go":            report.TriNo,
		"http2/frame.go":        report.TriYes,
		"frame.go":              report.TriUnknown,
	})
}
