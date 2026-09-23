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
	"net/http/client.go": `package http

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
