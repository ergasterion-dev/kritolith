package sandbox

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// The golden outputs under testdata/golden were captured from real
// `go test` / `go run` runs (go1.26.0 darwin/arm64) of the module in
// testdata/golden/victim (and testdata/golden/dotmod for
// dotted_module.txt). Only the absolute paths were rewritten: the
// checkout to /work/src and the toolchain to /usr/local/go. oom.txt is
// the one hand-written output, modelled on the runtime's format,
// because a real out-of-memory crash cannot be produced safely here.

const victimModule = "example.com/victim"

var victimPoCs = []string{"pkg/poc_panic_test.go", "pkg/poc_cb_test.go"}

func golden(t testing.TB, name string) []byte {
	t.Helper()
	if name == "" {
		return nil
	}
	b, err := os.ReadFile(filepath.Join("testdata", "golden", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func victimFuncs(names ...string) Targets {
	var fs []string
	for _, n := range names {
		fs = append(fs, victimModule+"/"+n)
	}
	return Targets{Module: victimModule, Funcs: fs, PoCFiles: victimPoCs}
}

func victimFiles(files ...string) Targets {
	return Targets{Module: victimModule, Files: files, PoCFiles: victimPoCs}
}

// cleanRange is the line range of pkg.Clean in victim/pkg/pkg.go.
var cleanRange = map[string][]FuncRange{"pkg/pkg.go": {{Name: "Clean", Start: 46, End: 51}}}
var parseRange = map[string][]FuncRange{"pkg/pkg.go": {{Name: "Parser.Parse", Start: 8, End: 10}}}

func withRanges(t Targets, r map[string][]FuncRange) Targets {
	t.FuncRanges = r
	return t
}

func TestAnalyzeGolden(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		cover    string
		exit     int
		timedOut bool
		oom      bool
		trunc    bool
		targets  Targets
		kind     string
		weak     bool
		reason   string
	}{
		{name: "panic through claimed method", file: "panic_claimed.txt", exit: 1, targets: victimFuncs("pkg.Parser.Parse"), kind: KindPanic},
		{name: "panic through claimed method, pointer form", file: "panic_claimed.txt", exit: 1, targets: victimFuncs("pkg.(*Parser).Parse"), kind: KindPanic},
		{name: "panic, claim not in stack", file: "panic_claimed.txt", exit: 1, targets: victimFuncs("pkg.Other"), kind: KindNone, reason: ReasonNoClaimedCode},
		{name: "panic through claimed file", file: "panic_claimed.txt", exit: 1, targets: victimFiles("pkg/pkg.go"), kind: KindPanic},
		{name: "claimed root file of same base name does not match", file: "panic_claimed.txt", exit: 1, targets: victimFiles("pkg.go"), kind: KindNone, reason: ReasonNoClaimedCode},
		{name: "claimed file elsewhere does not match", file: "panic_claimed.txt", exit: 1, targets: victimFiles("other/pkg.go"), kind: KindNone, reason: ReasonNoClaimedCode},
		{name: "nil deref in claimed func", file: "nil_deref.txt", exit: 1, targets: victimFuncs("pkg.Deref"), kind: KindPanic},
		{name: "claimed func called from a PoC closure", file: "closure.txt", exit: 1, targets: victimFuncs("pkg.Deref"), kind: KindPanic},
		{name: "generic claimed func", file: "generic.txt", exit: 1, targets: victimFuncs("pkg.Generic"), kind: KindPanic},
		{name: "stack overflow in claimed func", file: "stack_overflow.txt", exit: 1, targets: victimFuncs("pkg.Recurse"), kind: KindPanic},
		{name: "concurrent map writes in claimed closure", file: "map_write.txt", exit: 1, targets: victimFuncs("pkg.MapWrite"), kind: KindPanic},
		{name: "panic only in PoC file", file: "panic_poc.txt", exit: 1, targets: victimFuncs("pkg.Parser.Parse"), kind: KindNone, reason: ReasonNoClaimedCode},
		{name: "panic only in PoC file, PoC file claimed", file: "panic_poc.txt", exit: 1, targets: victimFiles("pkg/poc_panic_test.go"), kind: KindNone, reason: ReasonNoClaimedCode},
		{name: "panic only in PoC file, PoC func claimed", file: "panic_poc.txt", exit: 1, targets: victimFuncs("pkg.TestPanicPoC"), kind: KindNone, reason: ReasonNoClaimedCode},
		{name: "panic in stdlib only", file: "panic_stdlib.txt", exit: 1, targets: victimFuncs("pkg.Parser.Parse", "pkg.Clean"), kind: KindNone, reason: ReasonNoClaimedCode},
		{name: "panic in PoC callback invoked by claimed func", file: "callback_panic.txt", exit: 1, targets: victimFuncs("pkg.Walk"), kind: KindNone, reason: ReasonNoClaimedCode},
		{name: "panic in PoC callback, claimed file", file: "callback_panic.txt", exit: 1, targets: victimFiles("pkg/pkg.go"), kind: KindNone, reason: ReasonNoClaimedCode},
		{name: "panic text but exit 0", file: "panic_claimed.txt", exit: 0, targets: victimFuncs("pkg.Parser.Parse"), kind: KindNone, reason: ReasonPassed},
		{name: "race in claimed func", file: "race.txt", exit: 1, targets: victimFuncs("pkg.Count"), kind: KindRace},
		{name: "race in claimed file", file: "race.txt", exit: 1, targets: victimFiles("pkg/pkg.go"), kind: KindRace},
		{name: "race, claim elsewhere", file: "race.txt", exit: 1, targets: victimFuncs("pkg.Other"), kind: KindNone, reason: ReasonNoClaimedCode},
		{name: "race, creator frames do not count", file: "race.txt", exit: 1, targets: victimFuncs("pkg.TestRace"), kind: KindNone, reason: ReasonNoClaimedCode},
		{name: "assertion failure covering claimed func", file: "assert_fail.txt", cover: "assert_fail.cover", exit: 1, targets: withRanges(victimFuncs("pkg.Clean"), cleanRange), kind: KindFailingTest, weak: true},
		{name: "assertion failure covering claimed file", file: "assert_fail.txt", cover: "assert_fail.cover", exit: 1, targets: victimFiles("pkg/pkg.go"), kind: KindFailingTest, weak: true},
		{name: "assertion failure, claimed func not covered", file: "assert_fail.txt", cover: "assert_fail.cover", exit: 1, targets: withRanges(victimFuncs("pkg.Parser.Parse"), parseRange), kind: KindNone, reason: ReasonExitNoSignal},
		{name: "assertion failure on unclaimed code", file: "assert_noclaim.txt", cover: "assert_noclaim.cover", exit: 1, targets: withRanges(victimFuncs("pkg.Clean"), cleanRange), kind: KindNone, reason: ReasonExitNoSignal},
		{name: "assertion failure without coverage", file: "assert_fail.txt", exit: 1, targets: withRanges(victimFuncs("pkg.Clean"), cleanRange), kind: KindNone, reason: ReasonExitNoSignal},
		{name: "passing test covering claimed func", file: "pass.txt", cover: "pass.cover", exit: 0, targets: withRanges(victimFuncs("pkg.Clean"), cleanRange), kind: KindNone, reason: ReasonPassed},
		{name: "os.Exit(1)", file: "os_exit.txt", exit: 1, targets: victimFuncs("pkg.Parser.Parse"), kind: KindNone, reason: ReasonExitNoSignal},
		{name: "go test timeout", file: "timeout.txt", exit: 1, targets: victimFuncs("pkg.TestHang"), kind: KindNone, reason: ReasonTimeout},
		{name: "sandbox timeout", file: "", exit: -1, timedOut: true, targets: victimFuncs("pkg.Clean"), kind: KindNone, reason: ReasonTimeout},
		{name: "sandbox oom", file: "", exit: -1, oom: true, targets: victimFuncs("pkg.Clean"), kind: KindNone, reason: ReasonOOM},
		{name: "runtime out of memory through claimed code", file: "oom.txt", exit: 1, targets: victimFuncs("pkg.Grow"), kind: KindNone, reason: ReasonOOM},
		{name: "build error", file: "build_error.txt", exit: 1, targets: victimFuncs("pkg.Clean"), kind: KindNone, reason: ReasonBuild},
		{name: "setup failed", file: "setup_failed.txt", exit: 1, targets: victimFuncs("pkg.Clean"), kind: KindNone, reason: ReasonBuild},
		{name: "no tests to run", file: "no_tests.txt", exit: 0, targets: victimFuncs("pkg.Clean"), kind: KindNone, reason: ReasonNoTestsRan},
		{name: "pass", file: "pass.txt", exit: 0, targets: victimFuncs("pkg.Clean"), kind: KindNone, reason: ReasonPassed},
		{name: "main program, claimed func in main package", file: "main_panic.txt", exit: 2, targets: victimFuncs("cmd/tool.crash"), kind: KindPanic},
		{name: "main program, trimpath", file: "main_panic_trimpath.txt", exit: 2, targets: victimFuncs("cmd/tool.crash"), kind: KindPanic},
		{name: "main program, claimed library method", file: "main_panic.txt", exit: 2, targets: victimFuncs("pkg.Parser.Parse"), kind: KindPanic},
		{name: "main program, main func in another dir", file: "main_panic.txt", exit: 2, targets: victimFuncs("cmd/other.crash"), kind: KindNone, reason: ReasonNoClaimedCode},
		{name: "deadlock is not a reproduction", file: "deadlock.txt", exit: 2, targets: victimFuncs("cmd/dl.wait"), kind: KindNone, reason: ReasonExitNoSignal},
		{name: "truncated, signal still found", file: "panic_claimed.txt", exit: 1, trunc: true, targets: victimFuncs("pkg.Parser.Parse"), kind: KindPanic},
		{name: "truncated, no signal", file: "os_exit.txt", exit: 1, trunc: true, targets: victimFuncs("pkg.Parser.Parse"), kind: KindNone, reason: ReasonTruncated},
		{name: "no module, no reproduction", file: "panic_claimed.txt", exit: 1, targets: Targets{Funcs: []string{victimModule + "/pkg.Parser.Parse"}}, kind: KindNone, reason: ReasonNoClaimedCode},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := RunOutput{ExitCode: tc.exit, TimedOut: tc.timedOut, OOM: tc.oom, Truncated: tc.trunc, Output: golden(t, tc.file), Coverage: golden(t, tc.cover)}
			got := Analyze(out, tc.targets)
			if got.Kind != tc.kind || got.Weak != tc.weak || got.Reason != tc.reason {
				t.Fatalf("Analyze = %+v, want kind %q weak %v reason %q", got, tc.kind, tc.weak, tc.reason)
			}
			if got.Kind != KindNone && got.Detail == "" {
				t.Fatal("reproduction without detail")
			}
		})
	}
}

func TestAnalyzeDottedModule(t *testing.T) {
	claims := []report.Claim{{Kind: report.ClaimFunction, Value: "T.Boom", Source: "deterministic", Verified: report.TriYes, DeclPkgDir: ".", DeclReceiver: "T", DeclName: "Boom"}}
	tg := TargetsFromClaims(claims, "example.com/lib.v2")
	tg.PoCFiles = []string{"root_test.go"}
	got := Analyze(RunOutput{ExitCode: 1, Output: golden(t, "dotted_module.txt")}, tg)
	if got.Kind != KindPanic {
		t.Fatalf("got %+v", got)
	}
}

// Every golden output, with or without coverage, must never reproduce
// when there is nothing claimed (all claims unknown or unverified).
func TestAnalyzeEmptyTargetsNeverReproduce(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("testdata", "golden"))
	if err != nil {
		t.Fatal(err)
	}
	unverified := []report.Claim{
		{Kind: report.ClaimFunction, Value: "Parser.Parse", Verified: report.TriUnknown, DeclPkgDir: "pkg", DeclReceiver: "Parser", DeclName: "Parse"},
		{Kind: report.ClaimFunction, Value: "Clean", Verified: report.TriNo, DeclPkgDir: "pkg", DeclName: "Clean"},
		{Kind: report.ClaimFile, Value: "pkg/pkg.go", Verified: report.TriUnknown},
	}
	empties := []Targets{{}, TargetsFromClaims(unverified, victimModule), {Module: victimModule, PoCFiles: victimPoCs, FuncRanges: cleanRange}}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		out := golden(t, e.Name())
		for _, exit := range []int{0, 1, 2} {
			for _, cov := range []string{"", "assert_fail.cover"} {
				for _, tg := range empties {
					got := Analyze(RunOutput{ExitCode: exit, Output: out, Coverage: golden(t, cov)}, tg)
					if got.Kind != KindNone {
						t.Fatalf("%s exit %d targets %+v: got %+v", e.Name(), exit, tg, got)
					}
				}
			}
		}
	}
}

func TestAnalyzeExclusions(t *testing.T) {
	base := string(golden(t, "panic_claimed.txt"))
	// The same stack, but the "claimed" file sits in a dependency in the
	// module cache: the frame is outside the module and must not count.
	dep := strings.ReplaceAll(base, "example.com/victim/pkg.(*Parser).Parse(...)\n\t/work/src/pkg/pkg.go:9", "github.com/dep/x/pkg.(*Parser).Parse(...)\n\t/root/go/pkg/mod/github.com/dep/x@v1.0.0/pkg/pkg.go:9")
	if dep == base {
		t.Fatal("replacement did not apply")
	}
	if got := Analyze(RunOutput{ExitCode: 1, Output: []byte(dep)}, victimFiles("pkg/pkg.go")); got.Kind != KindNone {
		t.Fatalf("dependency frame counted: %+v", got)
	}
	// A claimed stdlib function never counts even if handed in directly.
	if got := Analyze(RunOutput{ExitCode: 1, Output: golden(t, "panic_stdlib.txt")}, Targets{Module: victimModule, Funcs: []string{"time.NewTicker"}}); got.Kind != KindNone {
		t.Fatalf("stdlib target counted: %+v", got)
	}
	// A frame whose file is a PoC file never counts, even under a
	// claimed function's name.
	poc := strings.ReplaceAll(base, "/work/src/pkg/pkg.go:9", "/work/src/pkg/poc_panic_test.go:9")
	if got := Analyze(RunOutput{ExitCode: 1, Output: []byte(poc)}, victimFuncs("pkg.Parser.Parse")); got.Kind != KindNone {
		t.Fatalf("PoC-file frame counted: %+v", got)
	}
	// The last crash wins: a fake earlier "panic" header printed by the
	// PoC is ignored in favour of the real one that ended the process.
	fake := "panic: fake\n\ngoroutine 1 [running]:\nexample.com/victim/pkg.Clean(...)\n\t/work/src/pkg/pkg.go:47\n\n" + string(golden(t, "panic_poc.txt"))
	if got := Analyze(RunOutput{ExitCode: 1, Output: []byte(fake)}, victimFuncs("pkg.Clean")); got.Kind != KindNone {
		t.Fatalf("earlier fake panic counted: %+v", got)
	}
	// Coverage of a PoC file never counts, nor coverage outside the module.
	cov := []byte("mode: set\nexample.com/victim/pkg/poc_panic_test.go:20.30,25.2 2 1\ngithub.com/dep/x/pkg/pkg.go:46.23,47.12 1 1\n")
	tg := victimFiles("pkg/poc_panic_test.go")
	tg.FuncRanges = map[string][]FuncRange{"pkg/poc_panic_test.go": {{Name: "TestAssert", Start: 1, End: 100}}}
	if got := Analyze(RunOutput{ExitCode: 1, Output: golden(t, "assert_fail.txt"), Coverage: cov}, tg); got.Kind != KindNone {
		t.Fatalf("PoC coverage counted: %+v", got)
	}
	// A failing test that also crashed outside claimed code is not signal 3.
	if got := Analyze(RunOutput{ExitCode: 1, Output: golden(t, "panic_poc.txt"), Coverage: golden(t, "assert_fail.cover")}, withRanges(victimFuncs("pkg.Clean"), cleanRange)); got.Kind != KindNone {
		t.Fatalf("crash plus coverage counted: %+v", got)
	}
}

func TestTargetsFromClaims(t *testing.T) {
	fn := func(dir, recv, name string, v report.Tri, src string) report.Claim {
		return report.Claim{Kind: report.ClaimFunction, Value: name, Source: src, Verified: v, DeclPkgDir: dir, DeclReceiver: recv, DeclName: name}
	}
	file := func(p string, v report.Tri) report.Claim {
		return report.Claim{Kind: report.ClaimFile, Value: p, Source: "deterministic", Verified: v}
	}
	tests := []struct {
		name   string
		module string
		claims []report.Claim
		want   Targets
	}{
		{
			name:   "method and function, deterministic and llm",
			module: "github.com/x/y",
			claims: []report.Claim{fn("pkg", "T", "M", report.TriYes, "deterministic"), fn("pkg/sub", "", "F", report.TriYes, "llm:big")},
			want:   Targets{Module: "github.com/x/y", Funcs: []string{"github.com/x/y/pkg.T.M", "github.com/x/y/pkg/sub.F"}, PkgDirs: []string{"pkg", "pkg/sub"}},
		},
		{
			name:   "root package",
			module: "github.com/x/y",
			claims: []report.Claim{fn(".", "", "F", report.TriYes, "deterministic")},
			want:   Targets{Module: "github.com/x/y", Funcs: []string{"github.com/x/y.F"}, PkgDirs: []string{"."}},
		},
		{
			name:   "dots in the last element are escaped like the runtime",
			module: "gopkg.in/lib.v2",
			claims: []report.Claim{fn(".", "T", "M", report.TriYes, "deterministic"), fn("yaml.v3", "", "F", report.TriYes, "deterministic")},
			want:   Targets{Module: "gopkg.in/lib.v2", Funcs: []string{"gopkg.in/lib%2ev2.T.M", "gopkg.in/lib.v2/yaml%2ev3.F"}, PkgDirs: []string{".", "yaml.v3"}},
		},
		{
			name:   "unverified, unknown and unfingerprinted claims never count",
			module: "github.com/x/y",
			claims: []report.Claim{fn("pkg", "", "A", report.TriUnknown, "deterministic"), fn("pkg", "", "B", report.TriNo, "deterministic"), fn("", "", "C", report.TriYes, "deterministic"), file("pkg/a.go", report.TriUnknown)},
			want:   Targets{Module: "github.com/x/y"},
		},
		{
			name:   "vendor, testdata, escaping and bad identifiers are dropped",
			module: "github.com/x/y",
			claims: []report.Claim{fn("vendor/github.com/d/e", "", "F", report.TriYes, "deterministic"), fn("pkg/testdata", "", "F", report.TriYes, "deterministic"), fn("../out", "", "F", report.TriYes, "deterministic"), fn("/abs", "", "F", report.TriYes, "deterministic"), fn("pkg", "", "F(x)", report.TriYes, "deterministic"), fn("pkg", "*T", "M", report.TriYes, "deterministic")},
			want:   Targets{Module: "github.com/x/y"},
		},
		{
			name:   "file claims",
			module: "github.com/x/y",
			claims: []report.Claim{file("pkg/a.go", report.TriYes), file("a.go", report.TriYes), file("pkg/a_test.go", report.TriYes), file("vendor/d/a.go", report.TriYes), file("README.md", report.TriYes), file("../a.go", report.TriYes)},
			want:   Targets{Module: "github.com/x/y", Files: []string{"a.go", "pkg/a.go"}, PkgDirs: []string{".", "pkg"}},
		},
		{
			name:   "duplicates collapse",
			module: "github.com/x/y",
			claims: []report.Claim{fn("pkg", "", "F", report.TriYes, "deterministic"), fn("pkg", "", "F", report.TriYes, "llm:x"), file("pkg/a.go", report.TriYes), file("pkg/a.go", report.TriYes)},
			want:   Targets{Module: "github.com/x/y", Funcs: []string{"github.com/x/y/pkg.F"}, Files: []string{"pkg/a.go"}, PkgDirs: []string{"pkg"}},
		},
		{
			name:   "no module path, nothing counts",
			module: "",
			claims: []report.Claim{fn("pkg", "", "F", report.TriYes, "deterministic")},
			want:   Targets{},
		},
		{
			name:   "invalid module path, nothing counts",
			module: "github.com/x y\n",
			claims: []report.Claim{fn("pkg", "", "F", report.TriYes, "deterministic")},
			want:   Targets{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := TargetsFromClaims(tc.claims, tc.module)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got  %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

func TestAnalyzeHostileInput(t *testing.T) {
	huge := bytes.Repeat([]byte("panic: "), 1<<20)
	deep := []byte("panic: x\n\ngoroutine 1 [running]:\n" + strings.Repeat("example.com/victim/pkg.Other()\n\t/work/src/pkg/pkg.go:58 +0x1\n", 5000) + "example.com/victim/pkg.Clean(...)\n\t/work/src/pkg/pkg.go:47\n")
	tests := []struct {
		name string
		out  RunOutput
	}{
		{"huge single line", RunOutput{ExitCode: 2, Output: huge, Coverage: huge}},
		{"binary", RunOutput{ExitCode: 2, Output: []byte{0, 0xff, '\n', 0xfe, '(', ')'}, Coverage: []byte("mode: set\n\xff:1.1,2.2 1 1\n")}},
		{"truncated frame", RunOutput{ExitCode: 2, Output: []byte("panic: x\n\ngoroutine 1 [running]:\nexample.com/victim/pkg.(")}},
		{"unbalanced parens", RunOutput{ExitCode: 2, Output: []byte("panic: x\n\ngoroutine 1 [running]:\n)))(((\n\t:\n")}},
		{"frame beyond the cap", RunOutput{ExitCode: 2, Output: deep}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Analyze(tc.out, withRanges(victimFuncs("pkg.Clean"), cleanRange))
			if got.Kind != KindNone {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func FuzzAnalyze(f *testing.F) {
	entries, err := os.ReadDir(filepath.Join("testdata", "golden"))
	if err != nil {
		f.Fatal(err)
	}
	cover := golden(f, "assert_fail.cover")
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".txt") {
			f.Add(golden(f, e.Name()), cover, 1, "pkg.Parser.Parse")
		}
	}
	f.Add([]byte("panic: x\n\ngoroutine 1 [running]:\nexample.com/victim/pkg.Clean(...)\n\t/work/src/pkg/pkg.go:47\n"), []byte(nil), 2, "pkg.Clean")
	f.Fuzz(func(t *testing.T, output, coverage []byte, exit int, fn string) {
		out := RunOutput{ExitCode: exit, Output: output, Coverage: coverage}
		empty := []Targets{{}, {Module: victimModule, PoCFiles: victimPoCs, FuncRanges: cleanRange}, TargetsFromClaims(nil, victimModule)}
		for _, tg := range empty {
			if got := Analyze(out, tg); got.Kind != KindNone {
				t.Fatalf("reproduction with empty targets: %+v", got)
			}
		}
		got := Analyze(out, withRanges(victimFuncs(fn), cleanRange))
		switch got.Kind {
		case KindNone, KindPanic, KindRace, KindFailingTest:
		default:
			t.Fatalf("unknown kind %q", got.Kind)
		}
		if !validReasons[got.Reason] {
			t.Fatalf("unknown reason %q", got.Reason)
		}
		if (got.Kind == KindNone) == (got.Reason == "") {
			t.Fatalf("kind %q with reason %q", got.Kind, got.Reason)
		}
	})
}

// Review round 1: frames and coverage from outside the checked-out tree
// (module cache, vendor), frames without a file, build text on a run
// that exited 0, glob closures, and the documented caps.
func TestAnalyzeReviewFixes(t *testing.T) {
	stack := func(sym, file string) []byte {
		s := "panic: boom\n\ngoroutine 1 [running]:\n" + sym + "(...)\n"
		if file != "" {
			s += "\t" + file + "\n"
		}
		return []byte(s + "example.com/a/b/pkg.TestPoC(0x0?)\n\t/work/src/pkg/poc_test.go:5 +0x1\n")
	}
	abTargets := func(funcs []string, files []string) Targets {
		return Targets{Module: "example.com/a/b", Funcs: funcs, Files: files, PoCFiles: []string{"pkg/poc_test.go"}}
	}
	claimedF := abTargets([]string{"example.com/a/b/pkg.F"}, nil)
	claimedFile := abTargets(nil, []string{"pkg/x.go"})
	tests := []struct {
		name    string
		out     RunOutput
		targets Targets
		kind    string
		reason  string
	}{
		{"in-tree frame still matches", RunOutput{ExitCode: 2, Output: stack("example.com/a/b/pkg.F", "/work/src/pkg/x.go:3")}, claimedF, KindPanic, ""},
		{"module cache frame never matches", RunOutput{ExitCode: 2, Output: stack("example.com/a/b/pkg.F", "/root/go/pkg/mod/example.com/a/b/pkg@v1.0.0/x.go:3")}, claimedF, KindNone, ReasonNoClaimedCode},
		{"module cache frame never matches a file claim", RunOutput{ExitCode: 2, Output: stack("example.com/a/b/pkg.F", "/root/go/pkg/mod/example.com/a/b@v1.0.0/pkg/x.go:3")}, claimedFile, KindNone, ReasonNoClaimedCode},
		{"vendored frame never matches", RunOutput{ExitCode: 2, Output: stack("example.com/a/b/pkg.F", "/work/src/sub/vendor/example.com/a/b/pkg/x.go:3")}, claimedF, KindNone, ReasonNoClaimedCode},
		{"frame without a file never matches", RunOutput{ExitCode: 2, Output: stack("example.com/a/b/pkg.F", "")}, claimedF, KindNone, ReasonNoClaimedCode},
		{"glob closure never matches a func named glob", RunOutput{ExitCode: 2, Output: stack("example.com/a/b/pkg.glob..func1", "/work/src/pkg/x.go:3")}, abTargets([]string{"example.com/a/b/pkg.glob"}, nil), KindNone, ReasonNoClaimedCode},
		{"build text on a run that exited 0", RunOutput{ExitCode: 0, Output: []byte("# x\nx.go:1:2: undefined: y\nFAIL\tx [build failed]\nok  \tx\t0.1s\n")}, claimedF, KindNone, ReasonPassed},
		{"in-tree coverage still counts", RunOutput{ExitCode: 1, Output: []byte("--- FAIL: TestPoC (0.00s)\nFAIL\n"), Coverage: []byte("mode: set\nexample.com/a/b/pkg/x.go:3.1,4.2 1 1\n")}, claimedFile, KindFailingTest, ""},
		{"module cache coverage never counts", RunOutput{ExitCode: 1, Output: []byte("--- FAIL: TestPoC (0.00s)\nFAIL\n"), Coverage: []byte("mode: set\nexample.com/a/b/pkg@v1.0.0/x.go:3.1,4.2 1 1\nexample.com/a/b/vendor/example.com/a/b/pkg/x.go:3.1,4.2 1 1\n")}, abTargets(nil, []string{"pkg/x.go", "pkg@v1.0.0/x.go", "vendor/example.com/a/b/pkg/x.go"}), KindNone, ReasonExitNoSignal},
		{"oversized crash header is not a header", RunOutput{ExitCode: 2, Output: []byte("panic: " + strings.Repeat("x", 5000) + "\n\ngoroutine 1 [running]:\nexample.com/a/b/pkg.F(...)\n\t/work/src/pkg/x.go:3\n")}, claimedF, KindNone, ReasonExitNoSignal},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Analyze(tc.out, tc.targets)
			if got.Kind != tc.kind || got.Reason != tc.reason {
				t.Fatalf("Analyze = %+v, want kind %q reason %q", got, tc.kind, tc.reason)
			}
		})
	}
}

func TestCanonicalRejectsEmptyToken(t *testing.T) {
	for _, sym := range []string{"example.com/a/pkg.glob..func1", "pkg..F", "pkg.F."} {
		if p, n, ok := canonical(sym); ok {
			t.Errorf("canonical(%q) = %q, %q, ok", sym, p, n)
		}
	}
	if _, n, ok := canonical("example.com/a/pkg.F.func1.2"); !ok || n != "F" {
		t.Errorf("closure: got %q %v", n, ok)
	}
}

func TestRaceReportCap(t *testing.T) {
	one := "==================\nWARNING: DATA RACE\nRead at 0x01 by goroutine 1:\n  example.com/a/b/pkg.Other()\n      /work/src/pkg/x.go:9 +0x1\n\nPrevious write at 0x01 by goroutine 2:\n  example.com/a/b/pkg.Other()\n      /work/src/pkg/x.go:9 +0x1\n==================\n"
	stacks := raceStacks(splitLines([]byte(strings.Repeat(one, maxRaceReports+10))))
	if len(stacks) != 2*maxRaceReports {
		t.Fatalf("got %d stacks from %d reports, want %d", len(stacks), maxRaceReports+10, 2*maxRaceReports)
	}
}
