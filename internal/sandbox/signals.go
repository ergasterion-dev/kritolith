package sandbox

import (
	"bytes"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// Signal kinds. Only the first three are reproductions; see the
// "Reproduced signals" section of the sandbox design.
const (
	KindPanic       = "panic-in-claimed-code"
	KindRace        = "race-in-claimed-code"
	KindFailingTest = "failing-test-reaching-claimed-code"
	KindNone        = "none"
)

// Reasons a run did not reproduce. A reproduction has Reason "".
const (
	ReasonBuild         = "build"
	ReasonTimeout       = "timeout"
	ReasonOOM           = "oom"
	ReasonNoClaimedCode = "no-claimed-code-in-stack"
	ReasonExitNoSignal  = "exit-nonzero-no-signal"
	ReasonTruncated     = "truncated"
	ReasonNoTestsRan    = "no-tests-ran"
	ReasonPassed        = "passed"
	// ReasonSkipped is never returned by Analyze, which cannot tell
	// which tests were requested: the Runner sets it when a run that
	// Analyze calls "passed" skipped a requested test (t.Skip exits 0).
	ReasonSkipped = "skipped"
)

var validReasons = map[string]bool{
	"": true, ReasonBuild: true, ReasonTimeout: true, ReasonOOM: true, ReasonNoClaimedCode: true,
	ReasonExitNoSignal: true, ReasonTruncated: true, ReasonNoTestsRan: true, ReasonPassed: true, ReasonSkipped: true,
}

// Work caps: Analyze reads hostile output and must stay cheap.
const (
	maxScanBytes   = 1 << 20 // of Output, and of Coverage
	maxStackFrames = 200     // per stack examined
	maxLineBytes   = 4096    // longer lines are never frames, headers or profile lines
	maxRaceReports = 32
	maxDetailBytes = 300
)

// FuncRange is the line span [Start, End] (1-based, inclusive) of one
// claimed function's declaration in a file.
type FuncRange struct {
	Name       string
	Start, End int
}

// Targets is the claimed code a run must reach to count as a
// reproduction. Build it with TargetsFromClaims; the sandbox adds
// PoCFiles and FuncRanges.
type Targets struct {
	// Module is the repository's module path (go.mod at the ref). With
	// no module nothing can be told apart from dependency code, so
	// nothing reproduces.
	Module string
	// Funcs are fully qualified function names in the runtime's form
	// with the receiver written without "*" ("github.com/x/y/pkg.T.M",
	// "github.com/x/y/pkg.F"; a dot in the last import path element is
	// escaped as "%2e", as the runtime prints it). "(*T).M" is accepted
	// and normalised. Entries outside Module are ignored.
	Funcs []string
	// Files are repo-relative .go files claimed by the report.
	Files []string
	// PkgDirs are the repo-relative directories declaring the claimed
	// code (the -coverpkg scope).
	PkgDirs []string
	// PoCFiles are the repo-relative paths the PoC's files were placed
	// at. Frames and coverage in them never count.
	PoCFiles []string
	// FuncRanges maps a repo-relative file to the line ranges of the
	// claimed functions declared in it (filled from grounding's AST).
	// A coverage block counts for signal 3 only inside one of these, or
	// anywhere in a file listed in Files.
	FuncRanges map[string][]FuncRange
}

// RunOutput is what the run phase captured.
type RunOutput struct {
	ExitCode  int
	TimedOut  bool // wall-clock limit hit
	OOM       bool // memory limit hit
	Truncated bool // output cap hit
	Output    []byte
	Coverage  []byte // a -coverprofile file, if any
}

// Signal is Analyze's decision. Kind is one of the Kind constants;
// Reason is "" for a reproduction and one of the Reason constants
// otherwise. Weak marks signal 3. Detail is printable, bounded text
// that may quote the (hostile) output.
type Signal struct {
	Kind   string
	Detail string
	Weak   bool
	Reason string
}

// TargetsFromClaims turns grounded claims into Targets. Only claims
// grounding verified (Verified == yes) count, from either source:
// function claims whose declaration grounding pinned to one package
// directory in the repository (DeclPkgDir set), and file claims naming
// a non-test .go file. Vendored and testdata directories, and
// directories the go tool ignores, are dependency or fixture code and
// are dropped. An empty or malformed modulePath yields no targets.
//
// The repository root is taken to be the module root, as grounding
// does.
func TargetsFromClaims(claims []report.Claim, modulePath string) Targets {
	if !validModulePath(modulePath) {
		return Targets{}
	}
	t := Targets{Module: modulePath}
	funcs, files, dirs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, c := range claims {
		if c.Verified != report.TriYes {
			continue
		}
		switch c.Kind {
		case report.ClaimFunction:
			if c.DeclPkgDir == "" || !validPkgDir(c.DeclPkgDir) || !isIdent(c.DeclName) || (c.DeclReceiver != "" && !isIdent(c.DeclReceiver)) {
				continue
			}
			name := c.DeclName
			if c.DeclReceiver != "" {
				name = c.DeclReceiver + "." + c.DeclName
			}
			funcs[runtimePkgPath(modulePath, c.DeclPkgDir)+"."+name] = true
			dirs[c.DeclPkgDir] = true
		case report.ClaimFile:
			f := c.Value
			base := path.Base(f)
			if path.Clean(f) != f || !strings.HasSuffix(f, ".go") || strings.HasSuffix(f, "_test.go") ||
				!validPkgDir(path.Dir(f)) || !validElem(base) {
				continue
			}
			files[f] = true
			dirs[path.Dir(f)] = true
		}
	}
	t.Funcs, t.Files, t.PkgDirs = sortedKeys(funcs), sortedKeys(files), sortedKeys(dirs)
	return t
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func validModulePath(m string) bool {
	if m == "" || len(m) > 512 {
		return false
	}
	for _, e := range strings.Split(m, "/") {
		if e == "" || e == "." || e == ".." {
			return false
		}
		for _, r := range e {
			if !(r < unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("-._~+", r))) {
				return false
			}
		}
	}
	return true
}

// validPkgDir accepts "." or a clean relative path whose elements the
// go tool builds as the module's own packages.
func validPkgDir(d string) bool {
	if d == "." {
		return true
	}
	if d == "" || path.Clean(d) != d || path.IsAbs(d) || strings.Contains(d, "\\") {
		return false
	}
	for _, e := range strings.Split(d, "/") {
		if e == "vendor" || e == "testdata" || !validElem(e) {
			return false
		}
	}
	return true
}

func validElem(e string) bool {
	if e == "" || e == "." || e == ".." || e[0] == '.' || e[0] == '_' {
		return false
	}
	for _, r := range e {
		if unicode.IsControl(r) || unicode.IsSpace(r) || r == '\\' || r == ':' || r == '%' {
			return false
		}
	}
	return true
}

func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if !(unicode.IsLetter(r) || r == '_' || (i > 0 && unicode.IsDigit(r))) {
			return false
		}
	}
	return true
}

// runtimePkgPath is the import path of dir as the runtime prints it in
// symbol names: dots in the last element are escaped as %2e.
func runtimePkgPath(module, dir string) string {
	ip := module
	if dir != "." {
		ip = module + "/" + dir
	}
	i := strings.LastIndex(ip, "/")
	return ip[:i+1] + strings.ReplaceAll(ip[i+1:], ".", "%2e")
}

// Analyze decides whether a run reproduced claimed behaviour. It never
// panics, reads at most maxScanBytes of output and of coverage, and
// returns a reproducing Kind only when a frame or coverage block lies in
// a claimed function or file that is in the module and not in the PoC.
// It never returns ReasonSkipped: an all-skipped run that exits 0 is
// ReasonPassed here, and the Runner, which knows the requested test
// names, turns it into ReasonSkipped.
func Analyze(out RunOutput, t Targets) Signal {
	data := out.Output
	truncated := out.Truncated
	if len(data) > maxScanBytes {
		data, truncated = data[:maxScanBytes], true
	}
	lines := splitLines(data)
	m := newMatcher(t)

	failed := out.ExitCode != 0
	// Build text in run-phase output only matters on a failed run: on
	// exit 0 it is something the PoC printed. The Runner must derive a
	// "build" outcome from the build phase's own output, never from the
	// run phase's.
	if failed && buildFailed(lines) {
		return none(ReasonBuild, "the PoC did not build")
	}
	var crashSeen, raceSeen, timeoutMsg, oomMsg bool
	if failed {
		if h := lastCrash(lines); h >= 0 {
			header := lines[h]
			switch {
			case strings.HasPrefix(header, "panic: test timed out after"):
				timeoutMsg = true
			case strings.HasPrefix(header, "fatal error: runtime: out of memory"),
				strings.HasPrefix(header, "fatal error: out of memory"):
				oomMsg = true
			case strings.HasPrefix(header, "fatal error: all goroutines are asleep"):
				// A deadlock is a hang, not a crash in claimed code.
			default:
				crashSeen = true
				if fr, ok := m.walk(crashStack(lines, h)); ok {
					return Signal{Kind: KindPanic, Detail: "crash through claimed code at " + fr.String() + ": " + clip(header)}
				}
			}
		}
		races := raceStacks(lines)
		raceSeen = len(races) > 0
		for _, st := range races {
			if fr, ok := m.walk(st); ok {
				return Signal{Kind: KindRace, Detail: "data race reported in claimed code at " + fr.String()}
			}
		}
	}
	if out.OOM || oomMsg {
		return none(ReasonOOM, "the run hit the memory limit")
	}
	if out.TimedOut || timeoutMsg {
		return none(ReasonTimeout, "the run hit the time limit")
	}
	if failed && !crashSeen && !raceSeen && m.ok {
		if test := failedTest(lines); test != "" {
			if hit := m.coverageHit(out.Coverage); hit != "" {
				return Signal{Kind: KindFailingTest, Weak: true, Detail: clip(test) + " failed, and coverage shows claimed code executed: " + hit}
			}
		}
	}
	if truncated {
		return none(ReasonTruncated, "the output was truncated before a signal was found")
	}
	if crashSeen || raceSeen {
		return none(ReasonNoClaimedCode, "the run crashed or raced, but not in claimed code")
	}
	if !failed {
		if noTestsRan(lines) {
			return none(ReasonNoTestsRan, "no test ran")
		}
		return none(ReasonPassed, "the PoC ran to completion and exited 0")
	}
	return none(ReasonExitNoSignal, fmt.Sprintf("the run exited %d without a signal in claimed code", out.ExitCode))
}

func none(reason, detail string) Signal {
	return Signal{Kind: KindNone, Reason: reason, Detail: detail}
}

func clip(s string) string {
	s = report.Printable(s)
	if len(s) > maxDetailBytes {
		s = strings.ToValidUTF8(s[:maxDetailBytes], "") + "..."
	}
	return s
}

func splitLines(b []byte) []string {
	raw := bytes.Split(b, []byte("\n"))
	out := make([]string, len(raw))
	for i, l := range raw {
		out[i] = strings.TrimSuffix(string(l), "\r")
	}
	return out
}

var (
	buildFailRe   = regexp.MustCompile(`^FAIL\s.*\[(build|setup) failed\]\s*$`)
	compileErrRe  = regexp.MustCompile(`^\S+\.go:\d+(:\d+)?: `)
	goroutineRe   = regexp.MustCompile(`^goroutine \d+ .*\[.*\]:\s*$`)
	raceAccessRe  = regexp.MustCompile(`^\s*(Previous )?([Aa]tomic )?([Rr]ead|[Ww]rite) at 0x[0-9a-fA-F]+ by (main goroutine|goroutine \d+):\s*$`)
	fileLineRe    = regexp.MustCompile(`^(\S.*?):(\d+)(\s+\+0x[0-9a-fA-F]+)?(\s+fp=.*)?$`)
	closureTokRe  = regexp.MustCompile(`^((func|gowrap|deferwrap)\d+|\d+)$`)
	failedTestRe  = regexp.MustCompile(`^\s*--- FAIL: (\S+)`)
	coverLineRe   = regexp.MustCompile(`^(.+):(\d+)\.(\d+),(\d+)\.(\d+) (\d+) (\d+)$`)
	coverModeRe   = regexp.MustCompile(`^mode: (set|count|atomic)$`)
	raceStartLine = "WARNING: DATA RACE"
	raceEndLine   = "=================="
)

func buildFailed(lines []string) bool {
	for i, l := range lines {
		if len(l) > maxLineBytes {
			continue
		}
		if buildFailRe.MatchString(l) {
			return true
		}
		if strings.HasPrefix(l, "# ") && i+1 < len(lines) && len(lines[i+1]) <= maxLineBytes && compileErrRe.MatchString(lines[i+1]) {
			return true
		}
	}
	return false
}

// lastCrash returns the index of the last "panic: " or "fatal error: "
// header, or -1. The last one is the crash that ended the process;
// anything the PoC printed earlier is ignored.
func lastCrash(lines []string) int {
	for i := len(lines) - 1; i >= 0; i-- {
		l := lines[i]
		if len(l) > maxLineBytes {
			continue
		}
		if strings.HasPrefix(l, "panic: ") || strings.HasPrefix(l, "fatal error: ") {
			return i
		}
	}
	return -1
}

type frame struct {
	sym  string // function symbol without arguments
	file string
	line int
}

func (f frame) String() string {
	s := f.sym
	if f.file != "" {
		s += " (" + f.file + ":" + strconv.Itoa(f.line) + ")"
	}
	return clip(s)
}

// crashStack returns the crashing goroutine's frames from the panic
// site outward: the first goroutine block after the header, with the
// deferred-call frames above the first "panic(" frame removed.
func crashStack(lines []string, header int) []frame {
	for i := header + 1; i < len(lines) && i < header+1+4*maxStackFrames; i++ {
		if len(lines[i]) <= maxLineBytes && goroutineRe.MatchString(lines[i]) {
			frames := parseFrames(lines, i+1)
			for j, f := range frames {
				if f.sym == "panic" {
					return frames[j+1:]
				}
			}
			return frames
		}
	}
	return nil
}

// raceStacks returns the access stacks (not the goroutine-creation
// stacks) of every race report.
func raceStacks(lines []string) [][]frame {
	var out [][]frame
	inRace, reports := false, 0
	for i := 0; i < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		switch {
		case l == raceStartLine:
			if reports >= maxRaceReports {
				return out
			}
			reports++
			inRace = true
		case l == raceEndLine:
			inRace = false
		case inRace && len(lines[i]) <= maxLineBytes && raceAccessRe.MatchString(lines[i]):
			out = append(out, parseFrames(lines, i+1))
		}
	}
	return out
}

// parseFrames reads "func(args)" / "\tfile:line +0x.." pairs from start
// until a blank line, a "created by" line, anything else, or the frame
// cap. Both goroutine tracebacks and race-report stacks use this shape.
func parseFrames(lines []string, start int) []frame {
	var frames []frame
	for i := start; i < len(lines) && len(frames) < maxStackFrames; i++ {
		raw := lines[i]
		if len(raw) > maxLineBytes {
			break
		}
		l := strings.TrimSpace(raw)
		if l == "" || strings.HasPrefix(l, "created by ") {
			break
		}
		if l == "...additional frames elided..." {
			continue
		}
		if sym, ok := stripArgs(l); ok {
			frames = append(frames, frame{sym: sym})
			continue
		}
		indented := raw != "" && (raw[0] == '\t' || raw[0] == ' ')
		if mm := fileLineRe.FindStringSubmatch(l); indented && mm != nil && len(frames) > 0 && frames[len(frames)-1].file == "" {
			n, err := strconv.Atoi(mm[2])
			if err != nil {
				break
			}
			frames[len(frames)-1].file, frames[len(frames)-1].line = mm[1], n
			continue
		}
		break
	}
	return frames
}

// stripArgs removes the trailing argument list "(...)" of a traceback
// function line.
func stripArgs(l string) (string, bool) {
	if !strings.HasSuffix(l, ")") {
		return "", false
	}
	depth := 0
	for i := len(l) - 1; i >= 0; i-- {
		switch l[i] {
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				if i == 0 || strings.ContainsAny(l[:i], " \t") {
					return "", false
				}
				return l[:i], true
			}
		}
	}
	return "", false
}

// canonical splits a runtime symbol into its unescaped package path and
// a name of the form "F" or "T.M": pointer receivers lose "(*)",
// generic instantiations lose "[...]", and closures, go/defer wrappers,
// method values and range-func bodies are attributed to the function
// that lexically contains them.
func canonical(sym string) (pkg, name string, ok bool) {
	var b strings.Builder
	depth := 0
	for _, r := range sym {
		switch {
		case r == '[':
			depth++
		case r == ']':
			depth--
			if depth < 0 {
				return "", "", false
			}
		case depth == 0:
			b.WriteRune(r)
		}
	}
	if depth != 0 {
		return "", "", false
	}
	s := b.String()
	slash := strings.LastIndex(s, "/")
	dot := strings.Index(s[slash+1:], ".")
	if dot < 0 {
		return "", "", false
	}
	pkg = strings.ReplaceAll(s[:slash+1+dot], "%2e", ".")
	rest := s[slash+1+dot+1:]
	rest = strings.NewReplacer("(*", "", "(", "", ")", "").Replace(rest)
	var toks []string
	for _, tok := range strings.Split(rest, ".") {
		if tok == "" {
			// "pkg.glob..func1" (a package-level closure) or a
			// malformed symbol: not attributable to a declared function.
			return "", "", false
		}
		if closureTokRe.MatchString(tok) {
			break
		}
		if i := strings.Index(tok, "-"); i >= 0 {
			tok = tok[:i]
		}
		if !isIdent(tok) {
			return "", "", false
		}
		toks = append(toks, tok)
	}
	if pkg == "" || len(toks) == 0 || len(toks) > 2 {
		return "", "", false
	}
	return pkg, strings.Join(toks, "."), true
}

type funcTarget struct{ pkg, name string }

type matcher struct {
	ok     bool
	t      Targets
	funcs  map[funcTarget]bool
	files  []string
	pocs   []string
	module string
}

func newMatcher(t Targets) *matcher {
	m := &matcher{t: t, funcs: map[funcTarget]bool{}, module: t.Module}
	if !validModulePath(t.Module) {
		return m
	}
	for _, f := range t.Funcs {
		pkg, name, ok := canonical(f)
		if ok && m.inModule(pkg) {
			m.funcs[funcTarget{pkg, name}] = true
		}
	}
	for _, f := range t.Files {
		if path.Clean(f) == f && strings.HasSuffix(f, ".go") && validPkgDir(path.Dir(f)) {
			m.files = append(m.files, f)
		}
	}
	for _, p := range t.PoCFiles {
		if p = strings.TrimPrefix(path.Clean(p), "/"); p != "" && p != "." {
			m.pocs = append(m.pocs, p)
		}
	}
	m.ok = len(m.funcs) > 0 || len(m.files) > 0
	return m
}

func (m *matcher) inModule(pkg string) bool {
	return pkg == m.module || strings.HasPrefix(pkg, m.module+"/")
}

func (m *matcher) pkgForDir(dir string) string {
	if dir == "." {
		return m.module
	}
	return m.module + "/" + dir
}

func hasPathSuffix(p, rel string) bool {
	return p == rel || strings.HasSuffix(p, "/"+rel)
}

func (m *matcher) isPoC(fr frame) bool {
	if fr.file == "" {
		return false
	}
	for _, p := range m.pocs {
		if hasPathSuffix(fr.file, p) {
			return true
		}
	}
	return false
}

// claimed reports whether a (non-PoC) frame is in claimed code inside
// the module. A frame in package main matches a claimed function only
// when its file sits in the claimed package's directory (the runtime
// names every main package "main"); a root main package can't be told
// apart that way and never matches.
func (m *matcher) claimed(fr frame) bool {
	if fr.file == "" || outsideTree(fr.file) {
		return false
	}
	pkg, name, ok := canonical(fr.sym)
	if !ok {
		return false
	}
	if pkg == "main" {
		fdir := path.Dir(fr.file)
		for ft := range m.funcs {
			if ft.name != name || ft.pkg == m.module {
				continue
			}
			if hasPathSuffix(fdir, strings.TrimPrefix(ft.pkg, m.module+"/")) {
				return true
			}
		}
		for _, f := range m.files {
			if path.Dir(f) != "." && hasPathSuffix(fr.file, f) {
				return true
			}
		}
		return false
	}
	if !m.inModule(pkg) {
		return false
	}
	if m.funcs[funcTarget{pkg, name}] {
		return true
	}
	for _, f := range m.files {
		if pkg == m.pkgForDir(path.Dir(f)) && hasPathSuffix(fr.file, f) {
			return true
		}
	}
	return false
}

// outsideTree reports whether a file path points at a copy of the code
// other than the checked-out tree: the module cache (an element with a
// version, "pkg@v1.2.3") or a vendor directory. Such a copy is a
// released version, not the claimed ref, so it never counts, even when
// its import path is the module's own.
func outsideTree(p string) bool {
	for _, e := range strings.Split(p, "/") {
		if e == "vendor" || strings.Contains(e, "@") {
			return true
		}
	}
	return false
}

// walk scans a stack from the innermost frame outward and reports the
// first claimed frame met before any PoC frame. Stopping at the PoC
// means a PoC callback that panics (or races) while claimed code is
// merely further up the stack does not count.
func (m *matcher) walk(frames []frame) (frame, bool) {
	if !m.ok {
		return frame{}, false
	}
	for _, fr := range frames {
		if m.isPoC(fr) {
			return frame{}, false
		}
		if m.claimed(fr) {
			return fr, true
		}
	}
	return frame{}, false
}

func failedTest(lines []string) string {
	for _, l := range lines {
		if len(l) > maxLineBytes {
			continue
		}
		if mm := failedTestRe.FindStringSubmatch(l); mm != nil {
			return mm[1]
		}
	}
	return ""
}

func noTestsRan(lines []string) bool {
	for _, l := range lines {
		if strings.Contains(l, "[no tests to run]") || strings.Contains(l, "testing: warning: no tests to run") || strings.Contains(l, "[no test files]") {
			return true
		}
	}
	return false
}

// coverageHit returns a description of the first executed coverage
// block that lies in a claimed function's line range or in a claimed
// file, or "" when there is none or the profile is malformed.
func (m *matcher) coverageHit(profile []byte) string {
	if len(profile) > maxScanBytes {
		profile = profile[:maxScanBytes]
	}
	lines := splitLines(profile)
	first := true
	for _, l := range lines {
		if l == "" || len(l) > maxLineBytes {
			continue
		}
		if first {
			if !coverModeRe.MatchString(l) {
				return ""
			}
			first = false
			continue
		}
		mm := coverLineRe.FindStringSubmatch(l)
		if mm == nil {
			continue
		}
		start, err1 := strconv.Atoi(mm[2])
		end, err2 := strconv.Atoi(mm[4])
		stmts, err3 := strconv.Atoi(mm[6])
		count, err4 := strconv.Atoi(mm[7])
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil || count <= 0 || stmts <= 0 || start <= 0 || end < start {
			continue
		}
		rel, ok := strings.CutPrefix(mm[1], m.module+"/")
		if !ok || outsideTree(mm[1]) || path.Clean(rel) != rel || !validPkgDir(path.Dir(rel)) {
			continue
		}
		if m.isPoC(frame{file: rel}) {
			continue
		}
		for _, f := range m.files {
			if rel == f {
				return clip(fmt.Sprintf("%s:%d-%d", rel, start, end))
			}
		}
		for _, r := range m.t.FuncRanges[rel] {
			if r.Start > 0 && r.End >= r.Start && start >= r.Start && end <= r.End {
				return clip(fmt.Sprintf("%s:%d-%d in %s", rel, start, end, r.Name))
			}
		}
	}
	return ""
}
