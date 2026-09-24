package ground

import (
	"context"
	"fmt"
	"go/token"
	"go/types"
	"path"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

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
// ref resolved, which commit it resolved to, and whether that commit
// came from a fallback version rather than the claimed ref itself (see
// Mirror.EnsureAndResolve), and the resolved commit's go.mod module
// path. An error here means
// the mirror itself couldn't be used (clone/fetch failure); callers
// must degrade to "not resolved" rather than propagate it as a
// pipeline failure (see Task 5's Service).
func groundClaims(ctx context.Context, m *Mirror, r report.Report, claims []report.Claim) (grounded []report.Claim, refResolved bool, resolvedCommit string, viaFallback bool, module string, err error) {
	var versions []string
	for _, c := range claims {
		if c.Kind == report.ClaimVersion {
			versions = append(versions, c.Value)
			if len(versions) >= maxFallbackRefs {
				break
			}
		}
	}
	commit, resolved, viaFallback, err := m.EnsureAndResolve(ctx, r.ClaimedRef, versions)
	if err != nil {
		return claims, false, "", false, "", err
	}
	if !resolved {
		return claims, false, "", false, "", nil
	}

	idx := newLazyIndex(ctx, m, commit)
	out := make([]report.Claim, len(claims))
	copy(out, claims)
	for i := range out {
		switch out[i].Kind {
		case report.ClaimFile:
			groundFileClaim(ctx, m, commit, &out[i], idx)
		case report.ClaimFunction:
			groundFunctionClaim(&out[i], idx)
		case report.ClaimLine:
			groundLineClaim(ctx, m, commit, &out[i], idx.get().decls)
		}
	}
	// Read go.mod directly here rather than through idx.get(): forcing
	// the full lazy index (a whole-tree file listing and read) just to
	// learn the module path would be wasteful for a report whose claims
	// never triggered it otherwise (e.g. version/vuln_class/sink only).
	var mod string
	if gomod, ok, err := m.ReadFile(ctx, commit, "go.mod"); err == nil && ok {
		mod = modulePath(gomod)
	}
	return out, true, commit, viaFallback, mod, nil
}

// symbolIndex is everything grounding learned from one scan of the
// repository's Go source at a resolved commit.
type symbolIndex struct {
	files  []string            // every .go path at the commit (possibly truncated)
	decls  []declaration       // top-level funcs and methods
	types  map[string]typeDecl // top-level types by name; methodSetOpen ORed across same-named types
	idents map[string]struct{} // every identifier token in any scanned file
	pkgs   map[string]bool     // package clause names declared in the repository
	// imports maps a local import name to every path imported under
	// that name anywhere in the repository.
	imports map[string][]string
	// module is the root go.mod's module path, or "" if there isn't
	// one (then every import counts as possibly external).
	module string
	// dirs holds every directory (and ancestor directory) containing
	// a listed Go file.
	dirs map[string]bool
	// unbound holds identifiers some file uses as the "x" of an "x.Y"
	// selector without an import binding x exactly (see
	// fileSymbols.unboundQualifiers).
	unbound map[string]bool
	// listed is true when files is the repository's full list of Go
	// files (the listing worked, wasn't truncated, and the tree has no
	// submodules, whose contents ls-tree can't see).
	listed bool
	// unparsed counts files go/parser rejected. Their identifiers are
	// still in idents, but their package clause, types, and imports
	// are missing, so claims whose disproof depends on those stay
	// unknown while it's non-zero.
	unparsed int
	// incomplete is non-empty when the scan could not cover the whole
	// tree (listing failed, too many files, a file couldn't be read).
	// An incomplete scan can confirm a claim but never disprove one.
	incomplete string
}

type lazyIndex struct {
	ctx    context.Context
	m      *Mirror
	commit string
	idx    *symbolIndex
	words  map[string]wordResult // ContainsWord results, by name
}

type wordResult struct {
	found bool
	err   error
}

// containsWord caches Mirror.ContainsWord per name for this commit.
func (l *lazyIndex) containsWord(name string) (bool, error) {
	if r, ok := l.words[name]; ok {
		return r.found, r.err
	}
	found, err := l.m.ContainsWord(l.ctx, l.commit, name)
	if l.words == nil {
		l.words = map[string]wordResult{}
	}
	l.words[name] = wordResult{found: found, err: err}
	return found, err
}

func newLazyIndex(ctx context.Context, m *Mirror, commit string) *lazyIndex {
	return &lazyIndex{ctx: ctx, m: m, commit: commit}
}

// get builds the index on first use and caches it. It never fails:
// every problem is recorded in symbolIndex.incomplete instead.
func (l *lazyIndex) get() *symbolIndex {
	if l.idx != nil {
		return l.idx
	}
	idx := &symbolIndex{
		types:   map[string]typeDecl{},
		idents:  map[string]struct{}{},
		pkgs:    map[string]bool{},
		imports: map[string][]string{},
		dirs:    map[string]bool{},
		unbound: map[string]bool{},
	}
	l.idx = idx
	if gomod, ok, err := l.m.ReadFile(l.ctx, l.commit, "go.mod"); err == nil && ok {
		idx.module = modulePath(gomod)
	}
	files, gitlinks, err := l.m.ListGoFiles(l.ctx, l.commit)
	if err != nil {
		idx.incomplete = "could not list the repository's Go files"
		return idx
	}
	idx.listed = true
	if gitlinks > 0 {
		idx.listed = false
		idx.incomplete = fmt.Sprintf("repository has %d git submodule(s) whose contents weren't scanned", gitlinks)
	}
	if len(files) > maxGoFiles {
		files = files[:maxGoFiles]
		idx.listed = false
		idx.incomplete = fmt.Sprintf("repository has more than %d Go files; only the first %d were scanned", maxGoFiles, maxGoFiles)
	}
	idx.files = files
	for _, f := range files {
		for d := path.Dir(f); d != "." && d != "/" && !idx.dirs[d]; d = path.Dir(d) {
			idx.dirs[d] = true
		}
	}
	for _, f := range files {
		content, ok, err := l.m.ReadFile(l.ctx, l.commit, f)
		if err != nil || !ok {
			if idx.incomplete == "" {
				idx.incomplete = fmt.Sprintf("could not read %s", report.Printable(f))
			}
			continue
		}
		fs := parseDeclarations(f, content)
		if fs.pkg == "" {
			idx.unparsed++
		} else {
			idx.pkgs[fs.pkg] = true
		}
		for _, im := range fs.imports {
			for _, name := range im.names {
				idx.imports[name] = append(idx.imports[name], im.path)
			}
		}
		for _, q := range fs.unboundQualifiers {
			idx.unbound[q] = true
		}
		idx.decls = append(idx.decls, fs.decls...)
		for _, t := range fs.types {
			prev, seen := idx.types[t.name]
			t.methodSetOpen = t.methodSetOpen || (seen && prev.methodSetOpen)
			idx.types[t.name] = t
		}
		scanIdentifiers(content, idx.idents)
	}
	return idx
}

// hasDirSuffix reports whether some directory in the tree is dir or
// ends with "/"+dir.
func (idx *symbolIndex) hasDirSuffix(dir string) bool {
	if idx.dirs[dir] {
		return true
	}
	for d := range idx.dirs {
		if strings.HasSuffix(d, "/"+dir) {
			return true
		}
	}
	return false
}

func (idx *symbolIndex) hasIdent(name string) bool {
	_, ok := idx.idents[name]
	return ok
}

// externalImport returns an import path, bound to the local name
// qual somewhere in the repository, that isn't inside the root
// module — i.e. evidence that "qual." can mean another module's
// package. It returns "" if every such import is in-module.
func (idx *symbolIndex) externalImport(qual string) string {
	for _, p := range idx.imports[qual] {
		if idx.module == "" || (p != idx.module && !strings.HasPrefix(p, idx.module+"/")) {
			return p
		}
	}
	return ""
}

// modulePath extracts the module path from go.mod content, or "".
func modulePath(gomod []byte) string {
	for _, line := range strings.Split(string(gomod), "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "module" {
			return strings.Trim(fields[1], "\"`")
		}
	}
	return ""
}

// groundFileClaim checks a file claim at its exact path. A miss is
// only Verified: no if the whole tree was listed, no file in it has the
// claimed path as a path suffix (reporters often cite a path relative
// to the package directory: "frame.go" for "http2/frame.go"), and the
// claim is either a bare filename or its directory exists somewhere in
// the tree. A multi-component path whose directory doesn't exist here
// ("net/http/server.go", or "v1.0.0/baz/qux.go" pulled out of a
// module-cache stack trace) is more likely a stdlib or dependency file
// mentioned in prose than a claim about this repository's layout.
func groundFileClaim(ctx context.Context, m *Mirror, commit string, c *report.Claim, l *lazyIndex) {
	ok, err := m.FileExists(ctx, commit, c.Value)
	short := shortSHA(commit)
	if err != nil {
		// A failed check is not proof of absence: never "no" here.
		c.Verified = report.TriUnknown
		c.Evidence = fmt.Sprintf("could not check the path at %s, so its absence isn't proven", short)
		return
	}
	if ok {
		c.Verified = report.TriYes
		c.Evidence = fmt.Sprintf("file exists at %s", short)
		return
	}
	idx := l.get()
	for _, f := range idx.files {
		if strings.HasSuffix(f, "/"+c.Value) {
			c.Verified = report.TriUnknown
			c.Evidence = fmt.Sprintf("not at that exact path at %s, but %s exists", short, report.Printable(f))
			return
		}
	}
	if !idx.listed {
		c.Verified = report.TriUnknown
		c.Evidence = fmt.Sprintf("not found at that exact path at %s; %s, so other locations weren't all checked", short, idx.incomplete)
		return
	}
	if dir := path.Dir(c.Value); dir != "." && !idx.hasDirSuffix(dir) {
		c.Verified = report.TriUnknown
		c.Evidence = fmt.Sprintf("not found at %s, and no directory %s exists in the repository, so it may be a standard library or dependency path", short, report.Printable(dir))
		return
	}
	c.Verified = report.TriNo
	c.Evidence = fmt.Sprintf("not found at %s", short)
}

// groundFunctionClaim sets Verified: yes when a matching func/method
// declaration exists, and Verified: no only when the claim is shaped
// so that its absence is proof (see disproves). Everything else stays
// unknown, with evidence saying why: GROUNDING_FAILED fires on
// Verified: no, and a false GROUNDING_FAILED on a real report is the
// worst bug this project can have.
func groundFunctionClaim(c *report.Claim, l *lazyIndex) {
	idx := l.get()
	if d, ambiguous := resolveUnique(idx.decls, c.Value); d != nil {
		c.Verified = report.TriYes
		c.Evidence = fmt.Sprintf("declared at %s:%d", report.Printable(d.file), d.line)
		if ambiguous {
			c.Evidence += " (ambiguous name, cannot fingerprint)"
			return
		}
		c.DeclPkgDir = path.Dir(d.file)
		c.DeclReceiver = d.receiver
		c.DeclName = d.name
		return
	}
	closest := ""
	if d := closestDeclaration(idx.decls, c.Value); d != nil {
		closest = fmt.Sprintf("; closest match: %s (%s:%d)", report.Printable(d.name), report.Printable(d.file), d.line)
	}
	if ok, why := idx.disproves(c.Value); !ok {
		c.Verified = report.TriUnknown
		c.Evidence = "no matching function or method declaration in the repository, but " + why + closest
		return
	}
	// Last check: the name must be absent from all tracked text, not
	// just Go identifiers — a name used only in a string literal, a
	// struct tag, a template, or a JS/config file is real.
	_, name := splitFunctionClaim(strings.TrimSpace(c.Value))
	found, err := l.containsWord(name)
	switch {
	case err != nil:
		c.Verified = report.TriUnknown
		c.Evidence = "no matching function or method declaration in the repository, but searching the repository's text failed, so absence isn't proven" + closest
		return
	case found:
		c.Verified = report.TriUnknown
		c.Evidence = fmt.Sprintf("no matching function or method declaration in the repository, but %s appears in the repository's tracked text (a string, struct tag, or non-Go file), so its absence as a declared function isn't proof", report.Printable(name)) + closest
		return
	}
	c.Verified = report.TriNo
	c.Evidence = "not declared in the repository" + closest
}

// disproves reports whether a function claim that matched no
// declaration is provably false, and if not, why not. Grounding has
// no import resolution, so only two shapes can be disproved, both of
// which bind the name to this repository:
//
//   - "(*T).M" / "(T).M" where T is a type declared in this
//     repository with a closed method set (no embedding, not an alias,
//     not derived from another named type) and the name M appears
//     nowhere in the repository's source. The reporter named this
//     repository's type and a method it doesn't have.
//   - "pkg.name" with an unexported name, where pkg is a package
//     declared in this repository, no file imports an out-of-module
//     package under the name pkg, and name appears nowhere in the
//     repository's source ("http2.parseHeader"). Unexported names
//     can't be reached from another package, so the claim is about
//     this repository's pkg.
//
// Every other qualified "x.Y" stays unknown: x may be an imported
// package ("protowire.ConsumeVarint", "sync.Pool"), a field or a
// variable ("URL.Scheme", "token.Data"). A bare "name" stays unknown
// too, exported or not: reporters describe call chains through code
// they didn't write ("json.Unmarshal recurses into literalStore"), so
// an unqualified name may be a function inside the standard library or
// a dependency, which grounding never scans. And nothing is
// disproved when the name appears anywhere as an identifier (it's a
// real field, type, var, const, local, or call into a dependency —
// "ChunkSize", "MaxBitLen", "paddingLength" — just not a function
// declared here) or when the scan was incomplete.
func (idx *symbolIndex) disproves(value string) (bool, string) {
	if idx.incomplete != "" {
		return false, idx.incomplete + ", so absence isn't proven"
	}
	value = strings.TrimSpace(value)
	recv, name := splitFunctionClaim(value)
	if name == "" || !isGoIdent(name) {
		return false, "the claim isn't a plain Go identifier"
	}
	if token.IsKeyword(name) || types.Universe.Lookup(name) != nil {
		return false, fmt.Sprintf("%s is a Go keyword or predeclared identifier", report.Printable(name))
	}
	if idx.hasIdent(name) {
		return false, fmt.Sprintf("%s appears in the repository source (as a field, type, variable, local, or call), so its absence as a declared function isn't proof", report.Printable(name))
	}
	switch {
	case (strings.HasPrefix(value, "(") || (recv != "" && !isExported(name))) && idx.unparsed > 0:
		return false, fmt.Sprintf("%d Go file(s) in the repository could not be parsed, so their types, packages, and imports are unknown", idx.unparsed)
	case strings.HasPrefix(value, "("):
		t, ok := idx.types[recv]
		if !ok {
			return false, fmt.Sprintf("type %s is not declared in the repository (it may belong to another package)", report.Printable(recv))
		}
		if t.methodSetOpen {
			return false, fmt.Sprintf("type %s embeds or derives from another type, so %s may be a promoted method", report.Printable(recv), report.Printable(name))
		}
		return true, ""
	case recv != "":
		switch {
		case isExported(name):
			return false, fmt.Sprintf("%s may be an imported package, a field, or a variable; without import resolution its absence here isn't proof", report.Printable(recv))
		case !idx.pkgs[recv]:
			return false, fmt.Sprintf("no package %s is declared in the repository (it may be an imported package, a field, or a variable)", report.Printable(recv))
		}
		if idx.unbound[recv] {
			return false, fmt.Sprintf("some file uses %s.X without an import that certainly binds %s (it may be a differently-named import or a variable)", report.Printable(recv), report.Printable(recv))
		}
		if ext := idx.externalImport(recv); ext != "" {
			return false, fmt.Sprintf("%s is also the name of imported package %s", report.Printable(recv), report.Printable(ext))
		}
		return true, ""
	default:
		return false, "an unqualified name may be a function in the standard library or a dependency (reporters name functions along a call chain through code they didn't write), so its absence here isn't proof"
	}
}

func isExported(name string) bool {
	r, _ := utf8.DecodeRuneInString(name)
	return unicode.IsUpper(r)
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
