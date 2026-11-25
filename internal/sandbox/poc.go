package sandbox

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// Limits on a PoC. They bound what hostile input can make us parse,
// copy into a scratch tree and hand to the compiler.
const (
	maxFiles     = 64
	maxFileBytes = 256 << 10
	maxNameBytes = 255

	// maxWalkDirs bounds the directory search done by PlacePoC so a
	// hostile repository with an enormous tree cannot stall it.
	maxWalkDirs = 5000
	// maxGoFilesPerDir bounds the package-clause reads per directory.
	maxGoFilesPerDir = 256
)

// NeedsInfo is returned when the PoC, or where it belongs, cannot be
// decided from what was supplied. The reporter (or operator) can fix
// it by supplying more. Reason may quote reporter text; callers must
// treat it as untrusted when displaying it.
type NeedsInfo struct{ Reason string }

func (e *NeedsInfo) Error() string { return "needs info: " + e.Reason }

// Inconclusive is returned when the sandbox cannot give a trustworthy
// answer for reasons that are not the reporter's to fix (a hostile or
// unusable go.mod, a missing module root). It is never a rejection of
// the report.
type Inconclusive struct{ Reason string }

func (e *Inconclusive) Error() string { return "inconclusive: " + e.Reason }

func needs(format string, a ...any) error { return &NeedsInfo{Reason: fmt.Sprintf(format, a...)} }

// Shape is the kind of PoC a report carries.
type Shape string

const (
	// ShapeTest is one or more _test.go files, dropped into the
	// target package directory and run by test function name.
	ShapeTest Shape = "test"
	// ShapeProgram is a single package main with func main.
	ShapeProgram Shape = "program"
	// ShapeFuzz is a seed corpus entry under testdata/fuzz/<FuzzName>/.
	ShapeFuzz Shape = "fuzz"
)

// PoC is a validated proof of concept. Files is a copy of the input
// artifacts; nothing in it has been executed.
type PoC struct {
	Shape     Shape
	Files     []report.Artifact
	TestNames []string // ShapeTest: Test functions declared, sorted
	FuzzName  string   // ShapeFuzz
	PkgName   string   // ShapeTest: package under test (without _test); ShapeProgram: "main"; empty for ShapeFuzz
}

// Tree is the extracted source of the repository at one ref. Paths
// are slash-separated and relative to the tree root; "." is the root.
// ReadDir returns the entry names of a directory, with a trailing "/"
// on subdirectories. Implementations must not return anything outside
// the tree.
type Tree interface {
	ReadDir(rel string) ([]string, error)
	ReadFile(rel string) ([]byte, error)
}

// quote renders hostile text for an error reason: bounded and escaped.
func quote(s string) string {
	const max = 80
	if len(s) > max {
		s = strings.ToValidUTF8(s[:max], "?") + "..."
	}
	return strconv.QuoteToASCII(s)
}

// checkComponent validates one plain file or directory name.
func checkComponent(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("empty name")
	case len(name) > maxNameBytes:
		return fmt.Errorf("name longer than %d bytes", maxNameBytes)
	case name == "." || name == "..":
		return fmt.Errorf("name is %q", name)
	case !utf8.ValidString(name):
		return fmt.Errorf("name is not valid UTF-8")
	}
	for _, r := range name {
		switch {
		case r == '/' || r == '\\':
			return fmt.Errorf("name contains a path separator")
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError:
			return fmt.Errorf("name contains a control or invalid character")
		}
	}
	return nil
}

// checkName validates a plain file name (no directories at all).
func checkName(name string) error { return checkComponent(name) }

// fuzzParts splits testdata/fuzz/<FuzzName>/<seed>.
func fuzzParts(name string) (fuzz, seed string, ok bool) {
	parts := strings.Split(name, "/")
	if len(parts) != 4 || parts[0] != "testdata" || parts[1] != "fuzz" {
		return "", "", false
	}
	return parts[2], parts[3], true
}

// checkFuzzName validates the one allowed path shape. The fuzz target
// name ends up in a -test.run regular expression, so it is limited to
// identifier characters.
func checkFuzzName(name string) error {
	fuzz, seed, ok := fuzzParts(name)
	if !ok {
		return fmt.Errorf("not a testdata/fuzz/<FuzzName>/<seed> path")
	}
	if err := checkComponent(fuzz); err != nil {
		return err
	}
	if err := checkComponent(seed); err != nil {
		return err
	}
	if !strings.HasPrefix(fuzz, "Fuzz") {
		return fmt.Errorf("fuzz target name does not start with Fuzz")
	}
	for _, r := range fuzz {
		if !(r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return fmt.Errorf("fuzz target name has a non-identifier character")
		}
	}
	return nil
}

// ValidatePoC checks the PoC files and decides their shape. Every
// failure is a *NeedsInfo. Go source is parsed, never built or run.
func ValidatePoC(arts []report.Artifact) (PoC, error) {
	if len(arts) == 0 {
		return PoC{}, needs("the report has no PoC files")
	}
	if len(arts) > maxFiles {
		return PoC{}, needs("PoC has %d files; the limit is %d", len(arts), maxFiles)
	}
	seen := make(map[string]bool, len(arts))
	var fuzzFiles, plainFiles int
	var fuzzName string
	for _, a := range arts {
		if len(a.Content) > maxFileBytes {
			return PoC{}, needs("PoC file %s is %d bytes; the limit is %d", quote(a.Name), len(a.Content), maxFileBytes)
		}
		if strings.Contains(a.Name, "/") {
			if err := checkFuzzName(a.Name); err != nil {
				return PoC{}, needs("PoC file name %s is not allowed: %v", quote(a.Name), err)
			}
			fz, _, _ := fuzzParts(a.Name)
			if fuzzName != "" && fuzzName != fz {
				return PoC{}, needs("PoC has seeds for more than one fuzz target")
			}
			fuzzName = fz
			fuzzFiles++
		} else {
			if err := checkName(a.Name); err != nil {
				return PoC{}, needs("PoC file name %s is not allowed: %v", quote(a.Name), err)
			}
			plainFiles++
		}
		key := strings.ToLower(a.Name) // also collide on case-insensitive filesystems
		if seen[key] {
			return PoC{}, needs("PoC file name %s is duplicated", quote(a.Name))
		}
		seen[key] = true
	}
	files := make([]report.Artifact, len(arts))
	for i, a := range arts {
		files[i] = report.Artifact{Name: a.Name, Content: append([]byte(nil), a.Content...)}
	}
	if fuzzFiles > 0 {
		if plainFiles > 0 {
			return PoC{}, needs("PoC mixes fuzz seeds with other files")
		}
		return PoC{Shape: ShapeFuzz, Files: files, FuzzName: fuzzName}, nil
	}
	return classifyGo(files)
}

// goFile is what we need to know about one parsed Go source file.
type goFile struct {
	name       string
	pkg        string
	tests      []string
	hasMain    bool
	isTestFile bool
}

func parseGo(a report.Artifact) (goFile, error) {
	if !strings.HasSuffix(a.Name, ".go") {
		return goFile{}, needs("PoC file %s is not a Go file", quote(a.Name))
	}
	if strings.HasPrefix(a.Name, ".") || strings.HasPrefix(a.Name, "_") {
		return goFile{}, needs("PoC file %s would be ignored by the go tool", quote(a.Name))
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, a.Name, a.Content, parser.SkipObjectResolution)
	if err != nil || f == nil {
		return goFile{}, needs("PoC file %s does not parse as Go", quote(a.Name))
	}
	g := goFile{name: a.Name, pkg: f.Name.Name, isTestFile: strings.HasSuffix(a.Name, "_test.go")}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv != nil {
			continue
		}
		switch {
		case isTestFunc(fd):
			g.tests = append(g.tests, fd.Name.Name)
		case fd.Name.Name == "main" && fd.Type.Params.NumFields() == 0 && fd.Type.Results.NumFields() == 0 && fd.Type.TypeParams.NumFields() == 0:
			g.hasMain = true
		}
	}
	return g, nil
}

// isTestFunc mirrors the go tool: TestXxx where Xxx does not start
// with a lower-case letter, taking a single *testing.T.
func isTestFunc(fd *ast.FuncDecl) bool {
	name := fd.Name.Name
	if !strings.HasPrefix(name, "Test") || name == "TestMain" {
		return false
	}
	if rest := name[len("Test"):]; rest != "" {
		if r, _ := utf8.DecodeRuneInString(rest); unicode.IsLower(r) {
			return false
		}
	}
	if fd.Type.TypeParams.NumFields() != 0 || fd.Type.Results.NumFields() != 0 || fd.Type.Params.NumFields() != 1 {
		return false
	}
	star, ok := fd.Type.Params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "T"
}

func classifyGo(files []report.Artifact) (PoC, error) {
	parsed := make([]goFile, 0, len(files))
	for _, a := range files {
		g, err := parseGo(a)
		if err != nil {
			return PoC{}, err
		}
		parsed = append(parsed, g)
	}
	allTest, anyTest := true, false
	for _, g := range parsed {
		allTest = allTest && g.isTestFile
		anyTest = anyTest || g.isTestFile
	}
	if anyTest && !allTest {
		return PoC{}, needs("PoC mixes test files with other Go files")
	}
	if !allTest {
		if len(parsed) != 1 {
			return PoC{}, needs("a program PoC must be a single file; got %d Go files", len(parsed))
		}
		g := parsed[0]
		if g.pkg != "main" || !g.hasMain {
			return PoC{}, needs("PoC %s is not a package main with func main or a _test.go file", quote(g.name))
		}
		return PoC{Shape: ShapeProgram, Files: files, PkgName: "main"}, nil
	}
	base := ""
	names := map[string]bool{}
	for _, g := range parsed {
		b := strings.TrimSuffix(g.pkg, "_test")
		if b == "" {
			b = g.pkg
		}
		if base != "" && b != base {
			return PoC{}, needs("PoC test files declare different packages (%s, %s)", quote(base), quote(b))
		}
		base = b
		for _, n := range g.tests {
			names[n] = true
		}
	}
	if len(names) == 0 {
		return PoC{}, needs("PoC has no Test function")
	}
	tests := make([]string, 0, len(names))
	for n := range names {
		tests = append(tests, n)
	}
	sort.Strings(tests)
	return PoC{Shape: ShapeTest, Files: files, TestNames: tests, PkgName: base}, nil
}

// cleanDir normalises a tree-relative directory and refuses anything
// that is not strictly inside the tree.
func cleanDir(rel string) (string, bool) {
	if rel == "" || strings.ContainsAny(rel, "\\\x00") || strings.HasPrefix(rel, "/") {
		return "", false
	}
	for _, r := range rel {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	c := path.Clean(rel)
	if c == ".." || strings.HasPrefix(c, "../") {
		return "", false
	}
	return c, true
}

func isIgnoredDirName(n string) bool {
	return strings.HasPrefix(n, ".") || strings.HasPrefix(n, "_") ||
		n == "testdata" || n == "vendor" || n == "node_modules"
}

// dirHasPkg reports whether dir holds a Go file of package pkg (or
// pkg_test). An empty pkg matches any Go file.
func dirHasPkg(tree Tree, dir, pkg string) bool {
	names, err := tree.ReadDir(dir)
	if err != nil {
		return false
	}
	read := 0
	for _, n := range names {
		if !strings.HasSuffix(n, ".go") || strings.HasPrefix(n, ".") || strings.HasPrefix(n, "_") {
			continue
		}
		if read++; read > maxGoFilesPerDir {
			break
		}
		if pkg == "" {
			return true
		}
		src, err := tree.ReadFile(path.Join(dir, n))
		if err != nil {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), n, src, parser.PackageClauseOnly)
		if err != nil || f == nil || f.Name == nil {
			continue
		}
		if f.Name.Name == pkg || f.Name.Name == pkg+"_test" {
			return true
		}
	}
	return false
}

// claimDirs returns the distinct, valid directories of verified
// function and file claims, in claim order.
func claimDirs(claims []report.Claim) []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range claims {
		if c.Verified != report.TriYes || (c.Kind != report.ClaimFunction && c.Kind != report.ClaimFile) {
			continue
		}
		raw := c.DeclPkgDir
		if raw == "" && c.Kind == report.ClaimFile {
			raw = path.Dir(c.Value)
		}
		d, ok := cleanDir(raw)
		if !ok || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// PlacePoC decides the directory (relative to the tree root) the PoC
// is dropped into. The order is fixed and never taken from free text:
// the operator's hint; the directory of a verified function or file
// claim that holds the PoC's package; the single directory holding
// that package. A program is built in a scratch directory, so it only
// needs a directory to find its module from: the hint, the single
// claimed directory, or the tree root. Zero or several candidates is a
// *NeedsInfo.
func PlacePoC(p PoC, tree Tree, hint string, claims []report.Claim) (string, error) {
	if hint != "" {
		d, ok := cleanDir(hint)
		if !ok {
			return "", needs("the PoC directory %s is not a path inside the repository", quote(hint))
		}
		if _, err := tree.ReadDir(d); err != nil {
			return "", needs("the PoC directory %s does not exist in the repository", quote(hint))
		}
		return d, nil
	}
	dirs := claimDirs(claims)
	if p.Shape == ShapeProgram {
		switch len(dirs) {
		case 0:
			return ".", nil
		case 1:
			return dirs[0], nil
		}
		return "", needs("verified claims name %d different directories; supply the PoC directory", len(dirs))
	}
	for _, d := range dirs {
		if dirHasPkg(tree, d, p.PkgName) {
			return d, nil
		}
	}
	if p.PkgName == "" {
		return "", needs("cannot tell which package the fuzz seeds belong to; supply the PoC directory")
	}
	var found []string
	visited := 0
	var walk func(dir string)
	walk = func(dir string) {
		if visited >= maxWalkDirs || len(found) > 1 {
			return
		}
		visited++
		names, err := tree.ReadDir(dir)
		if err != nil {
			return
		}
		if dirHasPkg(tree, dir, p.PkgName) {
			found = append(found, dir)
		}
		sort.Strings(names)
		for _, n := range names {
			if !strings.HasSuffix(n, "/") {
				continue
			}
			n = strings.TrimSuffix(n, "/")
			if isIgnoredDirName(n) || checkComponent(n) != nil {
				continue
			}
			walk(path.Join(dir, n))
		}
	}
	walk(".")
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return "", needs("no directory in the repository holds package %s; supply the PoC directory", quote(p.PkgName))
	}
	return "", needs("several directories hold package %s (%s, %s, ...); supply the PoC directory", quote(p.PkgName), quote(found[0]), quote(found[1]))
}

// ModuleRoot returns the directory of the nearest go.mod at or above
// dir (both relative to the tree root; "." is the root).
func ModuleRoot(tree Tree, dir string) (string, error) {
	d, ok := cleanDir(dir)
	if !ok {
		return "", &Inconclusive{Reason: "module lookup directory is outside the repository"}
	}
	first := true
	for {
		names, err := tree.ReadDir(d)
		if err != nil && first {
			return "", &Inconclusive{Reason: "PoC directory is not readable in the repository"}
		}
		first = false
		for _, n := range names {
			if n == "go.mod" {
				return d, nil
			}
		}
		if d == "." {
			return "", &Inconclusive{Reason: "no go.mod found at or above the PoC directory"}
		}
		d = path.Dir(d)
	}
}

// goModTokens splits one go.mod line the way the go tool does, but
// tolerantly: whitespace is only space, tab and CR; "//" starts a
// comment; parentheses and "=>" are their own tokens; quoted and
// back-quoted strings are one token; an unterminated quote runs to the
// end of the line.
func goModTokens(line string) []string {
	var toks []string
	i := 0
	for i < len(line) {
		c := line[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '/' && strings.HasPrefix(line[i:], "//"):
			return toks
		case c == '(' || c == ')':
			toks = append(toks, string(c))
			i++
		case c == '=' && strings.HasPrefix(line[i:], "=>"):
			toks = append(toks, "=>")
			i += 2
		case c == '`':
			j := strings.IndexByte(line[i+1:], '`')
			if j < 0 {
				toks = append(toks, line[i+1:])
				return toks
			}
			toks = append(toks, line[i+1:i+1+j])
			i += j + 2
		case c == '"':
			j := i + 1
			for j < len(line) && line[j] != '"' {
				if line[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(line) {
				toks = append(toks, strings.TrimPrefix(line[i:], `"`))
				return toks
			}
			if s, err := strconv.Unquote(line[i : j+1]); err == nil {
				toks = append(toks, s)
			} else {
				toks = append(toks, line[i+1:j])
			}
			i = j + 1
		default:
			j := i
			for j < len(line) {
				b := line[j]
				if b == ' ' || b == '\t' || b == '\r' || b == '(' || b == ')' || strings.HasPrefix(line[j:], "//") || strings.HasPrefix(line[j:], "=>") {
					break
				}
				j++
			}
			toks = append(toks, line[i:j])
			i = j
		}
	}
	return toks
}

// localReplaceProblem returns a reason when a replace right-hand side
// points at a local path outside the module, or "" when it is fine.
func localReplaceProblem(rhs []string) string {
	if len(rhs) == 0 {
		return ""
	}
	p := rhs[0]
	looksLocal := len(rhs) == 1 || p == "." || p == ".." ||
		strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../") || strings.HasPrefix(p, "/") ||
		strings.ContainsRune(p, '\\') || (len(p) >= 2 && p[1] == ':' && unicode.IsLetter(rune(p[0])))
	if !looksLocal {
		return ""
	}
	if strings.ContainsAny(p, "\\\x00") || strings.HasPrefix(p, "/") || (len(p) >= 2 && p[1] == ':') {
		return "go.mod replaces a module with an absolute or non-portable local path " + quote(p)
	}
	c := path.Clean(p)
	if c == ".." || strings.HasPrefix(c, "../") {
		return "go.mod replaces a module with a local path outside the module " + quote(p)
	}
	return ""
}

// CheckGoMod refuses a go.mod that the sandbox must not honour: a
// replace to a local path outside the module, and any toolchain line
// (which would make the go tool download and run a different
// toolchain). The reader is deliberately small and tolerant; it never
// returns a parse error, only a rejection with a reason (*Inconclusive).
func CheckGoMod(content []byte) error {
	src := strings.TrimPrefix(string(content), "\xef\xbb\xbf")
	block := ""
	for _, line := range strings.Split(src, "\n") {
		toks := goModTokens(line)
		if len(toks) == 0 {
			continue
		}
		dir, args := block, toks
		if block == "" {
			dir, args = toks[0], toks[1:]
			if n := len(args); n > 0 && args[n-1] == "(" {
				block, args = dir, args[:n-1]
			}
		} else if toks[0] == ")" {
			block = ""
			continue
		}
		switch dir {
		case "toolchain":
			return &Inconclusive{Reason: "go.mod has a toolchain line"}
		case "replace":
			for i, t := range args {
				if t == "=>" {
					if why := localReplaceProblem(args[i+1:]); why != "" {
						return &Inconclusive{Reason: why}
					}
					break
				}
			}
		}
	}
	return nil
}
