// Package ground checks extracted claims against the actual code at
// the reporter's claimed commit, using git (shelled out to) and
// go/parser only. Function and method grounding is a syntax-level
// search, not import-aware or type-checked: it never claims "package"
// identity it didn't verify.
package ground

import (
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"strconv"
	"strings"
	"unicode"
)

// declaration is one top-level function or method declaration found
// while scanning a repo tree at a resolved commit.
type declaration struct {
	name     string // function name, or method name for a method
	receiver string // receiver type name, without "*"; empty for a plain function
	file     string
	line     int
	endLine  int
}

// fileSymbols is what grounding keeps from parsing one Go file.
type fileSymbols struct {
	pkg     string        // package clause name
	decls   []declaration // top-level funcs and methods
	types   []typeDecl    // top-level types
	imports []importRef   // every import, with the local name(s) it may bind
	// unboundQualifiers are identifiers used as "x" in an "x.Y"
	// selector in this file that no import in the file is known to
	// bind exactly: a variable or field, or an import whose package
	// name differs from its path ("github.com/foo/go-yaml" used as
	// "yaml"). Either way "x.Y" there may not mean a repo package x.
	unboundQualifiers []string
}

// importRef is one import spec: the local names it may bind in the
// file (exactly one for an aliased import, several plausible guesses
// for an unaliased one) and the import path.
type importRef struct {
	names []string
	path  string
}

// parseDeclarations parses one Go source file's content and returns
// its package name, every top-level function and method declaration,
// every top-level type declaration (see typeDecl), and its imports. A
// file that fails to parse contributes nothing rather than failing the
// whole search: build-tag-gated syntax this parser can't handle, or a
// hostile/malformed file, must never abort grounding. (Its identifiers
// are still collected by scanIdentifiers, which needs no parse, so an
// unparseable file can only make grounding less willing to call a
// claim false, never more.)
func parseDeclarations(file string, content []byte) fileSymbols {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, content, parser.SkipObjectResolution)
	if err != nil {
		return fileSymbols{}
	}
	out := fileSymbols{pkg: f.Name.Name}
	exact := map[string]bool{} // local names this file's imports certainly bind
	for _, is := range f.Imports {
		path, err := strconv.Unquote(is.Path.Value)
		if err != nil {
			continue
		}
		if is.Name != nil {
			out.imports = append(out.imports, importRef{names: []string{is.Name.Name}, path: path})
			exact[is.Name.Name] = true
			continue
		}
		out.imports = append(out.imports, importRef{names: importNameCandidates(path), path: path})
		if last := lastPathElem(path); isGoIdent(last) {
			exact[last] = true
		}
	}
	seen := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		se, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := se.X.(*ast.Ident); ok && !exact[id.Name] && !seen[id.Name] {
			seen[id.Name] = true
			out.unboundQualifiers = append(out.unboundQualifiers, id.Name)
		}
		return true
	})
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			decl := declaration{
				name:    d.Name.Name,
				file:    file,
				line:    fset.Position(d.Pos()).Line,
				endLine: fset.Position(d.End()).Line,
			}
			if d.Recv != nil && len(d.Recv.List) > 0 {
				decl.receiver = receiverTypeName(d.Recv.List[0].Type)
			}
			out.decls = append(out.decls, decl)
		case *ast.GenDecl:
			if d.Tok != token.TYPE {
				continue
			}
			for _, spec := range d.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				out.types = append(out.types, typeDecl{name: ts.Name.Name, methodSetOpen: methodSetOpen(ts)})
			}
		}
	}
	return out
}

// lastPathElem returns an import path's last element, skipping a
// trailing "/vN" major-version element.
func lastPathElem(path string) string {
	elems := strings.Split(path, "/")
	last := elems[len(elems)-1]
	if len(elems) > 1 && isMajorVersion(last) {
		last = elems[len(elems)-2]
	}
	return last
}

// importNameCandidates returns every package name an unaliased import
// of path plausibly binds, without loading the package: the last path
// element (skipping a "/vN" element), and variants of it with a
// gopkg.in-style ".vN" suffix, a "go-"/"go_" prefix, or a
// "-go"/"_go"/".go" suffix stripped, dashes replaced by underscores,
// and each dash- or dot-separated piece. It deliberately
// over-generates: these names are only used to decide that a "pkg."
// qualifier might mean an out-of-module import, so a spurious
// candidate can only stop grounding from calling a claim false. (A
// package whose name matches none of these is still caught by
// fileSymbols.unboundQualifiers when a file uses it.)
func importNameCandidates(path string) []string {
	last := lastPathElem(path)
	set := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !set[s] {
			set[s] = true
			out = append(out, s)
		}
	}
	bases := []string{last}
	if i := strings.LastIndex(last, ".v"); i > 0 && isMajorVersion(last[i+1:]) {
		bases = append(bases, last[:i])
	}
	for _, b := range bases {
		for _, v := range []string{
			b,
			strings.TrimPrefix(strings.TrimPrefix(b, "go-"), "go_"),
			strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(b, "-go"), "_go"), ".go"),
		} {
			add(v)
			add(strings.ReplaceAll(v, "-", "_"))
			for _, piece := range strings.FieldsFunc(v, func(r rune) bool { return r == '-' || r == '.' }) {
				add(piece)
			}
		}
	}
	return out
}

// isGoIdent reports whether s is a valid Go identifier.
func isGoIdent(s string) bool {
	for i, r := range s {
		if !(r == '_' || unicode.IsLetter(r) || (i > 0 && unicode.IsDigit(r))) {
			return false
		}
	}
	return s != ""
}

func isMajorVersion(s string) bool {
	if len(s) < 2 || s[0] != 'v' {
		return false
	}
	for _, r := range s[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// typeDecl is one top-level type declaration. methodSetOpen is true
// when the type's method set can contain methods that are not
// declared on it directly anywhere in this repository: it embeds
// another type (promoted methods, possibly from another module), is an
// alias, or is defined from another named type (which may be an
// interface). For such a type, "method M isn't declared on T here"
// proves nothing.
type typeDecl struct {
	name          string
	methodSetOpen bool
}

// predeclaredNonInterface are predeclared type names with no methods;
// a type defined from one of them ("type Level int") has exactly the
// methods declared on it.
var predeclaredNonInterface = map[string]bool{
	"bool": true, "string": true, "byte": true, "rune": true, "uintptr": true,
	"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true,
	"float32": true, "float64": true, "complex64": true, "complex128": true,
}

func methodSetOpen(ts *ast.TypeSpec) bool {
	if ts.Assign.IsValid() { // alias: "type T = other.U"
		return true
	}
	switch t := ts.Type.(type) {
	case *ast.StructType:
		return hasEmbedded(t.Fields)
	case *ast.InterfaceType:
		return hasEmbedded(t.Methods)
	case *ast.ArrayType, *ast.MapType, *ast.FuncType, *ast.ChanType, *ast.StarExpr:
		return false
	case *ast.Ident:
		return !predeclaredNonInterface[t.Name]
	default: // another named type, qualified or generic: may be an interface or embed
		return true
	}
}

func hasEmbedded(fl *ast.FieldList) bool {
	if fl == nil {
		return false
	}
	for _, f := range fl.List {
		if len(f.Names) == 0 {
			return true
		}
	}
	return false
}

// scanIdentifiers adds every identifier token in content to into. It
// uses go/scanner, not go/parser, so it works on files that don't
// parse, and it skips comments and string literals: a name that only
// appears in a comment is not evidence a symbol exists. This is what
// grounding consults before calling a function claim false — a name
// that appears anywhere as an identifier (a field, a variable, a
// type, a call into another package) is a real symbol in or used by
// this codebase, just possibly not a function declared here.
func scanIdentifiers(content []byte, into map[string]struct{}) {
	fset := token.NewFileSet()
	f := fset.AddFile("", fset.Base(), len(content))
	var s scanner.Scanner
	s.Init(f, content, func(token.Position, string) {}, 0)
	for {
		_, tok, lit := s.Scan()
		if tok == token.EOF {
			return
		}
		if tok == token.IDENT {
			into[lit] = struct{}{}
		}
	}
}

func receiverTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return receiverTypeName(t.X)
	case *ast.IndexExpr: // generic receiver, one type param: func (t *Type[T]) M()
		return receiverTypeName(t.X)
	case *ast.IndexListExpr: // generic receiver, multiple type params: func (t *Type[T, U]) M()
		return receiverTypeName(t.X)
	case *ast.Ident:
		return t.Name
	default:
		return ""
	}
}

// splitFunctionClaim parses a claim value shaped "pkg.Func",
// "(*Type).Method", "(Type).Method", or a bare "Func" into a
// (receiver, name) pair. receiver is empty for a plain function or
// package-qualified function claim — "pkg.Func"'s "pkg" part is
// syntactically identical to a method claim's type name, so callers
// try both interpretations (see findDeclaration).
func splitFunctionClaim(value string) (receiver, name string) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "(") {
		closeParen := strings.IndexByte(value, ')')
		if closeParen < 0 {
			return "", value
		}
		recv := strings.TrimPrefix(value[1:closeParen], "*")
		rest := strings.TrimPrefix(value[closeParen+1:], ".")
		return recv, rest
	}
	idx := strings.LastIndexByte(value, '.')
	if idx < 0 {
		return "", value
	}
	return value[:idx], value[idx+1:]
}

// findDeclaration looks for a declaration matching value. A
// "(*Type).Method"/"(Type).Method" claim must match on both receiver
// and name. A "pkg.Func" claim matches a plain function by name, or a
// method whose receiver happens to equal "pkg" and whose name equals
// "Func", since without import resolution a package qualifier and a
// type name are syntactically indistinguishable. A bare "Func" claim
// names no receiver at all, so it matches a plain function first and
// otherwise a method of that name on any receiver (reports routinely
// write a method's bare name, e.g. "`AddMut`").
func findDeclaration(decls []declaration, value string) *declaration {
	if strings.HasPrefix(value, "(") {
		recv, name := splitFunctionClaim(value)
		for i := range decls {
			if decls[i].name == name && decls[i].receiver == recv {
				return &decls[i]
			}
		}
		return nil
	}
	recv, name := splitFunctionClaim(value)
	if recv == "" {
		var method *declaration
		for i := range decls {
			if decls[i].name != name {
				continue
			}
			if decls[i].receiver == "" {
				return &decls[i]
			}
			if method == nil {
				method = &decls[i]
			}
		}
		return method
	}
	for i := range decls {
		if decls[i].name != name {
			continue
		}
		if decls[i].receiver == recv || decls[i].receiver == "" {
			return &decls[i]
		}
	}
	return nil
}

// closestDeclaration returns the declaration whose name is closest to
// value's name part by edit distance, for a "not found, closest match"
// evidence string. Returns nil if decls is empty.
func closestDeclaration(decls []declaration, value string) *declaration {
	if len(decls) == 0 {
		return nil
	}
	_, target := splitFunctionClaim(value)
	var best *declaration
	bestDist := -1
	for i := range decls {
		d := levenshtein(target, decls[i].name)
		if bestDist < 0 || d < bestDist {
			bestDist = d
			best = &decls[i]
		}
	}
	return best
}

// levenshtein computes the edit distance between a and b.
func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	curr := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		curr[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			m := del
			if ins < m {
				m = ins
			}
			if sub < m {
				m = sub
			}
			curr[j] = m
		}
		prev, curr = curr, prev
	}
	return prev[len(rb)]
}
