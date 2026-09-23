// Package ground checks extracted claims against the actual code at
// the reporter's claimed commit, using git (shelled out to) and
// go/parser only. Function and method grounding is a syntax-level
// search, not import-aware or type-checked: it never claims "package"
// identity it didn't verify.
package ground

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
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

// parseDeclarations parses one Go source file's content and returns
// every top-level function and method declaration in it. A file that
// fails to parse contributes no declarations rather than failing the
// whole search: build-tag-gated syntax this parser can't handle, or a
// hostile/malformed file, must never abort grounding.
func parseDeclarations(file string, content []byte) []declaration {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, content, 0)
	if err != nil {
		return nil
	}
	var out []declaration
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		decl := declaration{
			name:    fn.Name.Name,
			file:    file,
			line:    fset.Position(fn.Pos()).Line,
			endLine: fset.Position(fn.End()).Line,
		}
		if fn.Recv != nil && len(fn.Recv.List) > 0 {
			decl.receiver = receiverTypeName(fn.Recv.List[0].Type)
		}
		out = append(out, decl)
	}
	return out
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
// and name. A "pkg.Func" or bare "Func" claim matches a plain function
// by name; "pkg.Func" additionally matches a method whose receiver
// happens to equal "pkg" and whose name equals "Func", since without
// import resolution a package qualifier and a type name are
// syntactically indistinguishable.
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
		for i := range decls {
			if decls[i].name == name && decls[i].receiver == "" {
				return &decls[i]
			}
		}
		return nil
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
