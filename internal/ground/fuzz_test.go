package ground

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// FuzzParseDeclarations feeds arbitrary bytes to the Go parser and
// scanner the way indexing a repository does. A file in the reported
// repository at the claimed commit is not trusted, so a malformed one
// must never panic or produce a declaration with an impossible
// position.
func FuzzParseDeclarations(f *testing.F) {
	for _, s := range []string{
		"",
		"package p\n\nfunc Foo() {}\n\nfunc (t *Type) Method() {}\n",
		"package p\nimport (\n\tj \"encoding/json\"\n\t\"gopkg.in/yaml.v3\"\n)\nfunc F() { j.Marshal(nil); yaml.Marshal(nil) }\n",
		"package p\ntype T[K comparable, V any] struct{ E }\nfunc (t *T[K, V]) Get(k K) V { var v V; return v }\n",
		"package p\ntype I interface{ M() }\ntype S struct{ I }\n",
		"package p\nfunc (", "package", "func F() {}", "package p\nimport \"\\xff\"\n",
		"package p\nfunc F() { x := `unterminated",
		"\x00\xff\xfe", strings.Repeat("(", 10000),
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		fs := parseDeclarations("f.go", content)
		lines := bytes.Count(content, []byte("\n")) + 1
		for _, d := range fs.decls {
			if d.name == "" || d.file != "f.go" {
				t.Fatalf("bad declaration %+v", d)
			}
			if d.line < 1 || d.endLine < d.line || d.endLine > lines {
				t.Fatalf("declaration %+v has lines outside 1..%d", d, lines)
			}
		}
		if fs.pkg == "" && (len(fs.decls) > 0 || len(fs.types) > 0) {
			t.Fatalf("declarations returned for a file with no package: %+v", fs)
		}
		idents := map[string]struct{}{}
		scanIdentifiers(content, idents)
		for name := range idents {
			if name == "" {
				t.Fatal("scanIdentifiers recorded an empty identifier")
			}
		}
	})
}

// FuzzFunctionClaim runs claim values, which come straight from report
// text or an LLM, through the lookups grounding performs on them.
func FuzzFunctionClaim(f *testing.F) {
	decls := []declaration{
		{name: "Foo", file: "a.go", line: 3, endLine: 5},
		{name: "ServeHTTP", receiver: "Server", file: "a.go", line: 7, endLine: 9},
		{name: "ServeHTTP", receiver: "Proxy", file: "b/b.go", line: 2, endLine: 4},
		{name: "parseHeaders", file: "c/frame.go", line: 412, endLine: 430},
	}
	for _, s := range []string{
		"Foo", "pkg.Foo", "(*Server).ServeHTTP", "(Proxy).ServeHTTP", "ServeHTTP",
		"parseHeader", "", ".", "(", "()", "(*).", "(*T", "a.b.c.d", " Foo ", "\xff.\xfe",
		strings.Repeat("x", 4096) + "." + strings.Repeat("y", 4096),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, value string) {
		splitFunctionClaim(value)
		SplitFunctionClaim(value)
		if d := findDeclaration(decls, value); d != nil && !containsDecl(decls, d) {
			t.Fatalf("findDeclaration(%q) returned a declaration not in the list", value)
		}
		if d, ambiguous := resolveUnique(decls, value); d != nil && ambiguous && !containsDecl(decls, d) {
			t.Fatalf("resolveUnique(%q) returned a declaration not in the list", value)
		}
		if closestDeclaration(decls, value) == nil {
			t.Fatalf("closestDeclaration(%q) = nil with declarations present", value)
		}
		if closestDeclaration(nil, value) != nil {
			t.Fatalf("closestDeclaration(%q) != nil with no declarations", value)
		}
	})
}

func containsDecl(decls []declaration, d *declaration) bool {
	for i := range decls {
		if &decls[i] == d {
			return true
		}
	}
	return false
}

// FuzzValidateClaimPath checks that an accepted path stays inside the
// repository tree: relative, with no "." or ".." component.
func FuzzValidateClaimPath(f *testing.F) {
	for _, s := range []string{
		"a.go", "internal/hpack/decode.go", "a/../../../etc/passwd", "/etc/passwd",
		"./a.go", "a/./b.go", "..", "", "a//b.go", "-rf", "a\nb.go", "a/..b/c.go",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, path string) {
		if ValidateClaimPath(path) != nil {
			return
		}
		if path == "" || strings.HasPrefix(path, "/") {
			t.Fatalf("accepted path %q", path)
		}
		for _, part := range strings.Split(path, "/") {
			if part == "." || part == ".." {
				t.Fatalf("accepted path %q with component %q", path, part)
			}
		}
	})
}

// FuzzReadBatch feeds arbitrary bytes to the `git cat-file --batch`
// output parser. Whatever git prints, the parser must answer for the
// paths strictly in order, never hand back more than maxReadBytes for
// one file, and either answer every path or return an error — an
// unanswered path with a nil error would let a file that was never
// read count as scanned.
func FuzzReadBatch(f *testing.F) {
	const oid = "e1fcd82abba34df74614020343be8eb1fe85f0d9"
	for _, s := range []string{
		"",
		oid + " blob 5\nhello\n" + oid + " blob 0\n\n",
		oid + ":a.go missing\n" + oid + " tree 3\nabc\n",
		oid + " blob 5\nhel",
		oid + " blob -1\n",
		oid + " blob 9223372036854775807\nx\n",
		oid + " blob 99999999999999999999\n",
		"not-an-oid blob 1\nx\n",
		oid + " blob\n",
		" missing\n missing\n",
	} {
		f.Add([]byte(s), uint8(2))
	}
	f.Fuzz(func(t *testing.T, data []byte, n uint8) {
		count := int(n%8) + 1
		paths := make([]string, count)
		askable := make([]bool, count)
		for i := range paths {
			paths[i] = fmt.Sprintf("f%d.go", i)
			askable[i] = i%4 != 3 // exercise the not-askable branch too
		}
		next := 0
		err := readBatch(bufio.NewReader(bytes.NewReader(data)), paths, askable, func(path string, content []byte, ok bool) {
			if next >= count || path != paths[next] {
				t.Fatalf("callback for %q out of order (call %d)", path, next)
			}
			if !askable[next] && ok {
				t.Fatalf("a path git was never asked about read as ok: %q", path)
			}
			if !ok && content != nil {
				t.Fatalf("content returned with ok=false for %q", path)
			}
			if int64(len(content)) > maxReadBytes {
				t.Fatalf("%d bytes returned for %q; cap is %d", len(content), path, maxReadBytes)
			}
			next++
		})
		if err == nil && next != count {
			t.Fatalf("nil error but only %d of %d paths answered", next, count)
		}
	})
}
