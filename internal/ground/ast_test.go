package ground

import "testing"

func TestParseDeclarationsFunctionAndMethod(t *testing.T) {
	src := []byte(`package p

func Foo() {}

func (t *Type) Method() {}

func (v Value) OtherMethod() {}
`)
	decls := parseDeclarations("p.go", src).decls
	if len(decls) != 3 {
		t.Fatalf("decls = %+v, want 3", decls)
	}
	want := map[string]string{"Foo": "", "Method": "Type", "OtherMethod": "Value"}
	got := map[string]string{}
	for _, d := range decls {
		got[d.name] = d.receiver
	}
	for name, recv := range want {
		if v, ok := got[name]; !ok || v != recv {
			t.Errorf("decl %q receiver = %q (present=%v), want %q", name, v, ok, recv)
		}
	}
}

func TestParseDeclarationsPositions(t *testing.T) {
	src := []byte("package p\n\nfunc Foo() {\n\treturn\n}\n")
	decls := parseDeclarations("p.go", src).decls
	if len(decls) != 1 {
		t.Fatalf("decls = %+v, want 1", decls)
	}
	if decls[0].line != 3 || decls[0].endLine != 5 {
		t.Errorf("decl = %+v, want line 3, endLine 5", decls[0])
	}
}

func TestParseDeclarationsInvalidSyntaxIsNotFatal(t *testing.T) {
	decls := parseDeclarations("bad.go", []byte("this is not go code {{{")).decls
	if decls != nil {
		t.Errorf("decls = %+v, want nil for unparseable input", decls)
	}
}

func TestParseDeclarationsGenericReceiver(t *testing.T) {
	src := []byte(`package p

type Type[T any] struct{}

func (t *Type[T]) Method() {}

func (t Type[T, U]) Other() {}
`)
	decls := parseDeclarations("p.go", src).decls
	if len(decls) != 2 {
		t.Fatalf("decls = %+v, want 2", decls)
	}
	for _, d := range decls {
		if d.receiver != "Type" {
			t.Errorf("decl %q receiver = %q, want %q (generic receivers must still resolve their base type name)", d.name, d.receiver, "Type")
		}
	}
}

func TestSplitFunctionClaim(t *testing.T) {
	tests := []struct {
		value        string
		wantReceiver string
		wantName     string
	}{
		{"Foo", "", "Foo"},
		{"pkg.Foo", "pkg", "Foo"},
		{"(*Type).Method", "Type", "Method"},
		{"(Type).Method", "Type", "Method"},
	}
	for _, tt := range tests {
		recv, name := splitFunctionClaim(tt.value)
		if recv != tt.wantReceiver || name != tt.wantName {
			t.Errorf("splitFunctionClaim(%q) = %q, %q, want %q, %q", tt.value, recv, name, tt.wantReceiver, tt.wantName)
		}
	}
}

func TestFindDeclarationPlainFunction(t *testing.T) {
	decls := []declaration{{name: "Foo", file: "p.go", line: 3}}
	if d := findDeclaration(decls, "pkg.Foo"); d == nil || d.name != "Foo" {
		t.Errorf("findDeclaration(pkg.Foo) = %v, want a match on Foo", d)
	}
	if d := findDeclaration(decls, "Foo"); d == nil {
		t.Errorf("findDeclaration(Foo) = nil, want a match")
	}
	if d := findDeclaration(decls, "pkg.Bar"); d != nil {
		t.Errorf("findDeclaration(pkg.Bar) = %v, want nil", d)
	}
}

func TestFindDeclarationMethod(t *testing.T) {
	decls := []declaration{{name: "Method", receiver: "Type", file: "p.go", line: 5}}
	if d := findDeclaration(decls, "(*Type).Method"); d == nil {
		t.Errorf("findDeclaration((*Type).Method) = nil, want a match")
	}
	if d := findDeclaration(decls, "Type.Method"); d == nil {
		t.Errorf("findDeclaration(Type.Method) = nil, want a match")
	}
	if d := findDeclaration(decls, "(*Other).Method"); d != nil {
		t.Errorf("findDeclaration((*Other).Method) = %v, want nil (wrong receiver)", d)
	}
}

func TestClosestDeclaration(t *testing.T) {
	decls := []declaration{
		{name: "parseHeaders", file: "frame.go", line: 412},
		{name: "unrelated", file: "other.go", line: 1},
	}
	got := closestDeclaration(decls, "http2.parseHeader")
	if got == nil || got.name != "parseHeaders" {
		t.Errorf("closestDeclaration = %v, want parseHeaders", got)
	}
}

func TestClosestDeclarationEmpty(t *testing.T) {
	if got := closestDeclaration(nil, "anything"); got != nil {
		t.Errorf("closestDeclaration(nil, ...) = %v, want nil", got)
	}
}

func TestLevenshtein(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "abc", 0},
		{"abc", "", 3},
		{"parseHeader", "parseHeaders", 1},
		{"kitten", "sitting", 3},
	}
	for _, tt := range tests {
		if got := levenshtein(tt.a, tt.b); got != tt.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestFindDeclarationBareNameMatchesMethod(t *testing.T) {
	// go-2024-3279 cites "`AddMut`", a method on LegacyDec, by its bare
	// name.
	decls := []declaration{{name: "AddMut", receiver: "LegacyDec", file: "math/dec.go", line: 275}}
	if d := findDeclaration(decls, "AddMut"); d == nil {
		t.Error("findDeclaration(AddMut) = nil, want the method on LegacyDec")
	}
	// A plain function of the same name still wins over a method.
	decls = append(decls, declaration{name: "AddMut", file: "plain.go", line: 1})
	if d := findDeclaration(decls, "AddMut"); d == nil || d.receiver != "" {
		t.Errorf("findDeclaration(AddMut) = %+v, want the plain function", d)
	}
}

func TestParseDeclarationsPackageImportsAndTypes(t *testing.T) {
	src := []byte(`package widgets

import (
	"strings"
	yaml "gopkg.in/yaml.v3"
	"example.com/mod/v2"
	_ "embed"
)

type Closed struct{ a int }
type Embeds struct{ Closed }
type Alias = strings.Builder
type Level int
type Named Closed
type Iface interface{ Close() error }
type IfaceEmbeds interface{ Iface }
type Fn func()
`)
	fs := parseDeclarations("w.go", src)
	if fs.pkg != "widgets" {
		t.Errorf("pkg = %q, want widgets", fs.pkg)
	}
	wantImports := map[string]string{"strings": "strings", "yaml": "gopkg.in/yaml.v3", "mod": "example.com/mod/v2", "_": "embed"}
	if len(fs.imports) != len(wantImports) {
		t.Fatalf("imports = %+v, want %d", fs.imports, len(wantImports))
	}
	for _, im := range fs.imports {
		if wantImports[im.name] != im.path {
			t.Errorf("import %q -> %q, want %q", im.name, im.path, wantImports[im.name])
		}
	}
	wantOpen := map[string]bool{
		"Closed": false, "Embeds": true, "Alias": true, "Level": false,
		"Named": true, "Iface": false, "IfaceEmbeds": true, "Fn": false,
	}
	if len(fs.types) != len(wantOpen) {
		t.Fatalf("types = %+v, want %d", fs.types, len(wantOpen))
	}
	for _, td := range fs.types {
		if want, ok := wantOpen[td.name]; !ok || td.methodSetOpen != want {
			t.Errorf("type %s methodSetOpen = %v, want %v", td.name, td.methodSetOpen, want)
		}
	}
}

func TestImportName(t *testing.T) {
	tests := map[string]string{
		"strings": "strings",
		"google.golang.org/protobuf/encoding/protowire": "protowire",
		"github.com/golang-jwt/jwt/v5":                  "jwt",
		"gopkg.in/yaml.v3":                              "yaml",
		"github.com/foo/go-bar":                         "go_bar",
	}
	for path, want := range tests {
		if got := importName(path); got != want {
			t.Errorf("importName(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestScanIdentifiers(t *testing.T) {
	src := []byte(`package p

// onlyInComment is mentioned here but never used.
var s = "onlyInString"

func f() {
	paddingLength := 3
	_ = protowire.ConsumeVarint
	_ = types.MessageLimit{ChunkSize: paddingLength}
}
`)
	got := map[string]struct{}{}
	scanIdentifiers(src, got)
	for _, want := range []string{"paddingLength", "protowire", "ConsumeVarint", "ChunkSize", "MessageLimit", "f"} {
		if _, ok := got[want]; !ok {
			t.Errorf("identifier %q not collected", want)
		}
	}
	for _, not := range []string{"onlyInComment", "onlyInString"} {
		if _, ok := got[not]; ok {
			t.Errorf("identifier %q collected from a comment or string, want skipped", not)
		}
	}
}

func TestScanIdentifiersToleratesUnparseableInput(t *testing.T) {
	got := map[string]struct{}{}
	scanIdentifiers([]byte("func broken( {{{ declaredInBrokenFile @@@ \x00"), got)
	if _, ok := got["declaredInBrokenFile"]; !ok {
		t.Errorf("identifiers = %v, want declaredInBrokenFile collected despite syntax errors", got)
	}
}
