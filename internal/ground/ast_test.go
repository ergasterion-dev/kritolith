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
		if !contains(im.names, wantImportName(wantImports, im.path)) {
			t.Errorf("import %q names = %v, want them to include its binding", im.path, im.names)
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

func wantImportName(want map[string]string, path string) string {
	for name, p := range want {
		if p == path {
			return name
		}
	}
	return ""
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestImportNameCandidates(t *testing.T) {
	tests := map[string]string{
		"strings": "strings",
		"google.golang.org/protobuf/encoding/protowire": "protowire",
		"github.com/golang-jwt/jwt/v5":                  "jwt",
		"gopkg.in/yaml.v3":                              "yaml",
		"github.com/foo/go-yaml":                        "yaml", // reviewer probe: real package name is yaml
		"github.com/foo/yaml-go":                        "yaml",
		"github.com/foo/yaml.go":                        "yaml",
		"github.com/foo/go-bar":                         "go_bar",
		"github.com/mattn/go-sqlite3":                   "sqlite3",
	}
	for path, want := range tests {
		if got := importNameCandidates(path); !contains(got, want) {
			t.Errorf("importNameCandidates(%q) = %v, want it to include %q", path, got, want)
		}
	}
}

func TestParseDeclarationsUnboundQualifiers(t *testing.T) {
	src := []byte(`package p

import (
	"github.com/foo/go-yaml"
	j "encoding/json"
	"strings"
)

func f(parser *P) {
	_ = yaml.Marshal
	_ = j.Marshal
	_ = strings.ToLower
	_ = parser.error
}
`)
	fs := parseDeclarations("p.go", src)
	got := map[string]bool{}
	for _, q := range fs.unboundQualifiers {
		got[q] = true
	}
	for _, want := range []string{"yaml", "parser"} {
		if !got[want] {
			t.Errorf("unboundQualifiers = %v, want %q (no import certainly binds it)", fs.unboundQualifiers, want)
		}
	}
	for _, not := range []string{"j", "strings"} {
		if got[not] {
			t.Errorf("unboundQualifiers = %v, don't want %q (an import binds it exactly)", fs.unboundQualifiers, not)
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

func TestResolveUniqueSingleMatch(t *testing.T) {
	decls := []declaration{{name: "peek", receiver: "parser", file: "decode.go", line: 10}}
	d, ambiguous := resolveUnique(decls, "(*parser).peek")
	if d == nil || d.name != "peek" {
		t.Fatalf("resolveUnique = %v, %v, want a match on peek", d, ambiguous)
	}
	if ambiguous {
		t.Error("a single matching declaration must not be ambiguous")
	}
}

func TestResolveUniqueAmbiguousAcrossPackages(t *testing.T) {
	// Two different packages each declare a type T with a method M — the
	// exact G1 same-named-type collision. A claim naming "T.M" resolves
	// to *a* declaration (findDeclaration's existing behavior, unchanged)
	// but must now be reported ambiguous: grounding can't be sure which
	// T the reporter meant.
	decls := []declaration{
		{name: "M", receiver: "T", file: "pkg1/a.go", line: 5},
		{name: "M", receiver: "T", file: "pkg2/b.go", line: 9},
	}
	d, ambiguous := resolveUnique(decls, "(*T).M")
	if d == nil {
		t.Fatal("resolveUnique = nil, want a match (findDeclaration still finds one)")
	}
	if !ambiguous {
		t.Error("two declarations sharing (name, receiver) must be reported ambiguous")
	}
}

func TestResolveUniqueAmbiguousSamePackage(t *testing.T) {
	// Two files in the same directory both declaring a plain function
	// named Foo (e.g. GOOS-tagged variants this per-file scan can't tell
	// are mutually exclusive) must also be ambiguous — the rule is
	// "shared anywhere in the repo", not "shared across directories".
	decls := []declaration{
		{name: "Foo", file: "pkg/a_linux.go", line: 3},
		{name: "Foo", file: "pkg/a_darwin.go", line: 3},
	}
	d, ambiguous := resolveUnique(decls, "Foo")
	if d == nil {
		t.Fatal("resolveUnique = nil, want a match")
	}
	if !ambiguous {
		t.Error("two declarations with the same (name, receiver) in the same directory must still be ambiguous")
	}
}

func TestResolveUniqueNoMatch(t *testing.T) {
	d, ambiguous := resolveUnique(nil, "pkg.Func")
	if d != nil || ambiguous {
		t.Errorf("resolveUnique(nil, ...) = %v, %v, want nil, false", d, ambiguous)
	}
}

func TestResolveUniqueBareNameUniquelyResolved(t *testing.T) {
	// fab-017's exact scenario: a bare name with no written qualifier at
	// all, but only one declaration in the whole repo has that name —
	// it must resolve unambiguously.
	decls := []declaration{
		{name: "isOriginAllowed", file: "rest/internal/cors/handlers.go", line: 40},
	}
	d, ambiguous := resolveUnique(decls, "isOriginAllowed")
	if d == nil || ambiguous {
		t.Errorf("resolveUnique = %v, %v, want a unique match", d, ambiguous)
	}
}

func TestResolveUniqueBareNameAmbiguousAcrossReceivers(t *testing.T) {
	// A bare method name declared on three different receivers, with no
	// plain function of that name anywhere. findDeclaration's bare-name
	// branch returns the first method in slice order as a guess — but
	// every one of these three declarations is a plausible candidate for
	// what the claim means, so resolveUnique must report ambiguous. The
	// old (narrower) implementation only compared against the single
	// (name, receiver) pair findDeclaration happened to resolve to
	// (here, ("ServeHTTP", "Router")) and incorrectly reported false.
	decls := []declaration{
		{name: "ServeHTTP", receiver: "Router", file: "router.go", line: 10},
		{name: "ServeHTTP", receiver: "Static", file: "static.go", line: 20},
		{name: "ServeHTTP", receiver: "Proxy", file: "proxy.go", line: 30},
	}
	d, ambiguous := resolveUnique(decls, "ServeHTTP")
	if d == nil {
		t.Fatal("resolveUnique = nil, want a match (findDeclaration still finds one)")
	}
	if !ambiguous {
		t.Error("a bare name matching methods on three different receivers must be reported ambiguous")
	}
}

func TestResolveUniqueQualifiedAmbiguousFunctionOrMethod(t *testing.T) {
	// "pkg.Func" is syntactically indistinguishable from "(Type).Method"
	// with Type == "pkg" — findDeclaration matches either a plain
	// function named Func, or a method named Func with receiver == pkg.
	// When both exist, the claim is genuinely ambiguous about which one
	// the reporter meant, even though findDeclaration itself picks one.
	decls := []declaration{
		{name: "Func", file: "yaml.go", line: 5},                           // plain function
		{name: "Func", receiver: "yaml", file: "yaml/decode.go", line: 15}, // method on type "yaml"
	}
	d, ambiguous := resolveUnique(decls, "yaml.Func")
	if d == nil {
		t.Fatal("resolveUnique = nil, want a match (findDeclaration still finds one)")
	}
	if !ambiguous {
		t.Error("a pkg.Func claim matching both a plain function and a method with receiver==pkg must be reported ambiguous")
	}
}
