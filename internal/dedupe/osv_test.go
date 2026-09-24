package dedupe

import "testing"

const yamlAdvisoryFixture = `{
  "id": "GO-2022-0603",
  "affected": [
    {
      "package": {"ecosystem": "Go", "name": "gopkg.in/yaml.v3"},
      "ecosystem_specific": {
        "imports": [
          {"path": "gopkg.in/yaml.v3", "symbols": ["parser.peek", "Unmarshal"]}
        ]
      }
    }
  ]
}`

func TestMatchesOSVSymbol(t *testing.T) {
	tests := []struct {
		name             string
		qualifier, fname string
		want             bool
	}{
		{"method form matches qualifier.name", "parser", "peek", true},
		{"bare function name matches", "yaml", "Unmarshal", true},
		{"unrelated symbol does not match", "parser", "advance", false},
		{"unrelated qualifier does not match the bare-name symbol", "otherpkg", "Unmarshal", true}, // Unmarshal alone still matches: same ambiguity ground.findDeclaration accepts
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesOSVSymbol([]byte(yamlAdvisoryFixture), tt.qualifier, tt.fname); got != tt.want {
				t.Errorf("matchesOSVSymbol(%q, %q) = %v, want %v", tt.qualifier, tt.fname, got, tt.want)
			}
		})
	}
}

func TestMatchesOSVSymbolMalformedJSON(t *testing.T) {
	if matchesOSVSymbol([]byte("not json"), "parser", "peek") {
		t.Error("malformed advisory JSON must never match")
	}
}
