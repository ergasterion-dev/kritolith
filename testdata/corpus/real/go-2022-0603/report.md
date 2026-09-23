# Panic in yaml.v3 Unmarshal on malformed input

gopkg.in/yaml.v3 (commit 539c8e751b99281a79dc659ba8dc44d91e444723) panics when `Unmarshal` is fed a short malformed
document that ends in an incomplete UTF-8 sequence.

`(*parser).peek` in `decode.go` only checks the boolean result of
`yaml_parser_parse`. For this input the C-derived parser reports success but leaves
`p.parser.error` set, so `peek` returns an event of type none and the decoder panics
with `internal error: attempted to parse unknown event (please report): none`.

Impact: any program that decodes untrusted YAML with yaml.v3 can be crashed with a
10-byte payload (`Unmarshal` does not recover this panic).

## Reproduce

Drop this test into the repository root at commit `539c8e751b99281a79dc659ba8dc44d91e444723` and run `go test -run TestPoC -count=1 .` from that directory. It fails (or panics) on the affected code and passes once the issue is fixed.

```go
package yaml

import (
	"testing"
)

// Input from the fix commit's decode_test.go entry for issue #666.
// Vulnerable: Unmarshal panics. Fixed: it returns an error.
func TestPoCIssue666Panic(t *testing.T) {
	var v interface{}
	err := Unmarshal([]byte("0: [:!00 \xef"), &v)
	if err == nil {
		t.Fatal("expected an error for malformed input, got nil")
	}
}
```
