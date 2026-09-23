# Out-of-bounds read / panic in go-cvss ParseVector for complete CVSS v2.0 vectors

go-cvss (v0.3.0, commit b57518b8ad20c04f25770524b69ce7ca3859914f) panics when `ParseVector` in `20/cvss20.go` parses a
full CVSS v2.0 vector (base + temporal + environmental metrics).

The parser walks the three metric groups (base, temporal, environmental) and, each
time a group is fully consumed, moves on with `currSlc = slcs[slci]`. After the last
environmental metric it does this one more time, indexing `slcs[3]` of a 3-element
slice: `panic: runtime error: index out of range [3] with length 3`.

Impact: any tool that parses CVSS v2.0 vectors from untrusted data (feeds, uploaded
reports) crashes on a valid, complete vector.

## Reproduce

Drop this test into `20/` at commit `b57518b8ad20c04f25770524b69ce7ca3859914f` and run `go test -run TestPoC -count=1 .` from that directory. It fails (or panics) on the affected code and passes once the issue is fixed.

```go
package gocvss20

import (
	"testing"
)

// Vector from the advisory's exploit example (GHSA-xhmf-mmv2-4hhx).
// Vulnerable: ParseVector panics with index out of range [3] with length 3.
// Fixed: the vector parses.
func TestPoCParseVectorFullVector(t *testing.T) {
	if _, err := ParseVector("AV:N/AC:L/Au:N/C:P/I:P/A:C/E:U/RL:OF/RC:C/CDP:MH/TD:H/CR:M/IR:M/AR:M"); err != nil {
		t.Fatalf("ParseVector: %v", err)
	}
}
```
