# Stack exhaustion in helm strvals parser from deeply nested --set keys

Helm (v3.10.2 line, commit 638ebffbc2e445156f3978f02fd83d9af1e56f5b) parses `--set` style strings with a recursive
descent parser that has no depth limit.

`(*parser).key` in `pkg/strvals/parser.go` recurses once per `.` in a key, and
`Parse` accepts keys of any depth. A key like `a.a.a....=1` with hundreds of
thousands of segments exhausts the goroutine stack and the Go runtime aborts the
whole process (`fatal error: stack overflow`, not recoverable).

Impact: any program that feeds user input into `strvals.Parse` / `ParseInto` (Helm
SDK users, CI systems, chart UIs) can be crashed.

## Reproduce

Drop this test into `pkg/strvals/` at commit `638ebffbc2e445156f3978f02fd83d9af1e56f5b` and run `go test -run TestPoC -count=1 .` from that directory. It fails (or panics) on the affected code and passes once the issue is fixed.

```go
package strvals

import (
	"fmt"
	"strings"
	"testing"
)

// Adapted from the fix commit's parser_test.go (TestParseSetNestedLevels): a
// --set key with more nesting levels than the fix's limit of 30. Vulnerable:
// Parse accepts arbitrarily deep keys (each level recurses in parser.key, so a
// long enough key exhausts the stack). Fixed: Parse rejects the key.
func TestPoCParseDeeplyNestedKey(t *testing.T) {
	parts := make([]string, 32)
	for i := range parts {
		parts[i] = fmt.Sprintf("name%d", i+1)
	}
	if _, err := Parse(strings.Join(parts, ".") + "=value"); err == nil {
		t.Fatal("expected an error for a 32-level nested key, got nil")
	}
}
```
