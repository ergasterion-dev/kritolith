# Panic in shoutrrr PartitionMessage for messages of exactly 2000/4000/6000 characters

shoutrrr (v0.5.3 line, commit 2c9378b69b079db2bbad29d383b54a7919434472) panics when a message length is an exact
multiple of the chunk size.

`PartitionMessage` in `pkg/util/partition_message.go` sets `chunkEnd = chunkOffset +
ChunkSize` and then indexes `runes[chunkEnd]` while looking for a split point, which
is one past the end when the message is exactly `ChunkSize` runes long:
`index out of range [2000] with length 2000`. The Discord service uses limits of
2000/6000/10.

Impact: anything that forwards user-controlled text to a notification URL (for
example Watchtower sending container logs) crashes on a message of the wrong size.

## Reproduce

Drop this test into `pkg/util/` at commit `2c9378b69b079db2bbad29d383b54a7919434472` and run `go test -run TestPoC -count=1 .` from that directory. It fails (or panics) on the affected code and passes once the issue is fixed.

```go
package util

import (
	"strings"
	"testing"

	"github.com/containrrr/shoutrrr/pkg/types"
)

// Sizes from issue #240: messages of exactly 2000, 4000 or 6000 runes with the
// Discord limits. Vulnerable: PartitionMessage panics (index out of range).
// Fixed: it returns chunks.
func TestPoCPartitionMessageExactChunkSize(t *testing.T) {
	limits := types.MessageLimit{ChunkSize: 2000, TotalChunkSize: 6000, ChunkCount: 10}
	for _, n := range []int{2000, 4000, 6000} {
		items, _ := PartitionMessage(strings.Repeat("x", n), limits, 100)
		if len(items) == 0 {
			t.Fatalf("no items for a %d rune message", n)
		}
	}
}
```
