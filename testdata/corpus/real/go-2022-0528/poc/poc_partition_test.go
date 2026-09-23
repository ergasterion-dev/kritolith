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
