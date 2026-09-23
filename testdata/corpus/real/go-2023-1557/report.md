# Panic in go-unixfs HAMT construction on a bad shard width

go-unixfs (v0.4.2, commit 6609090f4bd166547fcaf5242055ede5c14f8f41) panics while building a HAMT shard whose width is
a power of two but not a valid bitfield size.

`NewHamtFromDag` in `hamt/hamt.go` takes the fanout from the DAG node (attacker
controlled when the node comes from the network) and hands it to `makeShard`, which
calls `newChilder`. `newChilder` calls `bitfield.NewBitfield(size)`, and go-bitfield
panics with `Bitfield size must be a multiple of 8` for widths such as 2. Huge widths
are not bounded either. `NewShard` takes the same path.

Impact: a malicious UnixFS directory block crashes any node or gateway that loads
it.

## Reproduce

Drop this test into `hamt/` at commit `6609090f4bd166547fcaf5242055ede5c14f8f41` and run `go test -run TestPoC -count=1 .` from that directory. It fails (or panics) on the affected code and passes once the issue is fixed.

```go
package hamt

import "testing"

// Sizes from the fix commit's hamt_test.go (TestHamtBadSize). A HAMT width
// comes from untrusted DAG data (the fanout field decoded by NewHamtFromDag),
// and NewShard shares the same makeShard/newChilder path. Vulnerable: widths
// that pass the power-of-two check but are not valid bitfield sizes (e.g. 2)
// panic inside newChilder. Fixed: every bad width is rejected with an error.
func TestPoCBadHamtWidth(t *testing.T) {
	for _, size := range []int{-8, 7, 2, 1337, 1024 + 8, -3} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("NewShard(nil, %d) panicked: %v", size, r)
				}
			}()
			if _, err := NewShard(nil, size); err == nil {
				t.Errorf("NewShard(nil, %d): expected an error, got nil", size)
			}
		}()
	}
}
```
