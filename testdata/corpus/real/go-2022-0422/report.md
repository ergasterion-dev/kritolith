# Panic in go-codec-dagpb DecodeBytes on a truncated Links entry

go-codec-dagpb (v1.3.0, commit fa6d623cbc0da39a4940da01d7506d05df80c7ad) panics when decoding a DAG-PB block whose
`Links` field declares more bytes than the block contains.

`DecodeBytes` in `unmarshal.go` reads the length prefix with
`protowire.ConsumeVarint` and then slices `remaining[:bytesLen]` without checking it
against `len(remaining)`: `slice bounds out of range [:11] with capacity 10`.

Impact: any IPFS/IPLD node that decodes dag-pb blocks received from peers can be
crashed with a 12-byte block.

## Reproduce

Drop this test into the repository root at commit `fa6d623cbc0da39a4940da01d7506d05df80c7ad` and run `go test -run TestPoC -count=1 .` from that directory. It fails (or panics) on the affected code and passes once the issue is fixed.

```go
package dagpb

import (
	"encoding/hex"
	"testing"
)

// Bytes from the fix commit's compat_test.go ("Links Hash some, short"): a Links
// entry whose declared length runs past the end of the block. Vulnerable:
// DecodeBytes slices past the buffer and panics. Fixed: it returns an error.
func TestPoCShortLinksBlock(t *testing.T) {
	src, err := hex.DecodeString("120b0a090155000500010203")
	if err != nil {
		t.Fatal(err)
	}
	if err := DecodeBytes(Type.PBNode.NewBuilder(), src); err == nil {
		t.Fatal("expected an error for a truncated Links block, got nil")
	}
}
```
