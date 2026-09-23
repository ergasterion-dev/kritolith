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
