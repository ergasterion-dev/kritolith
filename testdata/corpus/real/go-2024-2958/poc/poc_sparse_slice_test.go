package schema

import "testing"

// Adapted from the fix commit's decoder_test.go (TestDecoder_MaxSize): a
// nested-slice path with a huge index. Vulnerable: Decoder.decode allocates a
// slice of index+1 elements (here 10,000,001) from one form key. Fixed: indexes
// above the default MaxSize (16000) are rejected.
func TestPoCSparseSliceIndex(t *testing.T) {
	type Item struct{ V int }
	type Form struct{ Items []Item }
	var dst Form
	err := NewDecoder().Decode(&dst, map[string][]string{"Items.10000000.V": {"1"}})
	if err == nil {
		t.Fatalf("expected an error for index 10000000, got nil (len=%d)", len(dst.Items))
	}
}
