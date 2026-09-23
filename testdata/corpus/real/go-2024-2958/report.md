# Memory exhaustion in gorilla/schema from a single large slice index

gorilla/schema (v1.4.0, commit 180f71e625073e210314dc8ca83dfbbbd0096dfe) allocates slices sized by attacker input when
decoding nested-slice form keys.

In `(*Decoder).decode` in `decoder.go`, for a path like `Items.N.V` the decoder calls
`reflect.MakeSlice(t, idx+1, idx+1)` where `idx` is parsed straight from the key.
There is no upper bound, so one form field such as `Items.100000000.V=1` makes the
server allocate a hundred million zero-value structs. `NewDecoder` offers no way to
cap it.

Impact: any HTTP handler that decodes `r.PostForm` / query values into a struct with
a slice-of-struct field can be pushed out of memory with one small request.

## Reproduce

Drop this test into the repository root at commit `180f71e625073e210314dc8ca83dfbbbd0096dfe` and run `go test -run TestPoC -count=1 .` from that directory. It fails (or panics) on the affected code and passes once the issue is fixed.

```go
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
```
