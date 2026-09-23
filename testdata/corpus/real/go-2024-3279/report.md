# Panic in cosmossdk.io/math when a max-size Int is used as a LegacyDec

cosmossdk.io/math (v1.3.0 line, cosmos-sdk commit 1effb80c8b789c7b3aa7eee587182c6998426f38) has mismatched size limits
for `Int` and `LegacyDec`.

`Int` allows values up to 256 bits (`MaxBitLen` in `math/int.go`), but `LegacyDec`
arithmetic in `math/dec.go` (`AddMut`, `SubMut`, `MulMut`, `QuoMut`, ...) panics with
`Int overflow` as soon as the scaled 18-decimal value is longer than 315 bits. A
valid Int near the top of its range converted with `LegacyNewDecFromInt` is therefore
already "too big": even adding zero to it panics.

Impact: a chain (or module such as IBC-Go / tokenfactory) that mixes Int amounts with
Dec math can be halted by a transaction that pushes an amount near 2^256.

## Reproduce

Drop this test into `math/` at commit `1effb80c8b789c7b3aa7eee587182c6998426f38` and run `go test -run TestPoC -count=1 .` from that directory. It fails (or panics) on the affected code and passes once the issue is fixed.

```go
package math

import (
	"math/big"
	"testing"
)

// Adapted from the fix commit's dec_test.go (TestDecOpsWithinLimits, "max Int"):
// the largest valid Int (2^256-1) converted to a LegacyDec. Vulnerable: Int
// allows 256 bits but LegacyDec arithmetic caps at 315 bits of the scaled value,
// so a no-op AddMut panics with "Int overflow". Fixed: the value is in range.
func TestPoCDecFromMaxInt(t *testing.T) {
	max := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil), big.NewInt(1))
	d := LegacyNewDecFromInt(NewIntFromBigInt(max))
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("AddMut(0) on a Dec built from the max Int panicked: %v", r)
		}
	}()
	d.AddMut(LegacyZeroDec())
}
```
