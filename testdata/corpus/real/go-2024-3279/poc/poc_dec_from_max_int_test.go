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
