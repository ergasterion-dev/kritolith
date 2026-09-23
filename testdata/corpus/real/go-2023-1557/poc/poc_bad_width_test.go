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
