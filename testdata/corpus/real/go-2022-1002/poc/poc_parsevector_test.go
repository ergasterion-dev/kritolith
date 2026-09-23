package gocvss20

import (
	"testing"
)

// Vector from the advisory's exploit example (GHSA-xhmf-mmv2-4hhx).
// Vulnerable: ParseVector panics with index out of range [3] with length 3.
// Fixed: the vector parses.
func TestPoCParseVectorFullVector(t *testing.T) {
	if _, err := ParseVector("AV:N/AC:L/Au:N/C:P/I:P/A:C/E:U/RL:OF/RC:C/CDP:MH/TD:H/CR:M/IR:M/AR:M"); err != nil {
		t.Fatalf("ParseVector: %v", err)
	}
}
