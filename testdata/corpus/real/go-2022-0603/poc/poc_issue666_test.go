package yaml

import (
	"testing"
)

// Input from the fix commit's decode_test.go entry for issue #666.
// Vulnerable: Unmarshal panics. Fixed: it returns an error.
func TestPoCIssue666Panic(t *testing.T) {
	var v interface{}
	err := Unmarshal([]byte("0: [:!00 \xef"), &v)
	if err == nil {
		t.Fatal("expected an error for malformed input, got nil")
	}
}
