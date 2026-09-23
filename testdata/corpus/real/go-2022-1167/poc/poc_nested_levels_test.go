package strvals

import (
	"fmt"
	"strings"
	"testing"
)

// Adapted from the fix commit's parser_test.go (TestParseSetNestedLevels): a
// --set key with more nesting levels than the fix's limit of 30. Vulnerable:
// Parse accepts arbitrarily deep keys (each level recurses in parser.key, so a
// long enough key exhausts the stack). Fixed: Parse rejects the key.
func TestPoCParseDeeplyNestedKey(t *testing.T) {
	parts := make([]string, 32)
	for i := range parts {
		parts[i] = fmt.Sprintf("name%d", i+1)
	}
	if _, err := Parse(strings.Join(parts, ".") + "=value"); err == nil {
		t.Fatal("expected an error for a 32-level nested key, got nil")
	}
}
