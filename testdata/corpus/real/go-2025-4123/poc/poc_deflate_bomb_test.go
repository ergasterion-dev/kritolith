package jose

import (
	"strings"
	"testing"
)

// Adapted from the fix commit's sec_test/security_vulnerabilities_test.go
// (Test_DeflateBomb), scaled down and using a direct symmetric key instead of
// the test RSA pair. A 64 MiB payload compresses to about 64 KiB. Vulnerable:
// decrypt calls Deflate.Decompress, which inflates the whole payload with no
// size limit. Fixed: decompression stops at 250 KiB with ErrSizeExceeded.
func TestPoCDeflateBomb(t *testing.T) {
	key := make([]byte, 16)
	token, err := Encrypt(strings.Repeat("U", 64<<20), DIR, A128GCM, key, Zip(DEF))
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := Decode(token, key)
	if err == nil {
		t.Fatalf("expected a size-limit error, got nil and a %d byte payload from a %d byte token", len(payload), len(token))
	}
}
