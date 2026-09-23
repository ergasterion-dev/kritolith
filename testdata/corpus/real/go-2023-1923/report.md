# Panic in proxyprotocol parseV2 on a truncated PROXY v2 header

mastercactapus/proxyprotocol (v0.0.1, commit 18c1c8921ff9d2ce18c7c47de59ae03f1c4dfeec) panics on a PROXY protocol v2
header whose declared length is shorter than the address family needs.

`parseV2` in `headerv2.go` trusts the 16-bit length field: for TCP over IPv4 with
length 0 it cuts the buffer to the 16-byte fixed header and then still reads the
addresses and ports from it (`buf[24:]` for the source port), giving
`slice bounds out of range [24:16]`. `Parse` in `parse.go` reaches
it for any connection that starts with the v2 signature.

Impact: an unauthenticated client can crash a server (for example the Caddy
proxyprotocol plugin) with a 16-byte request.

## Reproduce

Drop this test into the repository root at commit `18c1c8921ff9d2ce18c7c47de59ae03f1c4dfeec` and run `go test -run TestPoC -count=1 .` from that directory. It fails (or panics) on the affected code and passes once the issue is fixed.

```go
package proxyprotocol

import (
	"bufio"
	"bytes"
	"testing"
)

// Input from the fix commit's parse_test.go (TestParse_Malformed).
// Vulnerable: Parse panics on a v2 header whose address block is missing.
// Fixed: Parse returns an error.
func TestPoCTruncatedV2Header(t *testing.T) {
	data := []byte{
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, // v2 signature
		0x21,       // version 2, PROXY command
		0x12,       // TCP over IPv4
		0x00, 0x00, // length 0: address data omitted
	}
	if _, err := Parse(bufio.NewReader(bytes.NewReader(data))); err == nil {
		t.Fatal("expected an error for a truncated header, got nil")
	}
}
```
