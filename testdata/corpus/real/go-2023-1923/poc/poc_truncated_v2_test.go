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
