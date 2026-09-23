# Remote panic in pion/interceptor from an RTP packet with a bogus padding length

pion/interceptor (v0.1.38, commit 791455129d4ef736c4009692e8ce108afe0fff14) trusts the RTP padding length byte when
copying packets for retransmission.

`(*PacketFactoryCopy).NewPacket` in `internal/rtpbuffer/packet_factory.go` strips
padding with `payload[:len(payload)-paddingLength]`, where `paddingLength` is the
last payload byte. A 3-byte payload ending in 200 gives
`slice bounds out of range [:-195]`.

Impact: any SFU or client using the NACK/RTX interceptors can be crashed by one
malicious RTP packet from a peer.

## Reproduce

Drop this test into `internal/rtpbuffer/` at commit `791455129d4ef736c4009692e8ce108afe0fff14` and run `go test -run TestPoC -count=1 .` from that directory. It fails (or panics) on the affected code and passes once the issue is fixed.

```go
package rtpbuffer

import (
	"testing"

	"github.com/pion/rtp"
)

// Input from the fix commit's rtpbuffer_test.go (TestRTPBuffer_Padding,
// "overflow padding"): a 3-byte payload whose padding length byte claims 200.
// Vulnerable: PacketFactoryCopy.NewPacket slices with a negative length and
// panics. Fixed: it returns an error.
func TestPoCPaddingOverflow(t *testing.T) {
	pm := NewPacketFactoryCopy()
	_, err := pm.NewPacket(&rtp.Header{SequenceNumber: 2, Padding: true}, []byte{0, 1, 200}, 1, 1)
	if err == nil {
		t.Fatal("expected an error for padding longer than the payload, got nil")
	}
}
```
