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
