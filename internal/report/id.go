package report

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewID returns a ULID: 48-bit millisecond timestamp plus 80 bits read
// from r, encoded as 26 Crockford base32 characters. IDs sort by time.
func NewID(t time.Time, r io.Reader) (string, error) {
	ms := uint64(t.UnixMilli())
	if ms>>48 != 0 {
		return "", errors.New("report: timestamp out of ULID range")
	}
	var b [16]byte
	b[0], b[1], b[2] = byte(ms>>40), byte(ms>>32), byte(ms>>24)
	b[3], b[4], b[5] = byte(ms>>16), byte(ms>>8), byte(ms)
	if _, err := io.ReadFull(r, b[6:]); err != nil {
		return "", fmt.Errorf("report: read id randomness: %w", err)
	}
	var out [26]byte
	hi, lo := binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])
	for i := 25; i >= 0; i-- {
		out[i] = crockford[lo&0x1f]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return string(out[:]), nil
}
