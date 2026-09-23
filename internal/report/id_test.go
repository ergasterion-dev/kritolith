package report

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestNewIDSpecVector(t *testing.T) {
	// From the ULID spec: timestamp 1469918176385 encodes to 01ARYZ6S41.
	id, err := NewID(time.UnixMilli(1469918176385), bytes.NewReader(make([]byte, 10)))
	if err != nil {
		t.Fatal(err)
	}
	if id != "01ARYZ6S410000000000000000" {
		t.Fatalf("id = %s", id)
	}
}

func TestNewIDShapeAndOrder(t *testing.T) {
	a, err := NewID(time.UnixMilli(1000), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewID(time.UnixMilli(2000), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 26 || strings.Trim(a, crockford) != "" {
		t.Errorf("malformed id %q", a)
	}
	if !(a < b) {
		t.Errorf("ids not time-ordered: %s >= %s", a, b)
	}
}

func TestNewIDErrors(t *testing.T) {
	if _, err := NewID(time.Now(), bytes.NewReader(nil)); err == nil {
		t.Error("short randomness: want error")
	}
	if _, err := NewID(time.UnixMilli(-1), rand.Reader); err == nil {
		t.Error("pre-epoch time: want error")
	}
}
