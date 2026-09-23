package yaml

import (
	"strings"
	"testing"
	"time"
)

// Inputs from the fix commit's benchmark_test.go (TestLimits). Vulnerable:
// Unmarshal of these ~1 MB documents burns CPU/memory for a long time or
// succeeds without limit. Fixed: each is rejected quickly with an error.
func TestPoCResourceLimits(t *testing.T) {
	cases := map[string][]byte{
		"1000kb of maps with 100 aliases": []byte(`{a: &a [{a}` + strings.Repeat(`,{a}`, 1000*1024/4-100) + `], b: &b [*a` + strings.Repeat(`,*a`, 99) + `]}`),
		"1000kb of deeply nested slices":  []byte(strings.Repeat(`[`, 1000*1024)),
		"1000kb of deeply nested maps":    []byte("x: " + strings.Repeat(`{`, 1000*1024)),
		"1000kb of deeply nested indents": []byte(strings.Repeat(`- `, 1000*1024)),
	}
	for name, data := range cases {
		done := make(chan error, 1)
		go func() {
			var v interface{}
			done <- Unmarshal(data, &v)
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("%s: expected a limit error, got nil", name)
			}
		case <-time.After(20 * time.Second):
			t.Fatalf("%s: Unmarshal did not return within 20s", name)
		}
	}
}
