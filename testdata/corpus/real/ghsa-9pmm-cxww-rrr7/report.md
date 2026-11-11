# rewrite plugin: nil-pointer panic when reverting an EDNS0 option on a reply with no OPT record

CoreDNS v1.14.4. The `rewrite` plugin accepts `edns0` rules with a `revert` flag, for
example `rewrite edns0 local set 0xffee 0xabcd revert`. With `revert`, the plugin queues a
response rule that removes the option again from the downstream reply.

In `plugin/rewrite/edns0.go`, `(*edns0SetResponseRule).RewriteResponse` calls
`res.IsEdns0()` and ranges over the result's `Option` field without checking it for nil.
When the downstream plugin answers without an OPT record, `IsEdns0` returns nil and the
range dereferences it.

Any ordinary query triggers it once such a rule is configured; the query does not need to
carry EDNS0 itself.

## Steps

Write the test file below to plugin/rewrite/pvr_edns0_panic_test.go and run
`go test ./plugin/rewrite -run TestPVREdns0Panic`.

`plugin/rewrite/pvr_edns0_panic_test.go`:

```go
package rewrite

import "testing"

func TestPVREdns0Panic(t *testing.T) {
	// builds a rule with revert, feeds it a reply with no OPT record
}
```

Output:

    pvr_edns0_panic_test.go: CONFIRMED remote nil-pointer panic in RewriteResponse

Impact: remote, unauthenticated denial of service of the affected server block.
