# CORS allow-list bypass in go-zero via suffix match

go-zero (v1.4.3 line, commit d953675085476c98772fbc495ccaf47b9fd479df) checks CORS origins with a plain suffix match.

`isOriginAllowed` in `rest/internal/cors/handlers.go` returns true when
`strings.HasSuffix(origin, allowed)`. With `rest.WithCors("safe.com")` an attacker
who registers `not-safe.com` (or `evilsafe.com`) passes the check, gets
`Access-Control-Allow-Origin` echoed back and can read authenticated responses from
the victim's browser.

Impact: cross-origin data theft from any go-zero service that relies on the CORS
allow-list.

## Reproduce

Drop this test into `rest/internal/cors/` at commit `d953675085476c98772fbc495ccaf47b9fd479df` and run `go test -run TestPoC -count=1 .` from that directory. It fails (or panics) on the affected code and passes once the issue is fixed.

```go
package cors

import "testing"

// Case from the advisory and the fix commit's handlers_test.go ("not safe origin").
// Vulnerable: isOriginAllowed accepts any origin that ends with an allowed
// domain. Fixed: only the domain itself and its subdomains are allowed.
func TestPoCOriginSuffixBypass(t *testing.T) {
	if isOriginAllowed([]string{"safe.com"}, "not-safe.com") {
		t.Fatal(`origin "not-safe.com" was allowed by allow-list ["safe.com"]`)
	}
}
```
