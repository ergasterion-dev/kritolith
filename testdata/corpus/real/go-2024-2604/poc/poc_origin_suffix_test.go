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
