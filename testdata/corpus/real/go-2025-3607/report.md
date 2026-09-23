# gorilla/csrf never runs its Referer origin check on real server requests

gorilla/csrf (v1.7.2, commit a009743572494ccbc9d159005bdc58b86a44ddba) is meant to reject cross-origin unsafe
requests over HTTPS by checking the Referer, but the check never fires.

In `(*csrf).ServeHTTP` in `csrf.go`, the Referer/`sameOrigin` check (helper in
`helpers.go`) is guarded by `if r.URL.Scheme == "https"`. For server-side requests
net/http leaves `r.URL.Scheme` empty, so the branch is dead code. A POST carrying a
valid token and cookie from a different origin (for example after an HTTP
machine-in-the-middle injects a form, or via a sibling subdomain) is accepted.

Impact: the documented TLS CSRF protection is silently off for every app using
`csrf.Protect`.

## Reproduce

Drop this test into the repository root at commit `a009743572494ccbc9d159005bdc58b86a44ddba` and run `go test -run TestPoC -count=1 .` from that directory. It fails (or panics) on the affected code and passes once the issue is fixed.

```go
package csrf

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Adapted from the fix commit's csrf_test.go (TestBadReferer), using a real
// server-side request (httptest.NewRequest leaves r.URL.Scheme empty, as
// net/http does). Vulnerable: the Referer check is gated on r.URL.Scheme ==
// "https", which never holds, so a cross-origin POST with a valid token passes.
// Fixed: the cross-origin Referer is rejected with 403.
func TestPoCCrossOriginRefererAccepted(t *testing.T) {
	var token string
	h := Protect([]byte("32-byte-long-auth-key-for-tests!"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = Token(r)
	}))

	get := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, get)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET: status %d", rr.Code)
	}

	post := httptest.NewRequest("POST", "/", nil)
	for _, c := range rr.Result().Cookies() {
		post.AddCookie(c)
	}
	post.Header.Set("X-CSRF-Token", token)
	post.Header.Set("Referer", "https://attacker.invalid/form")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, post)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-origin POST: status %d, want %d", rr.Code, http.StatusForbidden)
	}
}
```
