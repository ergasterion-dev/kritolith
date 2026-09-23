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
