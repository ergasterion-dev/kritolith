# golang-jwt v4 reports a forged expired token as 'expired' as well as 'invalid signature'

golang-jwt/jwt v4 (v4.5.0, commit 9358574a7a1a2c8d644f22b6e8de627ba85c58d0) validates claims before it verifies the
signature and merges both results into one error.

In `(*Parser).ParseWithClaims` in `parser.go`, an expired token with a bad signature
returns an error for which both `errors.Is(err, jwt.ErrTokenExpired)` and
`errors.Is(err, jwt.ErrTokenSignatureInvalid)` are true. Code that checks
`ErrTokenExpired` first (for example to trigger a refresh flow, or to log and
continue) then treats an attacker-forged token as a genuine, merely expired one.

Impact: callers that branch on `ErrTokenExpired` can accept or act on tokens whose
signature was never valid.

## Reproduce

Drop this test into the repository root at commit `9358574a7a1a2c8d644f22b6e8de627ba85c58d0` and run `go test -run TestPoC -count=1 .` from that directory. It fails (or panics) on the affected code and passes once the issue is fixed.

```go
package jwt

import (
	"errors"
	"os"
	"testing"
)

// Token from the fix commit's parser_test.go ("basic invalid and expired"): an
// expired token with an invalid RS256 signature, checked against the repo's
// test/sample_key.pub. Vulnerable: ParseWithClaims validates claims before the
// signature and reports ErrTokenExpired alongside the signature error, so code
// that only special-cases expiry (errors.Is(err, ErrTokenExpired)) treats a
// forged token as merely expired. Fixed: only the signature error is reported.
func TestPoCExpiredTokenWithBadSignature(t *testing.T) {
	pem, err := os.ReadFile("test/sample_key.pub")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParseRSAPublicKeyFromPEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	tok := "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIiLCJleHAiOjEyMzR9.IbFvatLIJ2Z7B_MAaeIaRZsRSQF1CDzmAE0osHII3WfRTbPavonrDXz-p2Ap_oh9LT2lyohL_jCLoVcpTyu7K3Rt-hdgxZ1_r1StwM1we0SqW2BFFeXCzyS9SLf2YTaVR35lVvfwwlCpPBgOw1SBbczm9m6yPgA9Afsvw_lG_GU2civvG0UzHXxbzWWvJoflGokJDuoHQiku2bfxReyNsoUGcLjx5tfkY7cPihM3CffPpRFYCVjv_abHYelZWpVjdGULQyJDInGYqO8oANqNTtjui7aqxBpcFCUBwVVgktM4Q6Dvj-o5LrdPyJSEl0b_R2JstFE5CbEZGN5anN1yHa"
	_, err = Parse(tok, func(*Token) (interface{}, error) { return key, nil })
	if !errors.Is(err, ErrTokenSignatureInvalid) {
		t.Fatalf("err = %v, want ErrTokenSignatureInvalid", err)
	}
	if errors.Is(err, ErrTokenExpired) {
		t.Fatalf("err = %v also matches ErrTokenExpired for a token with an invalid signature", err)
	}
}
```
