package jose

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// Token from the fix commit's jose_test.go (TestDecrypt_PBSE2_HS512_A256KW_*),
// with the protected header re-encoded to carry an attacker-chosen p2c of
// 2^31-1. Vulnerable: Decode runs PBKDF2 for ~2 billion iterations before it
// can fail. Fixed: the p2c bound check rejects the token immediately.
func TestPoCHugeP2C(t *testing.T) {
	orig := "eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwicDJjIjo4MTkyLCJwMnMiOiJCUlkxQ1M3VXNpaTZJNzhkIn0.ovjAL7yRnB_XdJbK8lAaUDRZ-CyVeio8f4pnqOt1FPj1PoQAdEX3S5x6DlzR8aqN_WR5LUwdqDSyUDYhSurnmq8VLfzd3AEe.YAjH6g_zekXJIlPN4Ooo5Q.tutaltxpeVyayXZ9pQovGXTWTf_GWWvtu25Jeg9jgoH0sUX9KCnL00A69e4GJR6EMxalmWsa45AItffbwjUBmwdyklC4ZbTgaovVRs-UwqsZFBO2fpEb7qLajjwra7o4OegzgXDD0jhrKrUusvRWGBvenvumb5euibUxmIfBUcVF1JbdfYxx7ztFeS-QKJpDkE00zyEkViq-QxfrMVl5p7LGmTz8hMrFL3LXLokypZSDgFBfsUzChJf3mlYzxiGaGUqhs7NksQJDoUYf6prPow.XwRVfVTTPogO74RnxZD_9Mse26fTSehna1pbWy4VHfY"
	parts := strings.SplitN(orig, ".", 2)
	hdr := `{"alg":"PBES2-HS512+A256KW","enc":"A256CBC-HS512","p2c":2147483647,"p2s":"BRY1CS7Usii6I78d"}`
	token := base64.RawURLEncoding.EncodeToString([]byte(hdr)) + "." + parts[1]

	done := make(chan error, 1)
	go func() {
		_, _, err := Decode(token, "top secret")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error for p2c=2^31-1, got nil")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Decode did not return within 10s for p2c=2^31-1")
	}
}
