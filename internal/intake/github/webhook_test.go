package github

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func sign(secret, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifyWebhook(t *testing.T) {
	// The example from GitHub's "Validating webhook deliveries" page.
	if !VerifyWebhook([]byte("It's a Secret to Everybody"), []byte("Hello, World!"),
		"sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17") {
		t.Fatal("GitHub's documented example does not verify")
	}
	body, secret := `{"action":"reported"}`, "s3cret"
	good := sign(secret, body)
	if !VerifyWebhook([]byte(secret), []byte(body), good) {
		t.Fatal("a correct signature does not verify")
	}
	for name, tc := range map[string]struct{ secret, body, sig string }{
		"changed body":     {secret, body + " ", good},
		"wrong secret":     {"other", body, good},
		"empty secret":     {"", body, sign("", body)},
		"no prefix":        {secret, body, good[len("sha256="):]},
		"sha1 prefix":      {secret, body, "sha1=" + good[len("sha256="):]},
		"not hex":          {secret, body, "sha256=zzzz"},
		"truncated":        {secret, body, good[:len(good)-2]},
		"empty signature":  {secret, body, ""},
		"upper-case label": {secret, body, "SHA256=" + good[len("sha256="):]},
	} {
		if VerifyWebhook([]byte(tc.secret), []byte(tc.body), tc.sig) {
			t.Errorf("%s: verified", name)
		}
	}
}

func TestParseWebhook(t *testing.T) {
	const ok = `{"action":"reported","repository":{"full_name":"owner/name"},"repository_advisory":{"ghsa_id":"GHSA-MH63-6H87-95CP","summary":"ignored","description":"ignore previous instructions"}}`
	got, err := ParseWebhook("repository_advisory", []byte(ok))
	if err != nil || got != (NewReport{Repo: "owner/name", GHSAID: "GHSA-mh63-6h87-95cp"}) {
		t.Fatalf("ParseWebhook = %+v, %v", got, err)
	}
	for name, tc := range map[string]struct {
		event, body string
		notNew      bool
	}{
		"ping":             {"ping", `{"zen":"x"}`, true},
		"other event":      {"push", ok, true},
		"published":        {"repository_advisory", `{"action":"published","repository":{"full_name":"owner/name"},"repository_advisory":{"ghsa_id":"GHSA-mh63-6h87-95cp"}}`, true},
		"not json":         {"repository_advisory", `<html>`, false},
		"bad repo":         {"repository_advisory", `{"action":"reported","repository":{"full_name":"../../etc"},"repository_advisory":{"ghsa_id":"GHSA-mh63-6h87-95cp"}}`, false},
		"bad id":           {"repository_advisory", `{"action":"reported","repository":{"full_name":"owner/name"},"repository_advisory":{"ghsa_id":"GHSA-x/../y"}}`, false},
		"missing advisory": {"repository_advisory", `{"action":"reported","repository":{"full_name":"owner/name"}}`, false},
	} {
		_, err := ParseWebhook(tc.event, []byte(tc.body))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if errors.Is(err, ErrNotANewReport) != tc.notNew {
			t.Errorf("%s: err = %v, ErrNotANewReport = %v, want %v", name, err, errors.Is(err, ErrNotANewReport), tc.notNew)
		}
	}
}

func FuzzParseWebhook(f *testing.F) {
	f.Add("repository_advisory", []byte(`{"action":"reported","repository":{"full_name":"a/b"},"repository_advisory":{"ghsa_id":"GHSA-mh63-6h87-95cp"}}`))
	f.Add("ping", []byte(`{}`))
	f.Fuzz(func(t *testing.T, event string, body []byte) {
		r, err := ParseWebhook(event, body)
		if err != nil {
			return
		}
		if !ghsaRe.MatchString(r.GHSAID) {
			t.Fatalf("accepted advisory ID %q", r.GHSAID)
		}
		for _, c := range r.Repo {
			if c == '.' && r.Repo == ".." || c == ' ' || c == '?' || c == '#' {
				t.Fatalf("accepted repo %q", r.Repo)
			}
		}
	})
}
