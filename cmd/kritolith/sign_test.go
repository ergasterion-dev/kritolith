package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/report"
	"github.com/ergasterion-dev/kritolith/internal/store"
)

var pubKeyRe = regexp.MustCompile(`ed25519:[A-Za-z0-9+/=]+`)

func TestKeygenSignBundleVerify(t *testing.T) {
	ctx := context.Background()
	dataDir := filepath.Join(t.TempDir(), "data")
	p := writeReport(t, "# Title\n\nno ref report mentioning parser.go")

	// Before keygen: verdicts are unsigned and --bundle is refused.
	var out, errOut bytes.Buffer
	if code := run(ctx, []string{"check", "--repo", "a/b", "--data-dir", dataDir, p}, &out, &errOut); code != 0 || strings.Contains(out.String(), "Signed:") {
		t.Fatalf("unsigned check: code %d, stdout %q", code, out.String())
	}
	bundle := filepath.Join(t.TempDir(), "v.tar")
	out.Reset()
	errOut.Reset()
	if code := run(ctx, []string{"check", "--repo", "a/b", "--data-dir", dataDir, "--bundle", bundle, p}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "kritolith keygen") {
		t.Fatalf("--bundle without a key: code %d, stderr %q", code, errOut.String())
	}

	out.Reset()
	errOut.Reset()
	if code := run(ctx, []string{"keygen", "--data-dir", dataDir}, &out, &errOut); code != 0 {
		t.Fatalf("keygen: code %d, stderr %s", code, errOut.String())
	}
	pub := pubKeyRe.FindString(out.String())
	if pub == "" {
		t.Fatalf("keygen did not print a public key:\n%s", out.String())
	}
	if strings.Contains(out.String(), "seed") {
		t.Error("keygen printed key material")
	}
	out.Reset()
	errOut.Reset()
	if code := run(ctx, []string{"keygen", "--data-dir", dataDir}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "already exists") {
		t.Fatalf("second keygen: code %d, stderr %q", code, errOut.String())
	}

	// After keygen: signed, stored signed, and bundled.
	out.Reset()
	errOut.Reset()
	if code := run(ctx, []string{"check", "--json", "--repo", "a/b", "--data-dir", dataDir, "--bundle", bundle, p}, &out, &errOut); code != 0 {
		t.Fatalf("signed check: code %d, stderr %s", code, errOut.String())
	}
	var v report.Verdict
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Signature) == 0 || v.SignedAt.IsZero() {
		t.Fatalf("verdict is not signed: %+v", v)
	}
	st, err := store.Open(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := st.GetVerdict(ctx, v.ReportID)
	st.Close()
	if err != nil || !bytes.Equal(stored.Signature, v.Signature) || !stored.SignedAt.Equal(v.SignedAt) {
		t.Fatalf("stored verdict: %+v, err %v", stored, err)
	}
	if fi, err := os.Stat(bundle); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("bundle file: %v, %v", fi, err)
	}
	// A bundle is a record: never overwritten.
	out.Reset()
	errOut.Reset()
	if code := run(ctx, []string{"check", "--repo", "a/b", "--data-dir", dataDir, "--bundle", bundle, p}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "exists") {
		t.Fatalf("overwriting a bundle: code %d, stderr %q", code, errOut.String())
	}

	// Verify three ways: own key, --pubkey, --pubkey-file.
	pubFile := filepath.Join(t.TempDir(), "k.pub")
	if err := os.WriteFile(pubFile, []byte(pub+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"verify-bundle", "--data-dir", dataDir, bundle},
		{"verify-bundle", "--pubkey", pub, bundle},
		{"verify-bundle", "--pubkey-file", pubFile, bundle},
	} {
		out.Reset()
		errOut.Reset()
		if code := run(ctx, args, &out, &errOut); code != 0 {
			t.Fatalf("%v: code %d, stderr %s", args, code, errOut.String())
		}
		for _, want := range []string{"OK: signature verifies against " + pub, "Kritolith: NEEDS_INFO", "Report: " + v.ReportID + " (a/b)", "Signed: ", "Report body sha256: "} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("%v: output missing %q:\n%s", args, want, out.String())
			}
		}
	}

	// A flipped byte, or the wrong key, must fail loudly and print no verdict.
	raw, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(raw, []byte("NEEDS_INFO"))
	if i < 0 {
		t.Fatal("test setup: outcome not found in the bundle")
	}
	copy(raw[i:], "INCONCLUSI")
	bad := filepath.Join(t.TempDir(), "bad.tar")
	if err := os.WriteFile(bad, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	otherDir := filepath.Join(t.TempDir(), "other")
	out.Reset()
	if code := run(ctx, []string{"keygen", "--data-dir", otherDir}, &out, &errOut); code != 0 {
		t.Fatal("keygen for a second installation failed")
	}
	otherPub := pubKeyRe.FindString(out.String())
	for name, args := range map[string][]string{
		"tampered":  {"verify-bundle", "--pubkey", pub, bad},
		"wrong key": {"verify-bundle", "--pubkey", otherPub, bundle},
	} {
		out.Reset()
		errOut.Reset()
		if code := run(ctx, args, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "DOES NOT VERIFY") || out.Len() != 0 {
			t.Errorf("%s: code %d, stdout %q, stderr %q", name, code, out.String(), errOut.String())
		}
	}
}

func TestVerifyBundleUsage(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		code int
		want string
	}{
		"no bundle":     {[]string{"verify-bundle"}, 2, "Usage: kritolith verify-bundle"},
		"two keys":      {[]string{"verify-bundle", "--pubkey", "ed25519:x", "--pubkey-file", "f", "b.tar"}, 2, "Usage: kritolith verify-bundle"},
		"bad key":       {[]string{"verify-bundle", "--pubkey", "nope", "b.tar"}, 1, "public key"},
		"no own key":    {[]string{"verify-bundle", "--data-dir", t.TempDir(), "b.tar"}, 1, "public key"},
		"help":          {[]string{"verify-bundle", "-h"}, 0, "Usage: kritolith verify-bundle"},
		"keygen extras": {[]string{"keygen", "extra"}, 2, "Usage: kritolith keygen"},
	} {
		var out, errOut bytes.Buffer
		if code := run(context.Background(), tc.args, &out, &errOut); code != tc.code || !strings.Contains(errOut.String(), tc.want) {
			t.Errorf("%s: code %d (want %d), stderr %q (want %q)", name, code, tc.code, errOut.String(), tc.want)
		}
	}
}
