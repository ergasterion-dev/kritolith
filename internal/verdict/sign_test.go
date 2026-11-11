package verdict

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

func testKey(seedByte byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize))
}

func testSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := NewSigner(testKey(1), func() time.Time { return time.Date(2026, 11, 11, 12, 30, 45, 999, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var (
	testReport = report.Report{
		ID: "R1", Source: report.SourceFile, SourceRef: "/tmp/r.md", Repo: "owner/name",
		ClaimedRef: "v1.2.3", Title: "Over-read", Body: "embargoed-body-marker in a.go",
	}
	testVerdict = report.Verdict{
		ReportID: "R1", Outcome: report.OutcomeGroundingFailed,
		Claims: []report.Claim{{Kind: report.ClaimFile, Value: "a.go", Source: "deterministic", Verified: report.TriNo, Evidence: "not found"}},
		Notes:  []string{"a claimed file or function does not exist at the resolved commit"},
	}
)

func signedBundle(t *testing.T) (*Signer, report.Verdict, []byte) {
	t.Helper()
	s := testSigner(t)
	v, err := s.Sign(testReport, testVerdict)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteBundle(&buf, testReport, v, s.PublicKey()); err != nil {
		t.Fatal(err)
	}
	return s, v, buf.Bytes()
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	s, v, bundle := signedBundle(t)
	if len(v.Signature) != ed25519.SignatureSize || !v.SignedAt.Equal(time.Date(2026, 11, 11, 12, 30, 45, 0, time.UTC)) {
		t.Fatalf("signed verdict = %+v", v)
	}
	doc, err := ReadBundle(bytes.NewReader(bundle), s.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if doc.Verdict.Outcome != report.OutcomeGroundingFailed || doc.Report.Repo != "owner/name" || doc.Report.ClaimedRef != "v1.2.3" {
		t.Errorf("document = %+v", doc)
	}
	if len(doc.Verdict.Claims) != 1 || doc.Verdict.Claims[0].Value != "a.go" {
		t.Errorf("claims = %+v", doc.Verdict.Claims)
	}
	out := Render(doc.SubjectReport(), doc.Verdict)
	for _, want := range []string{"Kritolith: GROUNDING_FAILED at v1.2.3", "file a.go — not found", "Report: R1 (owner/name)", "Signed: 2026-11-11 12:30:45 UTC"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered bundle missing %q:\n%s", want, out)
		}
	}
	// The report's text is embargoed and must not travel in the bundle;
	// its hash does, so a holder of the report can match them up.
	if bytes.Contains(bundle, []byte("embargoed-body-marker")) {
		t.Error("the bundle contains the report body")
	}
	sum := sha256.Sum256([]byte(testReport.Body))
	if doc.Report.BodySHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("body hash = %q", doc.Report.BodySHA256)
	}
}

// Signing must give the same bytes for the same verdict, whether its
// empty lists are nil or empty: a verdict read back from the store has
// one, a freshly composed verdict the other.
func TestDocumentEncodingIsStable(t *testing.T) {
	a := report.Verdict{ReportID: "R1", Outcome: report.OutcomeInconclusive}
	b := a
	b.Claims, b.Duplicates, b.Notes = []report.Claim{}, []report.DupMatch{}, []string{}
	b.Signature = []byte("ignored: a signature can't cover itself")
	da, err := NewDocument(testReport, a).Encode()
	if err != nil {
		t.Fatal(err)
	}
	db, err := NewDocument(testReport, b).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(da, db) {
		t.Fatalf("documents differ:\n%s\n%s", da, db)
	}
}

func TestSignatureCoversEverything(t *testing.T) {
	s := testSigner(t)
	v, err := s.Sign(testReport, testVerdict)
	if err != nil {
		t.Fatal(err)
	}
	verifies := func(r report.Report, v report.Verdict) bool {
		doc, err := NewDocument(r, v).Encode()
		if err != nil {
			t.Fatal(err)
		}
		return VerifyDocument(s.PublicKey(), doc, v.Signature)
	}
	if !verifies(testReport, v) {
		t.Fatal("an untouched verdict does not verify")
	}
	for name, mut := range map[string]func(*report.Report, *report.Verdict){
		"outcome": func(_ *report.Report, v *report.Verdict) { v.Outcome = report.OutcomeReproduced },
		"claim": func(_ *report.Report, v *report.Verdict) {
			v.Claims = append([]report.Claim{}, v.Claims...)
			v.Claims[0].Verified = report.TriYes
		},
		"evidence": func(_ *report.Report, v *report.Verdict) {
			v.Claims = append([]report.Claim{}, v.Claims...)
			v.Claims[0].Evidence = "found"
		},
		"note":        func(_ *report.Report, v *report.Verdict) { v.Notes = []string{"fine"} },
		"signed at":   func(_ *report.Report, v *report.Verdict) { v.SignedAt = v.SignedAt.Add(time.Second) },
		"report id":   func(r *report.Report, _ *report.Verdict) { r.ID = "R2" },
		"repo":        func(r *report.Report, _ *report.Verdict) { r.Repo = "other/name" },
		"claimed ref": func(r *report.Report, _ *report.Verdict) { r.ClaimedRef = "v9.9.9" },
		"report body": func(r *report.Report, _ *report.Verdict) { r.Body += " " },
		"title":       func(r *report.Report, _ *report.Verdict) { r.Title = "Other" },
	} {
		r2, v2 := testReport, v
		mut(&r2, &v2)
		if verifies(r2, v2) {
			t.Errorf("%s: a changed document still verifies", name)
		}
	}
	other, err := NewSigner(testKey(2), nil)
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := NewDocument(testReport, v).Encode()
	if VerifyDocument(other.PublicKey(), doc, v.Signature) {
		t.Error("verifies against a different key")
	}
	// The context string: the same key signing the bare document
	// elsewhere must not produce a signature accepted here.
	if VerifyDocument(s.PublicKey(), doc, ed25519.Sign(testKey(1), doc)) {
		t.Error("a signature without the context string verifies")
	}
	if VerifyDocument(nil, doc, v.Signature) || VerifyDocument(s.PublicKey(), doc, nil) || VerifyDocument(s.PublicKey()[:5], doc, v.Signature) {
		t.Error("malformed key or signature verifies")
	}
}

type tarEntry struct {
	name string
	data []byte
	typ  byte
}

func buildTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.data)), Typeflag: typ}
		if typ != tar.TypeReg {
			hdr.Size = 0
			hdr.Linkname = "/etc/passwd"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write(e.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestReadBundleRejects(t *testing.T) {
	s, v, good := signedBundle(t)
	doc, err := NewDocument(testReport, v).Encode()
	if err != nil {
		t.Fatal(err)
	}
	sig := []byte(base64.StdEncoding.EncodeToString(v.Signature))
	tampered := bytes.Replace(doc, []byte("GROUNDING_FAILED"), []byte("INCONCLUSIVE"), 1)
	if bytes.Equal(tampered, doc) {
		t.Fatal("test setup: nothing was replaced")
	}
	otherSig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(testKey(1), signedMessage([]byte("something else")))))
	v2Doc := bytes.Replace(doc, []byte(`"version": 1`), []byte(`"version": 2`), 1)
	v2Sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(testKey(1), signedMessage(v2Doc))))
	badOutcome := bytes.Replace(doc, []byte("GROUNDING_FAILED"), []byte("TOTALLY_FINE"), 1)
	badOutcomeSig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(testKey(1), signedMessage(badOutcome))))
	extraField := bytes.Replace(doc, []byte(`"version": 1`), []byte(`"version": 1, "extra": true`), 1)
	extraSig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(testKey(1), signedMessage(extraField))))

	cases := map[string]struct {
		bundle []byte
		want   string
	}{
		"not a tar":          {[]byte("hello, this is not an archive at all, not even close to one........"), "bundle"},
		"empty":              {nil, "must contain"},
		"tampered document":  {buildTar(t, []tarEntry{{name: "verdict.json", data: tampered}, {name: "verdict.sig", data: sig}}), "DOES NOT VERIFY"},
		"tampered signature": {buildTar(t, []tarEntry{{name: "verdict.json", data: doc}, {name: "verdict.sig", data: otherSig}}), "DOES NOT VERIFY"},
		"missing signature":  {buildTar(t, []tarEntry{{name: "verdict.json", data: doc}}), "must contain"},
		"missing document":   {buildTar(t, []tarEntry{{name: "verdict.sig", data: sig}}), "must contain"},
		"signature not b64":  {buildTar(t, []tarEntry{{name: "verdict.json", data: doc}, {name: "verdict.sig", data: []byte("!!!")}}), "not base64"},
		"extra entry":        {buildTar(t, []tarEntry{{name: "verdict.json", data: doc}, {name: "verdict.sig", data: sig}, {name: "evil.sh", data: []byte("x")}}), "unexpected bundle entry"},
		"path entry":         {buildTar(t, []tarEntry{{name: "../verdict.json", data: doc}, {name: "verdict.sig", data: sig}}), "unexpected bundle entry"},
		"duplicate entry":    {buildTar(t, []tarEntry{{name: "verdict.json", data: tampered}, {name: "verdict.json", data: doc}, {name: "verdict.sig", data: sig}}), "twice"},
		"symlink entry":      {buildTar(t, []tarEntry{{name: "verdict.json", typ: tar.TypeSymlink}, {name: "verdict.sig", data: sig}}), "not a regular file"},
		"oversized entry":    {buildTar(t, []tarEntry{{name: "verdict.json", data: bytes.Repeat([]byte("a"), maxDocumentBytes+1)}, {name: "verdict.sig", data: sig}}), "larger than"},
		// Validly signed by the right key, but not a document this
		// version understands.
		"signed, version 2":     {buildTar(t, []tarEntry{{name: "verdict.json", data: v2Doc}, {name: "verdict.sig", data: v2Sig}}), "unsupported document version"},
		"signed, bad outcome":   {buildTar(t, []tarEntry{{name: "verdict.json", data: badOutcome}, {name: "verdict.sig", data: badOutcomeSig}}), "unknown outcome"},
		"signed, unknown field": {buildTar(t, []tarEntry{{name: "verdict.json", data: extraField}, {name: "verdict.sig", data: extraSig}}), "not valid"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ReadBundle(bytes.NewReader(tc.bundle), s.PublicKey())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
	other, _ := NewSigner(testKey(2), nil)
	if _, err := ReadBundle(bytes.NewReader(good), other.PublicKey()); err == nil || !strings.Contains(err.Error(), "DOES NOT VERIFY") {
		t.Fatalf("a bundle checked against the wrong key: err = %v", err)
	}
}

func TestWriteBundleRefusesUnsignedOrMismatched(t *testing.T) {
	s := testSigner(t)
	if err := WriteBundle(&bytes.Buffer{}, testReport, testVerdict, s.PublicKey()); err == nil {
		t.Error("wrote a bundle for an unsigned verdict")
	}
	v, _ := s.Sign(testReport, testVerdict)
	v.Outcome = report.OutcomeInconclusive // changed after signing
	if err := WriteBundle(&bytes.Buffer{}, testReport, v, s.PublicKey()); err == nil {
		t.Error("wrote a bundle whose signature does not verify")
	}
}

func TestPublicKeyFormat(t *testing.T) {
	pub := testKey(1).Public().(ed25519.PublicKey)
	s := FormatPublicKey(pub)
	got, err := ParsePublicKey("  " + s + "\n")
	if err != nil || !got.Equal(pub) {
		t.Fatalf("round trip: %v, %v", got, err)
	}
	for _, bad := range []string{"", "ed25519:", "ed25519:!!!", "rsa:" + s[8:], s[8:], "ed25519:" + base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("ParsePublicKey(%q) accepted", bad)
		}
	}
}

func TestKeyFile(t *testing.T) {
	dir := t.TempDir()
	if _, found, err := LoadKey(dir); err != nil || found {
		t.Fatalf("no key yet: found %v, err %v", found, err)
	}
	pub, err := GenerateKey(dir, bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	privPath, pubPath := KeyPaths(dir)
	for path, want := range map[string]os.FileMode{privPath: 0o600, filepath.Dir(privPath): 0o700} {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != want {
			t.Errorf("%s has mode %v, want %v", path, st.Mode().Perm(), want)
		}
	}
	key, found, err := LoadKey(dir)
	if err != nil || !found || !key.Public().(ed25519.PublicKey).Equal(pub) {
		t.Fatalf("LoadKey: found %v, err %v", found, err)
	}
	if fromFile, err := LoadPublicKey(dir); err != nil || !fromFile.Equal(pub) {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	if raw, _ := os.ReadFile(pubPath); strings.Contains(string(raw), "seed") {
		t.Error("the public key file mentions a seed")
	}

	// A second keygen must not replace the key.
	if _, err := GenerateKey(dir, bytes.NewReader(bytes.Repeat([]byte{9}, 64))); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second keygen: err = %v", err)
	}
	if again, _, _ := LoadKey(dir); !again.Equal(key) {
		t.Fatal("the key changed")
	}

	// A key others can read is refused, not used.
	if err := os.Chmod(privPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadKey(dir); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("world-readable key: err = %v", err)
	}
	if err := os.Chmod(privPath, 0o600); err != nil {
		t.Fatal(err)
	}

	// Damaged or swapped key files are errors, never "no key".
	if err := os.WriteFile(privPath, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, found, err := LoadKey(dir); err == nil || found {
		t.Fatalf("garbage key: found %v, err %v", found, err)
	}
	if err := os.Remove(privPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(pubPath, privPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadKey(dir); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked key: err = %v", err)
	}
	if _, err := GenerateKey(dir, bytes.NewReader(bytes.Repeat([]byte{9}, 64))); err == nil {
		t.Fatal("keygen wrote through a symlink")
	}
}

func FuzzReadBundle(f *testing.F) {
	pub := testKey(1).Public().(ed25519.PublicKey)
	v := testVerdict
	v.SignedAt = time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	doc, _ := NewDocument(testReport, v).Encode()
	v.Signature = ed25519.Sign(testKey(1), signedMessage(doc))
	var good bytes.Buffer
	if err := WriteBundle(&good, testReport, v, pub); err != nil {
		f.Fatal(err)
	}
	f.Add(good.Bytes())
	f.Add([]byte{})
	f.Add(good.Bytes()[:600])
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := ReadBundle(bytes.NewReader(data), pub)
		if err != nil {
			return
		}
		// Anything accepted must be exactly what was signed.
		if !d.Verdict.Outcome.Valid() || d.Version != 1 {
			t.Fatalf("accepted an invalid document: %+v", d)
		}
		if d.Report.ID != testReport.ID || d.Verdict.Outcome != testVerdict.Outcome {
			t.Fatalf("accepted a document other than the signed one: %+v", d)
		}
	})
}
