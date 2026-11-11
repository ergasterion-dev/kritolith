package verdict

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

// signingContext is prepended to the document before signing, so a
// signature made here can never be mistaken for a signature over some
// other kind of message made with the same key.
const signingContext = "kritolith-verdict-v1\n"

const (
	bundleDocumentName  = "verdict.json"
	bundleSignatureName = "verdict.sig"

	maxBundleBytes   = 16 << 20
	maxDocumentBytes = 8 << 20
	publicKeyPrefix  = "ed25519:"
)

// Subject says which report a verdict is about, without carrying the
// report itself: the text of an embargoed report must not travel with
// its verdict. BodySHA256 lets someone who already has the report
// confirm it is the one that was checked.
type Subject struct {
	ID         string        `json:"id"`
	Source     report.Source `json:"source"`
	SourceRef  string        `json:"source_ref"`
	Repo       string        `json:"repo"`
	ClaimedRef string        `json:"claimed_ref"`
	Title      string        `json:"title"`
	BodySHA256 string        `json:"body_sha256"`
}

// Document is what gets signed: the verdict together with what it is
// a verdict on. Signing the verdict alone would leave a signature that
// could be attached to a different report.
type Document struct {
	Version int            `json:"version"`
	Report  Subject        `json:"report"`
	Verdict report.Verdict `json:"verdict"`
}

// NewDocument builds the document for r and v. The verdict's own
// Signature field is cleared (a signature can't cover itself) and its
// nil lists become empty ones, so the same verdict always encodes to
// the same bytes.
func NewDocument(r report.Report, v report.Verdict) Document {
	v.Signature = nil
	if v.Claims == nil {
		v.Claims = []report.Claim{}
	}
	if v.Duplicates == nil {
		v.Duplicates = []report.DupMatch{}
	}
	if v.Notes == nil {
		v.Notes = []string{}
	}
	sum := sha256.Sum256([]byte(r.Body))
	return Document{
		Version: 1,
		Report: Subject{
			ID: r.ID, Source: r.Source, SourceRef: r.SourceRef, Repo: r.Repo,
			ClaimedRef: r.ClaimedRef, Title: r.Title, BodySHA256: hex.EncodeToString(sum[:]),
		},
		Verdict: v,
	}
}

// Encode returns the document's bytes. These exact bytes are what is
// signed and what a bundle carries; a verifier checks the signature
// over the bytes it was given and never re-encodes.
func (d Document) Encode() ([]byte, error) {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("verdict: encode document: %w", err)
	}
	return append(b, '\n'), nil
}

// Signer signs verdicts with one ed25519 key.
type Signer struct {
	key ed25519.PrivateKey
	now func() time.Time
}

// NewSigner returns a Signer for key. A nil now uses time.Now.
func NewSigner(key ed25519.PrivateKey, now func() time.Time) (*Signer, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("verdict: signing key has the wrong size")
	}
	if now == nil {
		now = time.Now
	}
	return &Signer{key: key, now: now}, nil
}

// PublicKey returns the key verdicts signed here verify against.
func (s *Signer) PublicKey() ed25519.PublicKey {
	return s.key.Public().(ed25519.PublicKey)
}

// Sign returns v with SignedAt and Signature set. The signature covers
// the document for r and v, including SignedAt.
func (s *Signer) Sign(r report.Report, v report.Verdict) (report.Verdict, error) {
	v.SignedAt = s.now().UTC().Truncate(time.Second)
	doc, err := NewDocument(r, v).Encode()
	if err != nil {
		return report.Verdict{}, err
	}
	v.Signature = ed25519.Sign(s.key, signedMessage(doc))
	return v, nil
}

func signedMessage(doc []byte) []byte {
	return append([]byte(signingContext), doc...)
}

// VerifyDocument reports whether sig is pub's signature over doc.
func VerifyDocument(pub ed25519.PublicKey, doc, sig []byte) bool {
	return len(pub) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize &&
		ed25519.Verify(pub, signedMessage(doc), sig)
}

// FormatPublicKey renders a public key as "ed25519:<base64>".
func FormatPublicKey(pub ed25519.PublicKey) string {
	return publicKeyPrefix + base64.StdEncoding.EncodeToString(pub)
}

// ParsePublicKey reads the form FormatPublicKey writes.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	rest, ok := strings.CutPrefix(s, publicKeyPrefix)
	if !ok {
		return nil, fmt.Errorf("verdict: public key must start with %q", publicKeyPrefix)
	}
	raw, err := base64.StdEncoding.DecodeString(rest)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("verdict: public key is not a base64 ed25519 key")
	}
	return ed25519.PublicKey(raw), nil
}

// WriteBundle writes the evidence bundle for a signed verdict: a tar
// archive holding verdict.json (the signed document) and verdict.sig
// (the detached signature, base64). It refuses a verdict whose
// signature does not verify against pub, so a bundle that leaves here
// is one a verifier will accept.
func WriteBundle(w io.Writer, r report.Report, v report.Verdict, pub ed25519.PublicKey) error {
	if len(v.Signature) == 0 {
		return errors.New("verdict: bundle: the verdict is not signed")
	}
	doc, err := NewDocument(r, v).Encode()
	if err != nil {
		return err
	}
	if !VerifyDocument(pub, doc, v.Signature) {
		return errors.New("verdict: bundle: the verdict's signature does not verify")
	}
	sig := []byte(base64.StdEncoding.EncodeToString(v.Signature) + "\n")
	tw := tar.NewWriter(w)
	for _, f := range []struct {
		name string
		data []byte
	}{{bundleDocumentName, doc}, {bundleSignatureName, sig}} {
		hdr := &tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.data)), ModTime: v.SignedAt, Format: tar.FormatPAX}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("verdict: bundle: %w", err)
		}
		if _, err := tw.Write(f.data); err != nil {
			return fmt.Errorf("verdict: bundle: %w", err)
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("verdict: bundle: %w", err)
	}
	return nil
}

// ReadBundle reads a bundle and checks its signature against pub. It
// returns the document only if the signature is valid: nothing from an
// unverified bundle is handed back to be displayed. A bundle is
// untrusted input, so it may hold exactly the two expected regular
// files, within fixed size limits, and nothing is written to disk.
func ReadBundle(r io.Reader, pub ed25519.PublicKey) (Document, error) {
	var doc, sigText []byte
	tr := tar.NewReader(io.LimitReader(r, maxBundleBytes))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Document{}, fmt.Errorf("verdict: bundle is not a readable tar archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			return Document{}, fmt.Errorf("verdict: bundle entry %q is not a regular file", report.Printable(hdr.Name))
		}
		var dst *[]byte
		switch hdr.Name {
		case bundleDocumentName:
			dst = &doc
		case bundleSignatureName:
			dst = &sigText
		default:
			return Document{}, fmt.Errorf("verdict: unexpected bundle entry %q", report.Printable(hdr.Name))
		}
		if *dst != nil {
			return Document{}, fmt.Errorf("verdict: bundle has %s twice", hdr.Name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxDocumentBytes+1))
		if err != nil {
			return Document{}, fmt.Errorf("verdict: reading %s from the bundle: %w", hdr.Name, err)
		}
		if len(data) > maxDocumentBytes {
			return Document{}, fmt.Errorf("verdict: %s in the bundle is larger than %d bytes", hdr.Name, maxDocumentBytes)
		}
		*dst = append([]byte{}, data...)
	}
	if doc == nil || sigText == nil {
		return Document{}, fmt.Errorf("verdict: bundle must contain %s and %s", bundleDocumentName, bundleSignatureName)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigText)))
	if err != nil {
		return Document{}, errors.New("verdict: the bundle's signature is not base64")
	}
	if !VerifyDocument(pub, doc, sig) {
		return Document{}, errors.New("verdict: SIGNATURE DOES NOT VERIFY: the bundle was altered, or was signed with a different key")
	}
	var d Document
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return Document{}, fmt.Errorf("verdict: the signed document is not valid: %w", err)
	}
	if d.Version != 1 {
		return Document{}, fmt.Errorf("verdict: unsupported document version %d", d.Version)
	}
	if !d.Verdict.Outcome.Valid() {
		return Document{}, fmt.Errorf("verdict: the signed document has an unknown outcome %q", report.Printable(string(d.Verdict.Outcome)))
	}
	d.Verdict.Signature = sig
	return d, nil
}

// SubjectReport returns the parts of the original report a document
// carries, in the shape Render expects.
func (d Document) SubjectReport() report.Report {
	s := d.Report
	return report.Report{ID: s.ID, Source: s.Source, SourceRef: s.SourceRef, Repo: s.Repo, ClaimedRef: s.ClaimedRef, Title: s.Title}
}
