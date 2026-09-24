package dedupe

import (
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/ground"
	"github.com/ergasterion-dev/kritolith/internal/report"
)

func TestClaimFingerprints(t *testing.T) {
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*parser).peek", Verified: report.TriYes, DeclPkgDir: "yaml", DeclReceiver: "parser", DeclName: "peek"},
		{Kind: report.ClaimFunction, Value: "unverified.Func", Verified: report.TriUnknown, DeclPkgDir: "yaml", DeclName: "Func"},
		{Kind: report.ClaimFunction, Value: "Ambiguous", Verified: report.TriYes}, // resolved but ambiguous: no Decl* fields set
		{Kind: report.ClaimVulnClass, Value: "  Out-Of-Bounds Read  "},
	}
	got := claimFingerprints("go-yaml/yaml", claims)
	if len(got) != 1 {
		t.Fatalf("claimFingerprints = %+v, want exactly 1", got)
	}
	want := fingerprint{repo: "go-yaml/yaml", pkgDir: "yaml", receiver: "parser", name: "peek", vulnClass: "out-of-bounds read"}
	if got[0] != want {
		t.Errorf("claimFingerprints[0] = %+v, want %+v", got[0], want)
	}
}

func TestClaimFingerprintsNoVulnClass(t *testing.T) {
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*parser).peek", Verified: report.TriYes, DeclPkgDir: "yaml", DeclReceiver: "parser", DeclName: "peek"},
	}
	if got := claimFingerprints("go-yaml/yaml", claims); len(got) != 0 {
		t.Errorf("claimFingerprints = %+v, want none without a vuln_class claim", got)
	}
}

func TestClaimFingerprintsUnresolvedNeverContributes(t *testing.T) {
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "Read", Verified: report.TriYes}, // Verified but Decl* empty: unresolved or ambiguous
		{Kind: report.ClaimVulnClass, Value: "race"},
	}
	if got := claimFingerprints("owner/repo", claims); len(got) != 0 {
		t.Errorf("claimFingerprints = %+v, want none for a claim with no resolved declaration identity", got)
	}
}

func TestClaimFingerprintsBareNameFingerprintsWhenUniquelyResolved(t *testing.T) {
	// fab-017's own scenario: a bare name (no written qualifier) that
	// grounding resolved to one unambiguous declaration must fingerprint
	// exactly like a qualified claim would.
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "isOriginAllowed", Verified: report.TriYes, DeclPkgDir: "rest/internal/cors", DeclName: "isOriginAllowed"},
		{Kind: report.ClaimVulnClass, Value: "CORS misconfiguration"},
	}
	got := claimFingerprints("zeromicro/go-zero", claims)
	if len(got) != 1 {
		t.Fatalf("claimFingerprints = %+v, want exactly 1", got)
	}
	want := fingerprint{repo: "zeromicro/go-zero", pkgDir: "rest/internal/cors", name: "isOriginAllowed", vulnClass: "cors misconfiguration"}
	if got[0] != want {
		t.Errorf("claimFingerprints[0] = %+v, want %+v", got[0], want)
	}
}

// TestClaimFingerprintsRootLevelPackage: ground.groundFunctionClaim
// sets DeclPkgDir from path.Dir(declaration file), and path.Dir of a
// root-level file ("main.go") is "." — not "" and not the package
// name. A root-level declaration must still fingerprint correctly
// with that realistic "." pkgDir, distinct from the "" that means
// "unresolved" (see TestFingerprintMatches's emptyPkgDir case).
func TestClaimFingerprintsRootLevelPackage(t *testing.T) {
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "handleRequest", Verified: report.TriYes, DeclPkgDir: ".", DeclName: "handleRequest"},
		{Kind: report.ClaimVulnClass, Value: "SSRF"},
	}
	got := claimFingerprints("example/tool", claims)
	if len(got) != 1 {
		t.Fatalf("claimFingerprints = %+v, want exactly 1", got)
	}
	want := fingerprint{repo: "example/tool", pkgDir: ".", name: "handleRequest", vulnClass: "ssrf"}
	if got[0] != want {
		t.Errorf("claimFingerprints[0] = %+v, want %+v", got[0], want)
	}
}

func TestFingerprintMatches(t *testing.T) {
	a := fingerprint{repo: "r", pkgDir: "pkg", receiver: "T", name: "n", vulnClass: "v"}
	tests := []struct {
		name string
		b    fingerprint
		want bool
	}{
		{"identical", a, true},
		{"different repo", fingerprint{repo: "other", pkgDir: "pkg", receiver: "T", name: "n", vulnClass: "v"}, false},
		{"different pkgDir", fingerprint{repo: "r", pkgDir: "other", receiver: "T", name: "n", vulnClass: "v"}, false},
		{"different receiver", fingerprint{repo: "r", pkgDir: "pkg", receiver: "Other", name: "n", vulnClass: "v"}, false},
		{"empty vs non-empty receiver", fingerprint{repo: "r", pkgDir: "pkg", receiver: "", name: "n", vulnClass: "v"}, false},
		{"different vuln class", fingerprint{repo: "r", pkgDir: "pkg", receiver: "T", name: "n", vulnClass: "other"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := a.matches(tt.b); got != tt.want {
				t.Errorf("matches = %v, want %v", got, tt.want)
			}
		})
	}
	plainA := fingerprint{repo: "r", pkgDir: "pkg", name: "n", vulnClass: "v"}
	plainB := fingerprint{repo: "r", pkgDir: "pkg", name: "n", vulnClass: "v"}
	if !plainA.matches(plainB) {
		t.Error("two plain-function fingerprints (both empty receiver) must match each other")
	}
	emptyPkgDir := fingerprint{repo: "r", pkgDir: "", name: "n", vulnClass: "v"}
	if emptyPkgDir.matches(emptyPkgDir) {
		t.Error("two fingerprints both with an empty pkgDir must never match each other")
	}
}

func TestSplitFunctionClaimExported(t *testing.T) {
	if q, n := ground.SplitFunctionClaim("(*T).M"); q != "T" || n != "M" {
		t.Errorf("SplitFunctionClaim((*T).M) = %q, %q, want T, M", q, n)
	}
	if q, n := ground.SplitFunctionClaim("pkg.Func"); q != "pkg" || n != "Func" {
		t.Errorf("SplitFunctionClaim(pkg.Func) = %q, %q, want pkg, Func", q, n)
	}
}
