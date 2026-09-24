package dedupe

import (
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/ground"
	"github.com/ergasterion-dev/kritolith/internal/report"
)

func TestClaimFingerprints(t *testing.T) {
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*parser).peek", Verified: report.TriYes},
		{Kind: report.ClaimFunction, Value: "unverified.Func", Verified: report.TriUnknown},
		{Kind: report.ClaimFunction, Value: "Read", Verified: report.TriYes}, // bare name: no qualifier
		{Kind: report.ClaimVulnClass, Value: "  Out-Of-Bounds Read  "},
	}
	got := claimFingerprints("go-yaml/yaml", claims)
	if len(got) != 1 {
		t.Fatalf("claimFingerprints = %+v, want exactly 1", got)
	}
	want := fingerprint{repo: "go-yaml/yaml", qualifier: "parser", name: "peek", vulnClass: "out-of-bounds read"}
	if got[0] != want {
		t.Errorf("claimFingerprints[0] = %+v, want %+v", got[0], want)
	}
}

func TestClaimFingerprintsNoVulnClass(t *testing.T) {
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "(*parser).peek", Verified: report.TriYes},
	}
	if got := claimFingerprints("go-yaml/yaml", claims); len(got) != 0 {
		t.Errorf("claimFingerprints = %+v, want none without a vuln_class claim", got)
	}
}

func TestClaimFingerprintsBareNameExcluded(t *testing.T) {
	claims := []report.Claim{
		{Kind: report.ClaimFunction, Value: "Read", Verified: report.TriYes},
		{Kind: report.ClaimVulnClass, Value: "race"},
	}
	if got := claimFingerprints("owner/repo", claims); len(got) != 0 {
		t.Errorf("claimFingerprints = %+v, want none for a bare-name function claim", got)
	}
}

func TestFingerprintMatches(t *testing.T) {
	a := fingerprint{repo: "r", qualifier: "q", name: "n", vulnClass: "v"}
	tests := []struct {
		name string
		b    fingerprint
		want bool
	}{
		{"identical", a, true},
		{"different repo", fingerprint{repo: "other", qualifier: "q", name: "n", vulnClass: "v"}, false},
		{"different qualifier", fingerprint{repo: "r", qualifier: "other", name: "n", vulnClass: "v"}, false},
		{"different vuln class", fingerprint{repo: "r", qualifier: "q", name: "n", vulnClass: "other"}, false},
		{"both empty qualifier never matches", fingerprint{repo: "r", qualifier: "", name: "n", vulnClass: "v"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := a.matches(tt.b); got != tt.want {
				t.Errorf("matches = %v, want %v", got, tt.want)
			}
		})
	}
	empty := fingerprint{repo: "r", qualifier: "", name: "n", vulnClass: "v"}
	if empty.matches(empty) {
		t.Error("two fingerprints both with an empty qualifier must never match each other")
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
