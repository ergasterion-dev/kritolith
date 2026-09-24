package ground

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ergasterion-dev/kritolith/internal/report"
)

func TestGithubOriginURL(t *testing.T) {
	if got := githubOriginURL("golang/net"); got != "https://github.com/golang/net.git" {
		t.Errorf("githubOriginURL = %q", got)
	}
}

func TestServiceGroundSuccess(t *testing.T) {
	origin, commit := newGroundTestOrigin(t)
	s := NewService(t.TempDir())
	s.originURL = func(string) string { return origin }
	r := report.Report{ID: "R1", Repo: "owner/name", ClaimedRef: commit}
	claims := []report.Claim{{Kind: report.ClaimFile, Value: "main.go"}}
	grounded, resolved, resolvedRef, _ := s.Ground(context.Background(), r, claims)
	if !resolved || resolvedRef != commit {
		t.Fatalf("resolved = %v, resolvedRef = %q, want true, %q", resolved, resolvedRef, commit)
	}
	if grounded[0].Verified != report.TriYes {
		t.Errorf("claim = %+v, want Verified: yes", grounded[0])
	}
}

func TestServiceGroundDegradesOnCloneFailure(t *testing.T) {
	s := NewService(t.TempDir())
	s.originURL = func(string) string { return filepath.Join(t.TempDir(), "does-not-exist") }
	r := report.Report{ID: "R1", Repo: "owner/name", ClaimedRef: "deadbeef"}
	claims := []report.Claim{{Kind: report.ClaimFile, Value: "a.go"}}
	grounded, resolved, resolvedRef, _ := s.Ground(context.Background(), r, claims)
	if resolved {
		t.Error("want resolved = false for an unreachable origin")
	}
	if resolvedRef != "" {
		t.Errorf("resolvedRef = %q, want empty", resolvedRef)
	}
	if len(grounded) != 1 || grounded[0].Value != "a.go" {
		t.Errorf("grounded = %+v, want the original claims returned unchanged", grounded)
	}
}

func TestServiceImplementsGrounder(t *testing.T) {
	var _ Grounder = (*Service)(nil)
}
