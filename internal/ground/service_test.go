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
	gr := s.Ground(context.Background(), r, claims)
	if !gr.RefResolved || gr.ResolvedRef != commit {
		t.Fatalf("RefResolved = %v, ResolvedRef = %q, want true, %q", gr.RefResolved, gr.ResolvedRef, commit)
	}
	if gr.Claims[0].Verified != report.TriYes {
		t.Errorf("claim = %+v, want Verified: yes", gr.Claims[0])
	}
}

func TestServiceGroundDegradesOnCloneFailure(t *testing.T) {
	s := NewService(t.TempDir())
	s.originURL = func(string) string { return filepath.Join(t.TempDir(), "does-not-exist") }
	r := report.Report{ID: "R1", Repo: "owner/name", ClaimedRef: "deadbeef"}
	claims := []report.Claim{{Kind: report.ClaimFile, Value: "a.go"}}
	gr := s.Ground(context.Background(), r, claims)
	if gr.RefResolved {
		t.Error("want RefResolved = false for an unreachable origin")
	}
	if gr.ResolvedRef != "" {
		t.Errorf("ResolvedRef = %q, want empty", gr.ResolvedRef)
	}
	if len(gr.Claims) != 1 || gr.Claims[0].Value != "a.go" {
		t.Errorf("Claims = %+v, want the original claims returned unchanged", gr.Claims)
	}
}

func TestServiceImplementsGrounder(t *testing.T) {
	var _ Grounder = (*Service)(nil)
}

// Service.Mirror is the mirror Ground uses for a repository: the same
// path under the data dir and the same origin.
func TestServiceMirror(t *testing.T) {
	dir := t.TempDir()
	s := NewService(dir)
	tests := []struct {
		name, repo string
		wantErr    bool
	}{
		{"valid", "owner/name", false},
		{"invalid repo", "../etc", true},
		{"empty", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := s.Mirror(tt.repo)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Mirror(%q) = %+v, want an error", tt.repo, m)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want, _ := OpenMirror(dir, tt.repo, githubOriginURL(tt.repo))
			if *m != *want {
				t.Fatalf("Mirror = %+v, want %+v", m, want)
			}
		})
	}
}
