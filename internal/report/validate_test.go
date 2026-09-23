package report

import "testing"

func TestValidateRepo(t *testing.T) {
	good := []string{"golang/net", "a/b.c", "a-b/c_d", "ergasterion-dev/kritolith"}
	bad := []string{"", "golang", "/net", "golang/", "golang/net/extra", "-x/y", "a/..", "a/.", "a/b c", "a/b;rm", "a/b\n"}
	for _, s := range good {
		if err := ValidateRepo(s); err != nil {
			t.Errorf("ValidateRepo(%q) = %v, want nil", s, err)
		}
	}
	for _, s := range bad {
		if err := ValidateRepo(s); err == nil {
			t.Errorf("ValidateRepo(%q) = nil, want error", s)
		}
	}
}

func TestValidateRef(t *testing.T) {
	good := []string{"v1.2.3", "e1fcd82abba34df74614020343be8eb1fe85f0d9", "release-1.2", "refs/tags/v1", "a3f9c1"}
	bad := []string{
		"", "-x", "--upload-pack=touch /tmp/pwned", "a..b", "a/", "x.lock", "a.", "a b", "a~1", "HEAD@{1}", "a:b", "a//b",
		"refs/.hidden/x", "a/.git/config", "x/y.lock/z", ".", "refs/heads/.x",
	}
	for _, s := range good {
		if err := ValidateRef(s); err != nil {
			t.Errorf("ValidateRef(%q) = %v, want nil", s, err)
		}
	}
	for _, s := range bad {
		if err := ValidateRef(s); err == nil {
			t.Errorf("ValidateRef(%q) = nil, want error", s)
		}
	}
}

func TestIsFullSHA(t *testing.T) {
	tests := map[string]bool{
		"e1fcd82abba34df74614020343be8eb1fe85f0d9": true,
		"E1FCD82ABBA34DF74614020343BE8EB1FE85F0D9": false,
		"e1fcd82": false,
		"v1.2.3":  false,
	}
	for in, want := range tests {
		if got := IsFullSHA(in); got != want {
			t.Errorf("IsFullSHA(%q) = %v, want %v", in, got, want)
		}
	}
}
