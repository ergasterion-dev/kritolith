package sandbox

import "testing"

func TestUnescapeMountinfo(t *testing.T) {
	for in, want := range map[string]string{
		`/a/b`:            "/a/b",
		`/a\040b`:         "/a b",
		`/a\134b\011c`:    "/a\\b\tc",
		`/trailing\04`:    `/trailing\04`,
		`/x\999`:          `/x\999`,
		`/w/kritolith-1/`: "/w/kritolith-1/",
	} {
		if got := unescapeMountinfo(in); got != want {
			t.Errorf("unescapeMountinfo(%q) = %q, want %q", in, got, want)
		}
	}
}
