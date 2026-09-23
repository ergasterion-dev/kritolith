package report

import "testing"

func TestParseOutcome(t *testing.T) {
	for _, o := range Outcomes() {
		got, err := ParseOutcome(string(o))
		if err != nil || got != o {
			t.Errorf("ParseOutcome(%q) = %q, %v", o, got, err)
		}
	}
	for _, bad := range []string{"", "reproduced", "FIXED", "INCONCLUSIVE "} {
		if _, err := ParseOutcome(bad); err == nil {
			t.Errorf("ParseOutcome(%q) succeeded, want error", bad)
		}
	}
	if n := len(Outcomes()); n != 7 {
		t.Errorf("len(Outcomes()) = %d, want 7", n)
	}
}
