package report

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

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

func TestReproResultJSON(t *testing.T) {
	t.Run("old shape decodes", func(t *testing.T) {
		var r ReproResult
		if err := json.Unmarshal([]byte(`{"ref":"v1.0","reproduced":true,"signal":"panic"}`), &r); err != nil {
			t.Fatal(err)
		}
		want := ReproResult{Ref: "v1.0", Reproduced: true, Signal: "panic"}
		if !reflect.DeepEqual(r, want) {
			t.Errorf("got %+v, want %+v", r, want)
		}
	})
	t.Run("old shape encodes unchanged", func(t *testing.T) {
		b, err := json.Marshal(ReproResult{Ref: "v1.0", Reproduced: true, Signal: "panic"})
		if err != nil {
			t.Fatal(err)
		}
		if got, want := string(b), `{"ref":"v1.0","reproduced":true,"signal":"panic"}`; got != want {
			t.Errorf("got %s, want %s", got, want)
		}
	})
	t.Run("new shape round-trips", func(t *testing.T) {
		in := ReproResult{
			Ref: "v1.0", Reproduced: true, Signal: "panic",
			Control:      &ReproResult{Ref: "v1.1", Signal: "none", Phase: "run"},
			Phase:        "control",
			Shape:        "test",
			LogSHA256:    map[string]string{"build": "ab12", "run": "cd34"},
			Notes:        []string{"n1"},
			ControlState: "fixed",
		}
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{`"control"`, `"phase"`, `"shape"`, `"log_sha256"`, `"notes"`, `"control_state"`} {
			if !strings.Contains(string(b), k) {
				t.Errorf("missing %s in %s", k, b)
			}
		}
		var out ReproResult
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("got %+v, want %+v", out, in)
		}
	})
}
