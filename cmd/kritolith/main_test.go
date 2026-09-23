package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunDispatch(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{"no args", nil, 2, "", "Usage: kritolith"},
		{"version", []string{"version"}, 0, "kritolith dev", ""},
		{"help", []string{"help"}, 0, "Usage: kritolith", ""},
		{"-h", []string{"-h"}, 0, "Usage: kritolith", ""},
		{"unknown", []string{"frobnicate"}, 2, "", `unknown command "frobnicate"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := run(context.Background(), tt.args, &out, &errOut)
			if code != tt.wantCode {
				t.Fatalf("code = %d, want %d (stderr: %s)", code, tt.wantCode, errOut.String())
			}
			if !strings.Contains(out.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", out.String(), tt.wantStdout)
			}
			if !strings.Contains(errOut.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", errOut.String(), tt.wantStderr)
			}
		})
	}
}
