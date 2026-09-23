package report

import "testing"

func TestPrintable(t *testing.T) {
	tests := []struct{ in, want string }{
		{"plain text", "plain text"},
		{"a\x1b[31mb", "a�[31mb"},
		{"line1\nline2\r", "line1�line2�"},
		{"‮evil", "�evil"},
		{"x⁦y⁩", "x�y�"},
		{"bad\xffutf8", "bad�utf8"},
		{"\u0085c1", "�c1"},
		{"héllo 日本", "héllo 日本"},
	}
	for _, tt := range tests {
		if got := Printable(tt.in); got != tt.want {
			t.Errorf("Printable(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
