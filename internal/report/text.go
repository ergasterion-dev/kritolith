package report

import (
	"strings"
	"unicode"
)

// Printable makes untrusted text safe to show on one terminal line.
// Invalid UTF-8, control characters (including newlines and ESC) and
// Unicode bidirectional formatting characters become U+FFFD, so a
// hostile report can't move the cursor, recolor output or reorder text.
func Printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || isBidiControl(r) {
			return '�'
		}
		return r
	}, strings.ToValidUTF8(s, "�"))
}

func isBidiControl(r rune) bool {
	switch {
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
		return true
	case r == 0x200E, r == 0x200F, r == 0x061C:
		return true
	}
	return false
}
