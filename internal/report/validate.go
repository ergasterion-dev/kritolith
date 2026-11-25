package report

import (
	"fmt"
	"path"
	"regexp"
	"strings"
	"unicode"
)

var (
	repoRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$`)
	refRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$`)
	shaRe  = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// ValidateRepo checks that s is a GitHub-style owner/name.
func ValidateRepo(s string) error {
	if !repoRe.MatchString(s) {
		return fmt.Errorf("report: invalid repo %q: want owner/name", s)
	}
	if name := s[strings.IndexByte(s, '/')+1:]; name == "." || name == ".." {
		return fmt.Errorf("report: invalid repo name %q", s)
	}
	return nil
}

// ValidateRef checks that s is a safe commit SHA, tag or branch name.
// It is deliberately stricter than git: refs later reach git's command
// line, so anything that could parse as an option or revision
// expression (leading '-', "..", '@', '~', ':') is rejected. Every
// path component is checked too, not just the whole string: a
// component starting with '.' or ending in ".lock" is rejected
// wherever it appears, since these are git-internal path shapes a
// reporter-controlled ref should never be able to reach.
func ValidateRef(s string) error {
	if !refRe.MatchString(s) ||
		strings.Contains(s, "..") ||
		strings.Contains(s, "//") ||
		strings.HasSuffix(s, "/") ||
		strings.HasSuffix(s, ".") {
		return fmt.Errorf("report: invalid ref %q", s)
	}
	for _, part := range strings.Split(s, "/") {
		if strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return fmt.Errorf("report: invalid ref %q", s)
		}
	}
	return nil
}

// IsFullSHA reports whether s is a full lowercase 40-hex commit SHA.
func IsFullSHA(s string) bool { return shaRe.MatchString(s) }

// MaxPoCDirLen bounds a PoC directory hint.
const MaxPoCDirLen = 255

// ValidatePoCDir checks a PoC directory hint (Report.PoCDir): a
// repository-relative, clean, slash-separated path ("." is the
// repository root) with no ".." component, no NUL, backslash or control
// character, at most MaxPoCDirLen bytes. The sandbox re-checks the hint
// against the tree it extracts; this only refuses obvious nonsense at
// the edge.
func ValidatePoCDir(s string) error {
	switch {
	case s == "" || len(s) > MaxPoCDirLen:
		return fmt.Errorf("report: PoC dir must be 1..%d bytes", MaxPoCDirLen)
	case strings.HasPrefix(s, "/"):
		return fmt.Errorf("report: PoC dir %q must be relative to the repository root", s)
	case strings.ContainsRune(s, '\\') || strings.IndexFunc(s, unicode.IsControl) >= 0:
		return fmt.Errorf("report: PoC dir %q contains a backslash or control character", s)
	case path.Clean(s) != s:
		return fmt.Errorf("report: PoC dir %q must be a clean path", s)
	}
	for _, e := range strings.Split(s, "/") {
		if e == ".." {
			return fmt.Errorf("report: PoC dir %q must not contain ..", s)
		}
	}
	return nil
}
