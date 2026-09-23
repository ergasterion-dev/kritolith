package report

import (
	"fmt"
	"regexp"
	"strings"
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
