package sandbox

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"unicode"

	"github.com/ergasterion-dev/kritolith/internal/config"
)

// removeScratch removes one scratch tree; tests replace it.
var removeScratch = removeAllForce

// fastRemoveAll is removeAllForce's first attempt; tests make it fail
// to force the fallback.
var fastRemoveAll = os.RemoveAll

// beforeForceChmod runs just before the fallback gives a directory
// u+rwx, with the directory's path; tests use it to swap the directory
// for a symlink at that moment.
var beforeForceChmod = func(string) {}

// removeAllForce removes root even when the tree holds directories
// without owner write or search permission (`go mod download` makes
// module directories 0555; a PoC can chmod what it writes). A plain
// RemoveAll comes first; if it fails, forceRemoveTree walks the tree,
// gives every real directory u+rwx and removes it. A symlink, including
// root itself, is removed as a link: nothing is ever chmodded or removed
// through one, even when a still-running writer swaps a directory for a
// link while the walk is under way (on Linux every step is relative to
// a directory fd opened with O_NOFOLLOW, and the chmod goes through
// that fd).
func removeAllForce(root string) error {
	fi, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return os.Remove(root)
	}
	if err := fastRemoveAll(root); err == nil {
		return nil
	}
	return forceRemoveTree(root)
}

// errnoText is the system error of a filesystem failure without its
// path, for logs that must not carry repository or report text.
func errnoText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		return le.Err.Error()
	}
	return "unknown error"
}

// checkProxy is the Runner's own check of the GOPROXY value, on top of
// config validation: one URL, never a list that could fall back to
// "direct", never the keywords direct or off, never file://.
func checkProxy(p string) error {
	switch {
	case p == "", strings.ContainsAny(p, ",|"), strings.IndexFunc(p, unicode.IsSpace) >= 0,
		p == "direct", p == "off", strings.HasPrefix(strings.ToLower(p), "file:"):
		return fmt.Errorf("goproxy must be a single proxy URL")
	}
	return config.ValidateGoProxy(p)
}

// resultLineRe matches a test result line of `-test.v` output.
var resultLineRe = regexp.MustCompile(`^--- (PASS|SKIP|FAIL): (\S+) \(`)

// passedAllRequested decides whether a test or fuzz run that exited 0
// really passed: every requested test (or the fuzz target) has its own
// top-level "--- PASS: <name>" line, and nothing requested, nor any of
// its subtests or seeds, was skipped. It returns "" when it passed,
// ReasonSkipped when something was skipped, ReasonNoTestsRan otherwise.
// A t.Skip ends with exit 0 and "PASS", which says nothing about the
// code. Program PoCs always pass here.
func passedAllRequested(p PoC, out []byte) string {
	var names []string
	switch p.Shape {
	case ShapeTest:
		names = p.TestNames
	case ShapeFuzz:
		names = []string{p.FuzzName}
	default:
		return ""
	}
	passed := map[string]bool{}
	for _, l := range splitLines(out) {
		if len(l) > maxLineBytes {
			continue
		}
		trimmed := strings.TrimLeft(l, " \t")
		m := resultLineRe.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		switch m[1] {
		case "SKIP":
			for _, n := range names {
				if m[2] == n || strings.HasPrefix(m[2], n+"/") {
					return ReasonSkipped
				}
			}
		case "PASS":
			if trimmed == l {
				passed[m[2]] = true
			}
		}
	}
	for _, n := range names {
		if !passed[n] {
			return ReasonNoTestsRan
		}
	}
	return ""
}
