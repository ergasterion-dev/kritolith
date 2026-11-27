package sandbox

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strconv"
)

// Since Go 1.23 the linker refuses //go:linkname references to
// standard library symbols that are not on its allow list, and later
// releases shrink that list. An old claimed ref with an old dependency
// then stops linking under a new rootfs Go ("link: <package>: invalid
// reference to runtime.<symbol>"). The linker flag -checklinkname=0
// turns that one check off. A linker older than 1.23 does not know the
// flag and fails on it, so the flag is passed only when the rootfs Go
// is known to be 1.23 or newer.
const (
	// ldflagNoLinknameCheck is the only -ldflags value a sandbox build
	// passes. A -ldflags on the command line replaces one in GOFLAGS
	// (they are not merged), so any future linker flag must be joined
	// into this one value.
	ldflagNoLinknameCheck = "-ldflags=-checklinkname=0"

	// rootfsGoVersionFile is the release file of the rootfs's Go, as
	// the official images ship it. Its first line is "go1.27.4".
	rootfsGoVersionFile = "usr/local/go/VERSION"

	// goVersionBytes is how much of the version file is read.
	goVersionBytes = 64
)

// goReleaseRE matches the first line of a release's VERSION file:
// go1.27.4, go1.23, go1.23rc1, go1.24beta2.
var goReleaseRE = regexp.MustCompile(`^go([0-9]{1,3})\.([0-9]{1,3})(?:\.[0-9]{1,3}|(?:rc|beta)[0-9]{1,3})?$`)

// parseGoRelease reads the major and minor version from the start of a
// Go VERSION file. Only the first line counts. Anything that is not a
// release name (a development build, an empty or damaged file) is
// unknown: ok is false.
func parseGoRelease(b []byte) (major, minor int, ok bool) {
	line, _, _ := bytes.Cut(b, []byte("\n"))
	m := goReleaseRE.FindSubmatch(bytes.TrimSuffix(line, []byte("\r")))
	if m == nil {
		return 0, 0, false
	}
	major, err1 := strconv.Atoi(string(m[1]))
	minor, err2 := strconv.Atoi(string(m[2]))
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return major, minor, true
}

// rootfsLinknameCheckOff reports whether builds in this rootfs pass
// -checklinkname=0: its Go is a release, 1.23 or newer. A version file
// that is missing, unreadable, not a regular file or not a release
// name means false, which is the build command without the flag. It
// never fails: the rootfs is the operator's, and an unknown version
// must not stop a run.
func rootfsLinknameCheckOff(rootfs string) bool {
	b, err := readBounded(filepath.Join(rootfs, filepath.FromSlash(rootfsGoVersionFile)), goVersionBytes)
	if err != nil {
		return false
	}
	major, minor, ok := parseGoRelease(b)
	return ok && (major > 1 || (major == 1 && minor >= 23))
}
