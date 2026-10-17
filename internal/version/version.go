// Package version reads and compares versions of nodkey (DESIGN.md
// section 10). The client and the broker send each other their version
// in a header (api.VersionHeader). A value from the other side counts
// only if it has the form of a version (Valid); any other value counts as
// no version, and is never printed or logged. Only release versions
// (X.Y.Z) are compared, as numbers. A version of another form, such as
// "dev" or a commit, is a build from the source: Check reports nothing
// for it.
package version

import (
	"cmp"
	"regexp"
	"strconv"
	"strings"
)

// maxLen is the most bytes of a version.
const maxLen = 64

// pattern is the form of a version, such as "1.2.0", "v1.2.0-rc.1" or
// "dev". The audit log uses it for the broker_started entry too.
var pattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$`)

// Valid reports whether s has the form of a version: 1 to 64 letters,
// digits, ".", "+", "_" or "-", with a letter or a digit first. Such a
// value holds no space, no control character and no markup, so it is
// safe to print and to log. A value from the other side that is not
// valid counts as no version, and must never be printed or logged.
func Valid(s string) bool { return len(s) <= maxLen && pattern.MatchString(s) }

// maxDigits is the most digits of a number in a release version, so a
// number is at most 999999.
const maxDigits = 6

// Release is a release version: X.Y.Z.
type Release struct{ Major, Minor, Patch int }

// ParseRelease reads a release version: three numbers from 0 to 999999,
// each without leading zeros, separated by ".", and nothing else, such as
// "1.2.0". ok is false for any other text, such as "dev", "1.2",
// "1.02.0", "1.2.0-rc.1", "v1.2.0" or "1.2.0 ".
func ParseRelease(s string) (r Release, ok bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Release{}, false
	}
	var n [3]int
	for i, p := range parts {
		if p == "" || len(p) > maxDigits || len(p) > 1 && p[0] == '0' {
			return Release{}, false
		}
		for j := range len(p) {
			if p[j] < '0' || p[j] > '9' {
				return Release{}, false
			}
			n[i] = 10*n[i] + int(p[j]-'0')
		}
	}
	return Release{Major: n[0], Minor: n[1], Patch: n[2]}, true
}

// Compare returns -1 when r is older than o, 0 when they are the same,
// and +1 when r is newer. It compares the numbers, not the text: 1.10.0
// is newer than 1.9.0.
func (r Release) Compare(o Release) int {
	for _, d := range [3]int{r.Major - o.Major, r.Minor - o.Minor, r.Patch - o.Patch} {
		if d != 0 {
			return cmp.Compare(d, 0)
		}
	}
	return 0
}

// String returns the version as "X.Y.Z".
func (r Release) String() string {
	return strconv.Itoa(r.Major) + "." + strconv.Itoa(r.Minor) + "." + strconv.Itoa(r.Patch)
}

// Diff says how the version that the other side sent compares with the
// version of this side.
type Diff int

const (
	// NoDiff: there is nothing to say. Both sides run the same release,
	// or one of them is a build from the source.
	NoDiff Diff = iota
	// NotSent: this side runs a release, and the other side sent no
	// version, or a value that is not Valid. It may run an older nodkey
	// that does not send its version.
	NotSent
	// OtherOlder: the other side runs an older release than this side.
	OtherOlder
	// OtherNewer: the other side runs a newer release than this side.
	OtherNewer
)

// Check compares own, the version of this side, with other, the version
// that the other side sent ("" for none). When own is not a release, or
// other is a Valid version that is not a release, it returns NoDiff:
// builds from the source are not compared.
func Check(own, other string) Diff {
	mine, ok := ParseRelease(own)
	if !ok {
		return NoDiff
	}
	if !Valid(other) {
		return NotSent
	}
	theirs, ok := ParseRelease(other)
	if !ok {
		return NoDiff
	}
	switch theirs.Compare(mine) {
	case -1:
		return OtherOlder
	case 1:
		return OtherNewer
	}
	return NoDiff
}
