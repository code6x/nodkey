package version

import (
	"strings"
	"testing"
)

// TestValid: a version is 1 to 64 letters, digits, ".", "+", "_" or "-",
// with a letter or a digit first. Nothing else passes: no space, no
// control character, no markup, and nothing longer.
func TestValid(t *testing.T) {
	for _, s := range []string{
		"0.1.0", "1.2.0", "v1.2.0-rc.1", "dev", "1a2b3c4", "1.2.0+build.5", "x_y", "A",
		strings.Repeat("9", 64),
	} {
		if !Valid(s) {
			t.Errorf("Valid(%q) = false", s)
		}
	}
	for _, s := range []string{
		"", " ", "1.2.0 ", " 1.2.0", "1.2.0\n", "1.2.0\r\nX-Other: 1", "1.2.0\x00", "<b>1.2.0</b>", "1.2.0;rm",
		"1.2.0,1.3.0", "-1.2.0", ".1.2.0", "_dev", "+dev", "1.2.0/x", "d\u00e9v", "1.2.0\u202e", strings.Repeat("9", 65),
		strings.Repeat("a", 64<<10),
	} {
		if Valid(s) {
			t.Errorf("Valid(%q) = true", s)
		}
	}
}

// TestParseRelease: only X.Y.Z with numbers from 0 to 999999 and no
// leading zeros is a release. Everything else is not, so it is a build
// from the source, or not a version.
func TestParseRelease(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want Release
	}{
		{"0.0.0", Release{0, 0, 0}},
		{"0.1.0", Release{0, 1, 0}},
		{"1.2.3", Release{1, 2, 3}},
		{"10.20.30", Release{10, 20, 30}},
		{"999999.999999.999999", Release{999999, 999999, 999999}},
	} {
		got, ok := ParseRelease(tt.in)
		if !ok || got != tt.want {
			t.Errorf("ParseRelease(%q) = %v, %v; want %v", tt.in, got, ok, tt.want)
		}
		if got.String() != tt.in {
			t.Errorf("%v.String() = %q, want %q", got, got.String(), tt.in)
		}
	}
	for _, s := range []string{
		"", "dev", "1", "1.2", "1.2.3.4", "1..3", ".1.2", "1.2.", "01.2.3", "1.02.3", "1.2.03", "00.1.2",
		"1000000.0.0", "0.1000000.0", "0.0.1000000", "9999999999999999999999.0.0", "v1.2.3", "1.2.3-rc.1",
		"1.2.3+build", " 1.2.3", "1.2.3 ", "1.2.3\n", "+1.2.3", "-1.2.3", "1.-2.3", "1.2.x", "1.2.3a", "\u0661.\u0662.\u0663",
		"1.2.3\x00",
	} {
		if r, ok := ParseRelease(s); ok {
			t.Errorf("ParseRelease(%q) = %v, want no release", s, r)
		}
	}
}

// TestCompare: releases compare as numbers, not as text.
func TestCompare(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"0.1.0", "0.2.0", -1},
		{"0.2.0", "0.1.0", 1},
		{"1.9.0", "1.10.0", -1},
		{"1.10.0", "1.9.0", 1},
		{"2.0.0", "1.999999.999999", 1},
		{"1.2.3", "1.2.4", -1},
		{"1.3.0", "1.2.9", 1},
		{"0.0.9", "0.0.10", -1},
	} {
		a, okA := ParseRelease(tt.a)
		b, okB := ParseRelease(tt.b)
		if !okA || !okB {
			t.Fatalf("%q or %q is not a release", tt.a, tt.b)
		}
		if got := a.Compare(b); got != tt.want {
			t.Errorf("%s.Compare(%s) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

// TestCheck: only two releases are compared. A side that is a build from
// the source gives nothing to say; a release on this side and no valid
// version from the other gives NotSent.
func TestCheck(t *testing.T) {
	for _, tt := range []struct {
		own, other string
		want       Diff
	}{
		{"0.2.0", "0.2.0", NoDiff},
		{"0.2.0", "0.1.0", OtherOlder},
		{"0.2.0", "0.3.0", OtherNewer},
		{"1.9.0", "1.10.0", OtherNewer},
		{"0.2.0", "", NotSent},
		{"0.2.0", "0.1.0 x", NotSent},
		{"0.2.0", "<b>0.1.0</b>", NotSent},
		{"0.2.0", strings.Repeat("9", 65), NotSent},
		// Builds from the source, on either side.
		{"0.2.0", "dev", NoDiff},
		{"0.2.0", "1a2b3c4", NoDiff},
		{"0.2.0", "0.3.0-rc.1", NoDiff},
		{"0.2.0", "v0.3.0", NoDiff},
		{"dev", "0.1.0", NoDiff},
		{"dev", "", NoDiff},
		{"dev", "dev", NoDiff},
		{"", "0.1.0", NoDiff},
		{"", "", NoDiff},
		{"0.2.0 x", "0.1.0", NoDiff},
	} {
		if got := Check(tt.own, tt.other); got != tt.want {
			t.Errorf("Check(%q, %q) = %d, want %d", tt.own, tt.other, got, tt.want)
		}
	}
}
