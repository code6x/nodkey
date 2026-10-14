package config

import (
	"math"
	"testing"
	"time"
)

// TestParseRuleMaxPerDay checks that max_per_day, when it is in the file,
// is 1 or more. No limit means leaving it out, so 0 cannot be read as
// "no uses without a tap" by a person and as "no limit" by the broker.
func TestParseRuleMaxPerDay(t *testing.T) {
	const sec = "[secret.backup-token]"
	n := func(v int) *int { return &v }
	r, err := parseRule(sec, ruleKeys{Ask: "never"})
	if err != nil || r.MaxPerDay != 0 {
		t.Errorf("never without max_per_day = %+v, %v; want MaxPerDay 0 (no limit)", r, err)
	}
	for _, v := range []int{1, 2, 1000, math.MaxInt} {
		r, err := parseRule(sec, ruleKeys{Ask: "never", MaxPerDay: n(v)})
		if err != nil || r.MaxPerDay != v {
			t.Errorf("max_per_day = %d: %+v, %v; want MaxPerDay %d", v, r, err, v)
		}
	}
	for _, v := range []int{0, -1, math.MinInt} {
		r, err := parseRule(sec, ruleKeys{Ask: "never", MaxPerDay: n(v)})
		checkError(t, err, sec+" max_per_day: must be 1 or more; for no limit, leave max_per_day out", "")
		if r != (Rule{}) {
			t.Errorf("max_per_day = %d: rule %+v with the error, want none", v, r)
		}
	}
	// Only a "never" rule has a limit.
	window := "15m"
	for _, k := range []ruleKeys{{Ask: "always", MaxPerDay: n(1)}, {Ask: "window", Window: &window, MaxPerDay: n(1)}} {
		_, err := parseRule(sec, k)
		checkError(t, err, sec+" max_per_day: is not allowed with ask = ", "")
	}
}

// TestZeroRuleIsNoRule checks that the zero Ask, and so the zero Rule, is
// none of the three rules. Code that uses a rule denies any other Ask, so a
// Rule that LoadBroker did not make cannot open anything.
func TestZeroRuleIsNoRule(t *testing.T) {
	var zero Ask
	for _, a := range []Ask{AskAlways, AskWindow, AskNever} {
		if a == zero || a == (Rule{}).Ask {
			t.Errorf("the zero Ask is the rule %q", a)
		}
	}
	// parseRule never returns the zero Ask without an error.
	window := "15m"
	for _, k := range []ruleKeys{{}, {Ask: "always"}, {Ask: "window", Window: &window}, {Ask: "never"}, {Ask: "sometimes"}} {
		r, err := parseRule("[secret.x]", k)
		if err == nil && r.Ask == zero {
			t.Errorf("parseRule(%+v) = %+v with no error; want a rule with an Ask", k, r)
		}
		if err != nil && r != (Rule{}) {
			t.Errorf("parseRule(%+v): rule %+v with the error %v, want none", k, r, err)
		}
	}
}

// TestParseRuleWindow checks the bounds of a window: 1 minute to 8 hours.
// A shorter window would give grants of 0 whole minutes, so the rule would
// quietly act like "always".
func TestParseRuleWindow(t *testing.T) {
	const sec = "[secret.github-token]"
	for in, want := range map[string]time.Duration{"1m": time.Minute, "90s": 90 * time.Second, "15m": 15 * time.Minute, "8h": 8 * time.Hour} {
		r, err := parseRule(sec, ruleKeys{Ask: "window", Window: &in})
		if err != nil || r.Ask != AskWindow || r.Window != want {
			t.Errorf("window %q: %+v, %v; want a window of %v", in, r, err, want)
		}
	}
	for _, in := range []string{"0s", "1s", "59s", "59.999s", "-1m", "8h0m1s", "9h"} {
		r, err := parseRule(sec, ruleKeys{Ask: "window", Window: &in})
		checkError(t, err, sec+" window: must be at least 1m and at most 8h", "")
		if r != (Rule{}) {
			t.Errorf("window %q: rule %+v with the error, want none", in, r)
		}
	}
}

func TestParseHours(t *testing.T) {
	valid := []struct {
		in       string
		from, to time.Duration
	}{
		{"03:00-03:20", 3 * time.Hour, 3*time.Hour + 20*time.Minute},
		{"00:00-23:59", 0, 23*time.Hour + 59*time.Minute},
		{"23:30-00:30", 23*time.Hour + 30*time.Minute, 30 * time.Minute},
		{"12:00-00:00", 12 * time.Hour, 0},
	}
	for _, tt := range valid {
		h, err := parseHours(tt.in)
		if err != nil {
			t.Errorf("parseHours(%q): %v", tt.in, err)
			continue
		}
		if h.From != tt.from || h.To != tt.to {
			t.Errorf("parseHours(%q) = %v-%v, want %v-%v", tt.in, h.From, h.To, tt.from, tt.to)
		}
	}

	for _, in := range []string{
		"", "03:00", "3:00-3:20", "03:00-3:20", "03-04", "03:00-03:00",
		"24:00-01:00", "23:00-24:00", "03:60-04:00", "-01:00-02:00",
		"03:00 - 03:20", " 03:00-03:20", "03:00-03:20\n", "03:00:00-03:20:00",
		"０3:00-03:20", // a full-width digit
	} {
		if _, err := parseHours(in); err == nil {
			t.Errorf("parseHours(%q): got no error", in)
		}
	}
}

func TestHoursContains(t *testing.T) {
	at := func(hh, mm, ss, ns int) time.Time {
		return time.Date(2026, 10, 12, hh, mm, ss, ns, time.UTC)
	}
	short, err := parseHours("03:00-03:20")
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := parseHours("23:30-00:30")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		h    Hours
		t    time.Time
		want bool
	}{
		{"just before the start", short, at(2, 59, 59, 999999999), false},
		{"at the start", short, at(3, 0, 0, 0), true},
		{"inside", short, at(3, 10, 0, 0), true},
		{"just before the end", short, at(3, 19, 59, 999999999), true},
		{"at the end", short, at(3, 20, 0, 0), false},
		{"in the afternoon", short, at(15, 10, 0, 0), false},

		{"wrap: just before the start", wrap, at(23, 29, 59, 0), false},
		{"wrap: at the start", wrap, at(23, 30, 0, 0), true},
		{"wrap: before midnight", wrap, at(23, 59, 59, 0), true},
		{"wrap: at midnight", wrap, at(0, 0, 0, 0), true},
		{"wrap: after midnight", wrap, at(0, 29, 59, 0), true},
		{"wrap: at the end", wrap, at(0, 30, 0, 0), false},
		{"wrap: at noon", wrap, at(12, 0, 0, 0), false},

		// Hours not made by parseHours contain nothing.
		{"zero hours", Hours{}, at(0, 0, 0, 0), false},
		{"start equals end", Hours{From: time.Hour, To: time.Hour}, at(1, 0, 0, 0), false},
		{"negative start", Hours{From: -time.Hour, To: time.Hour}, at(0, 30, 0, 0), false},
		{"end after one day", Hours{From: time.Hour, To: 25 * time.Hour}, at(2, 0, 0, 0), false},
	}
	for _, tt := range tests {
		if got := tt.h.Contains(tt.t); got != tt.want {
			t.Errorf("%s: Contains(%s) = %v, want %v", tt.name, tt.t.Format("15:04:05.999999999"), got, tt.want)
		}
	}
}

func TestHoursContainsUsesTheTimeLocation(t *testing.T) {
	h, err := parseHours("03:00-03:20")
	if err != nil {
		t.Fatal(err)
	}
	// 00:10 UTC is 03:10 three hours east of UTC.
	utc := time.Date(2026, 10, 12, 0, 10, 0, 0, time.UTC)
	east := utc.In(time.FixedZone("UTC+3", 3*60*60))
	if h.Contains(utc) {
		t.Error("Contains(00:10 UTC) = true, want false")
	}
	if !h.Contains(east) {
		t.Error("Contains(03:10 UTC+3) = false, want true")
	}
}
