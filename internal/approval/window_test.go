package approval

import (
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/audit"
)

func mustZone(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Skipf("no zone data for %s: %v", name, err)
	}
	return loc
}

func hm(h, m int) time.Duration { return time.Duration(h)*time.Hour + time.Duration(m)*time.Minute }

func TestWindowHolds(t *testing.T) {
	utc := time.UTC
	// 2026-10-26 is a Monday.
	daily := window{days: anyDay, from: hm(3, 0), to: hm(5, 0)}
	monThu := window{days: 1<<time.Monday | 1<<time.Thursday, from: hm(3, 0), to: hm(5, 0)}
	tests := []struct {
		name string
		w    window
		at   time.Time
		want bool
	}{
		{"daily before the start", daily, time.Date(2026, 10, 26, 2, 59, 59, 0, utc), false},
		{"daily at the start", daily, time.Date(2026, 10, 26, 3, 0, 0, 0, utc), true},
		{"daily inside", daily, time.Date(2026, 10, 27, 4, 30, 0, 0, utc), true},
		{"daily last second", daily, time.Date(2026, 10, 26, 4, 59, 59, 0, utc), true},
		{"daily at the end", daily, time.Date(2026, 10, 26, 5, 0, 0, 0, utc), false},
		{"weekly monday", monThu, time.Date(2026, 10, 26, 4, 0, 0, 0, utc), true},
		{"weekly tuesday", monThu, time.Date(2026, 10, 27, 4, 0, 0, 0, utc), false},
		{"weekly thursday", monThu, time.Date(2026, 10, 29, 4, 0, 0, 0, utc), true},
		{"weekly sunday", monThu, time.Date(2026, 10, 25, 4, 0, 0, 0, utc), false},
		{"no days", window{from: hm(3, 0), to: hm(5, 0)}, time.Date(2026, 10, 26, 4, 0, 0, 0, utc), false},
		{"end before start", window{days: anyDay, from: hm(5, 0), to: hm(3, 0)}, time.Date(2026, 10, 26, 4, 0, 0, 0, utc), false},
		{"empty", window{days: anyDay, from: hm(3, 0), to: hm(3, 0)}, time.Date(2026, 10, 26, 3, 0, 0, 0, utc), false},
		{"past a day", window{days: anyDay, from: hm(3, 0), to: hm(25, 0)}, time.Date(2026, 10, 26, 4, 0, 0, 0, utc), false},
		{"unknown day bit", window{days: 1 << 7, from: hm(3, 0), to: hm(5, 0)}, time.Date(2026, 10, 26, 4, 0, 0, 0, utc), false},
		{"the whole day", window{days: anyDay, from: 0, to: 24 * time.Hour}, time.Date(2026, 10, 26, 23, 59, 59, 0, utc), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.w.holds(tt.at); got != tt.want {
				t.Errorf("holds(%s) = %v, want %v", tt.at, got, tt.want)
			}
		})
	}
}

func TestWindowAtLeftAndIndex(t *testing.T) {
	ws := []window{
		{days: anyDay, from: hm(1, 0), to: hm(2, 0)},
		{days: anyDay, from: hm(3, 0), to: hm(5, 0)},
	}
	at := time.Date(2026, 10, 26, 4, 0, 0, 0, time.UTC)
	key, left, ok := windowAt(ws, at)
	if !ok || key.index != 1 || left != time.Hour || key.day != dayOf(at) {
		t.Errorf("windowAt = %v, %v, %v", key, left, ok)
	}
	if _, _, ok := windowAt(ws, at.Add(2*time.Hour)); ok {
		t.Error("windowAt found a window at 06:00")
	}
	if _, _, ok := windowAt(nil, at); ok {
		t.Error("windowAt found a window in no windows")
	}
}

func TestWindowSummerTime(t *testing.T) {
	berlin := mustZone(t, "Europe/Berlin")
	w := window{days: anyDay, from: hm(2, 30), to: hm(2, 50)}
	// 2026-10-25: the clocks go back at 03:00 CEST to 02:00 CET, so 02:30
	// comes twice.
	first := time.Date(2026, 10, 25, 0, 30, 0, 0, time.UTC).In(berlin)  // 02:30 CEST
	second := time.Date(2026, 10, 25, 1, 30, 0, 0, time.UTC).In(berlin) // 02:30 CET
	if first.Hour() != 2 || second.Hour() != 2 || first.Equal(second) {
		t.Fatalf("setup: %s %s", first, second)
	}
	k1, _, ok1 := windowAt([]window{w}, first)
	k2, _, ok2 := windowAt([]window{w}, second)
	if !ok1 || !ok2 || k1 != k2 {
		t.Errorf("a window that opens twice must have one key: %v %v %v %v", k1, ok1, k2, ok2)
	}
	// 2026-03-29: the clocks go forward at 02:00 CET to 03:00 CEST, so
	// 02:30 never shows.
	for _, utc := range []time.Time{
		time.Date(2026, 3, 29, 0, 59, 59, 0, time.UTC),
		time.Date(2026, 3, 29, 1, 0, 0, 0, time.UTC),
		time.Date(2026, 3, 29, 1, 30, 0, 0, time.UTC),
	} {
		if _, _, ok := windowAt([]window{w}, utc.In(berlin)); ok {
			t.Errorf("a window in the skipped hour opened at %s", utc.In(berlin))
		}
	}
	// A window after the change opens at its clock time.
	w2 := window{days: anyDay, from: hm(3, 0), to: hm(4, 0)}
	if _, _, ok := windowAt([]window{w2}, time.Date(2026, 3, 29, 1, 0, 0, 0, time.UTC).In(berlin)); !ok {
		t.Error("03:00 CEST must be inside 03:00-04:00")
	}
}

func standingGrant(ws []window, per int, end time.Time) *grant {
	return &grant{
		kind: kindStanding, id: "g1", client: "web-1", uses: noLimit,
		windows: ws, perWindow: per,
		end: moment{mono: end, wall: end},
	}
}

// at makes a moment on both clocks from the wall time t.
func at(t time.Time) moment { return moment{mono: t, wall: t} }

func TestGrantKinds(t *testing.T) {
	tests := []struct {
		kind                       grantKind
		scheduled, standing, audit bool
	}{
		{kindWindow, false, false, false},
		{kindScheduled, true, false, true},
		{kindStanding, false, true, true},
	}
	for _, tt := range tests {
		g := &grant{kind: tt.kind, id: "x"} // an id does not decide the kind
		if g.scheduled() != tt.scheduled || g.standing() != tt.standing || g.audited() != tt.audit {
			t.Errorf("kind %d: scheduled=%v standing=%v audited=%v", tt.kind, g.scheduled(), g.standing(), g.audited())
		}
	}
	if (&grant{id: "x"}).audited() {
		t.Error("a grant with an id but the zero kind must be a window grant")
	}
	if (&grant{}).kind != kindWindow {
		t.Error("the zero kind must be window")
	}
}

func TestStandingLiveAndUse(t *testing.T) {
	utc := time.UTC
	end := time.Date(2026, 11, 30, 0, 0, 0, 0, utc)
	g := standingGrant([]window{{days: anyDay, from: hm(3, 0), to: hm(5, 0)}}, 2, end)
	day := func(d, h, m int) moment { return at(time.Date(2026, 11, d, h, m, 0, 0, utc)) }

	tests := []struct {
		name string
		now  moment
		live bool
		use  useResult
	}{
		{"outside", day(1, 2, 0), false, useOutsideWindow},
		{"first use", day(1, 3, 0), true, useOK},
		{"second use", day(1, 4, 0), true, useOK},
		{"third use is over", day(1, 4, 30), true, useOverUses},
		{"over again", day(1, 4, 31), true, useOverUses},
		{"after the window", day(1, 5, 0), false, useOutsideWindow},
		{"next day resets", day(2, 3, 0), true, useOK},
		{"next day second", day(2, 3, 1), true, useOK},
		{"next day over", day(2, 3, 2), true, useOverUses},
		{"at the end date", at(end.Add(0)), false, useNone},
		{"after the end date", at(end.Add(3 * time.Hour)), false, useNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := g.live(tt.now); got != tt.live {
				t.Errorf("live = %v, want %v", got, tt.live)
			}
			if got := g.tryUse(tt.now); got != tt.use {
				t.Errorf("tryUse = %v, want %v", got, tt.use)
			}
		})
	}
}

func TestStandingUseNotYetStartedAndNoWindows(t *testing.T) {
	utc := time.UTC
	end := time.Date(2026, 11, 30, 0, 0, 0, 0, utc)
	w := []window{{days: anyDay, from: 0, to: 24 * time.Hour}}
	g := standingGrant(w, 1, end)
	g.start = time.Date(2026, 11, 10, 0, 0, 0, 0, utc)
	if g.live(at(time.Date(2026, 11, 9, 12, 0, 0, 0, utc))) || g.tryUse(at(time.Date(2026, 11, 9, 12, 0, 0, 0, utc))) != useOutsideWindow {
		t.Error("a grant before its start must not be live, and a use is outside the windows")
	}
	// No windows: live, but never usable as a standing grant (fail closed).
	n := standingGrant(nil, 1, end)
	if n.tryUse(at(time.Date(2026, 11, 9, 12, 0, 0, 0, utc))) != useNone {
		t.Error("a standing grant without windows must not be used")
	}
	// An invalid window never holds.
	bad := standingGrant([]window{{days: anyDay, from: hm(5, 0), to: hm(3, 0)}}, 1, end)
	if bad.live(at(time.Date(2026, 11, 9, 4, 0, 0, 0, utc))) {
		t.Error("a grant with an invalid window must not be live")
	}
}

func TestStandingClockSetBackGivesNoUses(t *testing.T) {
	utc := time.UTC
	end := time.Date(2026, 11, 30, 0, 0, 0, 0, utc)
	g := standingGrant([]window{{days: anyDay, from: hm(3, 0), to: hm(5, 0)}}, 1, end)
	if g.tryUse(at(time.Date(2026, 11, 2, 3, 0, 0, 0, utc))) != useOK {
		t.Fatal("first use")
	}
	// The wall clock goes back to the day before: that opening is earlier
	// than the counted one, so it keeps the count.
	if got := g.tryUse(at(time.Date(2026, 11, 1, 3, 0, 0, 0, utc))); got != useOverUses {
		t.Errorf("tryUse after a clock set back = %v, want over uses", got)
	}
}

func TestStandingUseAcrossTheDayTheClocksGoBack(t *testing.T) {
	berlin := mustZone(t, "Europe/Berlin")
	end := time.Date(2026, 12, 1, 0, 0, 0, 0, berlin)
	g := standingGrant([]window{{days: anyDay, from: hm(2, 30), to: hm(2, 50)}}, 1, end)
	first := time.Date(2026, 10, 25, 0, 30, 0, 0, time.UTC).In(berlin)
	second := time.Date(2026, 10, 25, 1, 30, 0, 0, time.UTC).In(berlin)
	if g.tryUse(moment{mono: first, wall: first}) != useOK {
		t.Fatal("first use")
	}
	if got := g.tryUse(moment{mono: second, wall: second}); got != useOverUses {
		t.Errorf("second opening of the same window: %v, want over uses", got)
	}
	next := time.Date(2026, 10, 26, 2, 30, 0, 0, berlin)
	if got := g.tryUse(moment{mono: next, wall: next}); got != useOK {
		t.Errorf("next day: %v, want ok", got)
	}
}

func TestGiveBackUse(t *testing.T) {
	end := time.Date(2026, 11, 30, 0, 0, 0, 0, time.UTC)
	g := standingGrant([]window{{days: anyDay, from: 0, to: 24 * time.Hour}}, 1, end)
	now := at(time.Date(2026, 11, 2, 3, 0, 0, 0, time.UTC))
	if g.tryUse(now) != useOK || g.tryUse(now) != useOverUses {
		t.Fatal("setup")
	}
	g.giveBackUse()
	if g.tryUse(now) != useOK {
		t.Error("a use given back must be usable again")
	}
	s := &grant{kind: kindScheduled, uses: 1}
	s.giveBackUse()
	if s.uses != 2 {
		t.Errorf("scheduled uses = %d, want 2", s.uses)
	}
}

func TestDenyKeepsStandingGrants(t *testing.T) {
	now := time.Date(2026, 11, 2, 4, 0, 0, 0, time.UTC)
	c := &Core{clock: &manualClock{now: now}}
	r := ref{name: "db-password"}
	mk := func(kind grantKind) *grant {
		return &grant{kind: kind, id: "g", client: "web-1", refs: []ref{r}, uses: noLimit,
			end: moment{mono: now.Add(time.Hour), wall: now.Add(time.Hour)}}
	}
	for _, tt := range []struct {
		kind grantKind
		kept bool
	}{
		{kindWindow, false}, {kindScheduled, false}, {kindStanding, true},
	} {
		c.grants = []*grant{mk(tt.kind)}
		cs := &clientState{paused: map[ref]time.Time{}, denied: map[ref]uint64{}}
		p := &pending{client: "web-1", items: []item{{ref: r}}}
		res := &Result{}
		c.deny(cs, p, res, c.now(), 1)
		if kept := len(c.grants) == 1; kept != tt.kept {
			t.Errorf("kind %d: kept = %v, want %v", tt.kind, kept, tt.kept)
		}
		if tt.kind == kindStanding && len(res.ended) != 0 {
			t.Error("a Deny wrote an end entry for a standing grant")
		}
		if tt.kind == kindScheduled && (len(res.ended) != 1 || res.ended[0].Cause != audit.EndDenied) {
			t.Errorf("scheduled: ended = %v", res.ended)
		}
	}
}

func TestNextEndWakesAtTheEndOfTheWindow(t *testing.T) {
	berlin := mustZone(t, "Europe/Berlin")
	now := time.Date(2026, 11, 2, 4, 0, 0, 0, berlin)
	clock := &manualClock{now: now}
	c := &Core{clock: clock}
	end := now.Add(30 * 24 * time.Hour)
	c.grants = []*grant{
		{kind: kindWindow, end: moment{mono: now.Add(time.Minute), wall: now.Add(time.Minute)}}, // not audited: ignored
		standingGrant([]window{{days: anyDay, from: hm(3, 0), to: hm(5, 0)}}, 1, end),
	}
	next, ok := c.nextEnd()
	if !ok || !next.Equal(now.Add(time.Hour)) {
		t.Errorf("nextEnd = %v, %v; want the window end %v", next, ok, now.Add(time.Hour))
	}
	clock.now = time.Date(2026, 11, 2, 6, 0, 0, 0, berlin) // outside: the end date
	next, ok = c.nextEnd()
	if !ok || !next.Equal(end) {
		t.Errorf("nextEnd outside = %v, %v; want %v", next, ok, end)
	}
	c.grants = c.grants[:1]
	if _, ok := c.nextEnd(); ok {
		t.Error("nextEnd must ignore window grants")
	}
}
