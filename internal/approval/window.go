package approval

import "time"

// anyDay is the set of weekdays of a daily window: all seven.
const anyDay weekdays = 1<<7 - 1

// weekdays is a set of weekdays. Bit n is time.Weekday(n).
type weekdays uint8

// has reports whether d is in the set.
func (s weekdays) has(d time.Weekday) bool {
	return d >= time.Sunday && d <= time.Saturday && s&(1<<uint(d)) != 0
}

// window is a daily or weekly time of day in which a standing grant may be
// used (DESIGN.md section 8). It is read on the wall clock, in the time
// zone of that clock, as the "hours" of a rule are (section 12): the
// clock time decides, not the instant. So on the day the clocks go back, a
// window in the hour that comes twice opens twice, and on the day they
// go forward, a window in the skipped hour does not open. A window does not
// pass midnight: it needs from < to <= 24 hours.
type window struct {
	days     weekdays
	from, to time.Duration // time of day; to is not part of the window
}

// valid reports whether w can open. A window that is not valid never
// holds any time, so a mistake denies.
func (w window) valid() bool {
	return w.days != 0 && w.days&^anyDay == 0 && w.from >= 0 && w.from < w.to && w.to <= 24*time.Hour
}

// sinceMidnight returns the time of day that t shows on its own clock.
func sinceMidnight(t time.Time) time.Duration {
	hh, mm, ss := t.Clock()
	return time.Duration(hh)*time.Hour + time.Duration(mm)*time.Minute +
		time.Duration(ss)*time.Second + time.Duration(t.Nanosecond())
}

// holds reports whether t is inside w, read on t's own clock.
func (w window) holds(t time.Time) bool {
	if !w.valid() || !w.days.has(t.Weekday()) {
		return false
	}
	d := sinceMidnight(t)
	return w.from <= d && d < w.to
}

// windowKey names one opening of a window: the calendar date on the wall
// clock and the index of the window in the list of the grant. It is not an
// instant, so a window that opens twice on the day the clocks go back has
// one key, and one count of uses.
type windowKey struct {
	day   day
	index int
}

// after reports whether k is a later opening than o.
func (k windowKey) after(o windowKey) bool {
	if k.day != o.day {
		return k.day.after(o.day)
	}
	return k.index > o.index
}

// windowAt returns the first window of ws that holds t, with its key and
// the time left until the window ends, counted on the clock of t. ok is
// false if no window holds t.
func windowAt(ws []window, t time.Time) (key windowKey, left time.Duration, ok bool) {
	for i, w := range ws {
		if w.holds(t) {
			return windowKey{day: dayOf(t), index: i}, w.to - sinceMidnight(t), true
		}
	}
	return windowKey{}, 0, false
}

// useResult is what a try to use a grant gives. The broker turns the last
// two into alarms (DESIGN.md section 8).
type useResult int

const (
	// useOK: the use is taken.
	useOK useResult = iota
	// useNone: the grant cannot be used, for a reason that is no alarm:
	// it has not started or has ended, or it has no uses left in total.
	useNone
	// useOverUses: the grant is live and inside a window, but the uses
	// of this window are spent (cause over_uses).
	useOverUses
	// useOutsideWindow: the grant is live, but now is in none of its
	// windows (cause outside_window).
	useOutsideWindow
)
