package approval

import "time"

// Clock is where the core gets the time. It has two clocks:
//
//   - Now is the monotonic clock. The core measures with it how long a
//     request waits, how long a grant or a pause lasts, and the limit per
//     minute. The real one is time.Now: Go compares two of its times on
//     the monotonic clock, so setting the wall clock does not move them.
//     But the monotonic clock stops while the host sleeps (suspend).
//   - Wall is the wall clock, in the broker's local time zone. The core
//     reads the time of day and the date from it, for the "hours" and
//     "max_per_day" of a "never ask" rule, and for the times in a message.
//
// A request and a grant end when either clock reaches their end. So a host
// that slept does not make them last longer, and neither does a wall clock
// that is set back.
//
// Tests use a fake clock, approvaltest.Clock.
type Clock interface {
	// Now returns the time of the monotonic clock. The core only compares
	// it with other times from Now.
	Now() time.Time
	// Wall returns the time of the wall clock, without a monotonic
	// reading, in the broker's local time zone.
	Wall() time.Time
	// TimerAt returns a timer that fires once, when Now reaches t. If Now
	// has reached t, it fires at once.
	TimerAt(t time.Time) Timer
}

// Timer is a timer from a Clock.
type Timer interface {
	// C returns the channel that gets a value when the timer fires.
	C() <-chan time.Time
	// Stop stops the timer, if it has not fired yet.
	Stop()
}

// realClock is the time package.
type realClock struct{}

func (realClock) Now() time.Time  { return time.Now() }
func (realClock) Wall() time.Time { return time.Now().Round(0) } // Round(0) drops the monotonic reading

func (realClock) TimerAt(t time.Time) Timer {
	// time.Until uses the monotonic reading of t, if t has one.
	return realTimer{time.NewTimer(time.Until(t))}
}

type realTimer struct{ t *time.Timer }

func (t realTimer) C() <-chan time.Time { return t.t.C }
func (t realTimer) Stop()               { t.t.Stop() }

// moment is a point in time on both clocks of a Clock.
type moment struct {
	mono time.Time // from Clock.Now
	wall time.Time // from Clock.Wall
}

// now returns the current moment.
func (c *Core) now() moment {
	return moment{mono: c.clock.Now(), wall: c.clock.Wall()}
}

// add returns m plus d on both clocks.
func (m moment) add(d time.Duration) moment {
	return moment{mono: m.mono.Add(d), wall: m.wall.Add(d)}
}

// before reports whether m comes before end on both clocks. So an end has
// come as soon as either clock reaches it.
func (m moment) before(end moment) bool {
	return m.mono.Before(end.mono) && m.wall.Before(end.wall)
}

// until returns the time from m to end on the clock that reaches end
// first.
func (m moment) until(end moment) time.Duration {
	return min(end.mono.Sub(m.mono), end.wall.Sub(m.wall))
}

// earlier returns the earlier of two ends, on each clock.
func earlier(a, b moment) moment {
	if b.mono.Before(a.mono) {
		a.mono = b.mono
	}
	if b.wall.Before(a.wall) {
		a.wall = b.wall
	}
	return a
}
