// Package approvaltest has a fake clock and a fake approver for tests of
// the approval core and of the broker (DESIGN.md section 17). Only tests
// import it, so it is not part of the nodkey binary.
package approvaltest

import (
	"slices"
	"sync"
	"time"

	"github.com/code6x/nodkey/internal/approval"
)

// Clock is a fake approval.Clock. Its time moves only when Advance or
// JumpWall is called. It is safe for use by many goroutines.
type Clock struct {
	mu     sync.Mutex
	now    time.Time     // the monotonic clock
	wall   time.Duration // how far the wall clock is ahead of the monotonic one
	timers []*timer      // the timers that wait to fire
}

var _ approval.Clock = (*Clock)(nil)

// NewClock returns a fake clock whose two clocks start at start. The
// location of start is the broker's local time, for the "hours" and
// "max_per_day" of a "never ask" rule.
func NewClock(start time.Time) *Clock {
	return &Clock{now: start.Round(0)}
}

// Now returns the time of the monotonic clock.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Wall returns the time of the wall clock.
func (c *Clock) Wall() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now.Add(c.wall)
}

// JumpWall moves only the wall clock, by d, forward or back. So it acts as
// a host that slept for d (the monotonic clock stops then), or as a wall
// clock that someone set. No timer fires.
func (c *Clock) JumpWall(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wall += d
}

// TimerAt returns a timer that fires when the monotonic clock reaches t,
// or at once if it has.
func (c *Clock) TimerAt(t time.Time) approval.Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	tm := &timer{clock: c, when: t, ch: make(chan time.Time, 1)}
	if t.After(c.now) {
		c.timers = append(c.timers, tm)
	} else {
		tm.ch <- c.now
	}
	return tm
}

// Advance moves both clocks forward by d, and fires each timer that is
// due. A d that is not more than 0 does nothing: the monotonic clock never
// goes back.
func (c *Clock) Advance(d time.Duration) {
	if d <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	c.timers = slices.DeleteFunc(c.timers, func(t *timer) bool {
		if t.when.After(c.now) {
			return false
		}
		t.ch <- c.now // each timer fires once, so its channel has room
		return true
	})
}

// Timers returns how many timers wait to fire. A test can use it to see
// that the goroutines it started wait for the clock.
func (c *Clock) Timers() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}

type timer struct {
	clock *Clock
	when  time.Time
	ch    chan time.Time
}

func (t *timer) C() <-chan time.Time { return t.ch }

func (t *timer) Stop() {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	t.clock.timers = slices.DeleteFunc(t.clock.timers, func(o *timer) bool { return o == t })
}
