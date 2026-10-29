package approval_test

import (
	"testing"
	"testing/synctest"
	"time"
)

// TestWeeklySummary: with a fake clock, the summary comes once a week on
// Monday at 09:00 (the default), lists the live grants, and says nothing
// else on the way. An empty list is sent too.
func TestWeeklySummary(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := standEnv(t) // starts Wednesday 2026-10-14 12:00
		defer e.stop()
		e.pass(4*24*time.Hour + 20*time.Hour + 59*time.Minute) // Monday 08:59
		if n := len(e.fake.Summaries()); n != 0 {
			t.Fatalf("%d summaries before the time", n)
		}
		e.pass(time.Minute) // Monday 2026-10-19 09:00
		if s := e.fake.Summaries(); len(s) != 1 || len(s[0]) != 0 {
			t.Fatalf("summaries: %+v", s)
		}
		e.pass(time.Hour)
		if n := len(e.fake.Summaries()); n != 1 {
			t.Fatalf("%d summaries one hour later, want 1", n)
		}
		e.grant(standReq("laptop", newToken(t), "github-token"), 1)
		e.pass(7*24*time.Hour - time.Hour) // Monday 2026-10-26 09:00
		s := e.fake.Summaries()
		if len(s) != 2 || len(s[1]) != 1 || s[1][0].Client != "laptop" {
			t.Fatalf("summaries: %+v", s)
		}
	})
}

// TestNoSummaryWithoutStanding: a config without [standing] sends none.
func TestNoSummaryWithoutStanding(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		e.pass(15 * 24 * time.Hour)
		if n := len(e.fake.Summaries()); n != 0 {
			t.Errorf("%d summaries without [standing]", n)
		}
	})
}

// TestSummaryNotRepeatedAfterClockSetBack: a wall clock set back past the
// time does not send the same summary again.
func TestSummaryNotRepeatedAfterClockSetBack(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := standEnv(t)
		defer e.stop()
		e.pass(4*24*time.Hour + 21*time.Hour) // Monday 09:00
		if n := len(e.fake.Summaries()); n != 1 {
			t.Fatalf("%d summaries, want 1", n)
		}
		e.clock.JumpWall(-2 * time.Hour)
		e.pass(3 * time.Hour)
		if n := len(e.fake.Summaries()); n != 1 {
			t.Errorf("%d summaries after the clock was set back, want 1", n)
		}
	})
}
