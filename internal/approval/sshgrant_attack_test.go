package approval_test

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/code6x/nodkey/internal/approval/approvaltest"
	"github.com/code6x/nodkey/internal/audit"
)

// The format of a time of day in a message (as in package telegram): the
// part of a second is cut, not rounded.
const shownClock = "15:04:05"

// TestSSHGrantEndsAtTheShownSecond: a request for an SSH grant comes at
// 12:00:00.7, with --for 15m. The message shows that the grants end at
// 12:15:00, so they end then, and not at 12:15:00.7. (From the security
// review of issue #14: a login at 12:15:00.5 was still signed.)
func TestSSHGrantEndsAtTheShownSecond(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg, h := testConfig(t)
		e := newEnvWith(t, cfg, h, approvaltest.NewClock(noon.Add(700*time.Millisecond)))
		defer e.stop()
		ch := e.decide(grantReq("laptop", "deploy", "deploy", 15*time.Minute, "web-1"))
		mustWait(t, ch)
		p := e.asked(1)[0].Prompt
		ends := noon.Add(15 * time.Minute)
		if !p.GrantEnds.Equal(ends) || p.GrantEnds.Format(shownClock) != "12:15:00" {
			t.Fatalf("the grants end at %s; want exactly %s, the second that the message shows",
				p.GrantEnds.Format("15:04:05.000"), ends.Format("15:04:05.000"))
		}
		e.tap(1, audit.AnswerApproveWindow)
		r := mustResult(t, ch)
		checkAllowed(t, r)
		r.StartGrants()

		e.clock.Advance(ends.Add(-100 * time.Millisecond).Sub(e.clock.Now())) // 12:14:59.9
		checkAllowed(t, e.now(loginReq("laptop", "deploy", h.web1, "deploy")))
		e.clock.Advance(100 * time.Millisecond) // 12:15:00.0: the end shown
		e.needsTap(loginReq("laptop", "deploy", h.web1, "deploy"), 2)
	})
}

// TestWindowGrantEndsAtAWholeSecond: the same for "Approve 15 min". The
// person taps at 12:00:00.7, and the message then shows "approved for 15
// min by you at 12:00:00". So the grant ends at 12:15:00, not later.
func TestWindowGrantEndsAtAWholeSecond(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg, h := testConfig(t)
		e := newEnvWith(t, cfg, h, approvaltest.NewClock(noon.Add(700*time.Millisecond)))
		defer e.stop()
		e.approveWindow(secretsReq("laptop", "github-token"), 1)
		ended := e.fake.Ended()
		if len(ended) != 1 || ended[0].Ending.At.Format(shownClock) != "12:00:00" ||
			ended[0].Ending.WindowMinutes != 15 {
			t.Fatalf("the message after the tap shows %+v; want 15 min at 12:00:00", ended)
		}
		ends := noon.Add(15 * time.Minute)
		e.clock.Advance(ends.Add(-100 * time.Millisecond).Sub(e.clock.Now())) // 12:14:59.9
		checkAllowed(t, e.now(secretsReq("laptop", "github-token")))
		e.clock.Advance(100 * time.Millisecond) // 12:15:00.0
		e.needsTap(secretsReq("laptop", "github-token"), 2)
	})
}
