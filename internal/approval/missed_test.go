package approval_test

// Tests of the missed-window alarm of standing grants (DESIGN.md section
// 8). The fake clock starts at noon on 2026-10-14; the window is 03:00-05:00
// each day, and the grant lasts 30 days.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/grantkey"
)

// missedEnv starts a core with one standing grant and collects the entries
// of the alarms.
func missedEnv(t *testing.T) (*env, grantkey.Token, func() []audit.GrantAlarm) {
	t.Helper()
	e := standEnv(t)
	var mu sync.Mutex
	var got []audit.GrantAlarm
	e.core.OnGrantAlarm(func(ev audit.GrantAlarm) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, ev)
	})
	tok := newToken(t)
	e.grant(standReq("laptop", tok, "github-token"), 1)
	return e, tok, func() []audit.GrantAlarm {
		mu.Lock()
		defer mu.Unlock()
		return append([]audit.GrantAlarm(nil), got...)
	}
}

func (e *env) pass(d time.Duration) {
	e.t.Helper()
	e.clock.Advance(d)
	synctest.Wait()
}

// useGrant uses the grant with tok and returns the next token.
func (e *env) useGrant(tok grantkey.Token) grantkey.Token {
	e.t.Helper()
	h := grantkey.Hash(tok)
	res := e.core.UseStanding(approval.StandingRequest{Client: "laptop", Secrets: []string{"github-token"}, Token: &h})
	checkAllowed(e.t, res)
	next, ok := res.NewToken()
	if !ok {
		e.t.Fatal("no new token")
	}
	if err := res.SendNotice(context.Background()); err != nil {
		e.t.Fatal(err)
	}
	return next
}

func TestMissedWindowAlarm(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, _, entries := missedEnv(t)
		defer e.stop()
		// The window of the day before the grant started, and the time up
		// to 03:00, give nothing.
		e.pass(14*time.Hour + 59*time.Minute)
		if n := len(e.fake.Alarms()); n != 0 {
			t.Fatalf("%d alarms before the first window ended", n)
		}
		e.pass(2*time.Hour + time.Minute) // 05:00 on 2026-10-15 passed with no use
		al := e.fake.Alarms()
		if len(al) != 1 {
			t.Fatalf("%d alarms, want 1", len(al))
		}
		a := al[0]
		if a.Cause != audit.AlarmMissedWindow || a.Ended || a.Client != "laptop" || a.GrantID == "" ||
			len(a.Secrets) != 1 || a.Secrets[0] != "github-token" {
			t.Errorf("alarm %+v", a)
		}
		ev := entries()
		if len(ev) != 1 || ev[0].Cause != audit.AlarmMissedWindow || ev[0].GrantID != a.GrantID || ev[0].Client != "laptop" {
			t.Errorf("entries %+v", ev)
		}
		if h, _, _, _ := e.core.StandingGrants("laptop"); len(h) != 1 {
			t.Error("the grant must stay after the alarm")
		}
		// At most one for the window, however often the core looks again.
		e.pass(time.Hour)
		e.pass(10 * time.Hour)
		if n := len(e.fake.Alarms()); n != 1 {
			t.Errorf("%d alarms for one window", n)
		}
		// The next window gives its own.
		e.pass(24 * time.Hour)
		if n := len(e.fake.Alarms()); n != 2 {
			t.Errorf("%d alarms after two windows, want 2", n)
		}
	})
}

func TestNoMissedAlarmAfterAUsedWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, tok, entries := missedEnv(t)
		defer e.stop()
		e.pass(15*time.Hour + 30*time.Minute) // 03:30 on 2026-10-15
		tok = e.useGrant(tok)
		e.pass(2 * time.Hour) // 05:30: the window ended with a use
		if n := len(e.fake.Alarms()); n != 0 {
			t.Errorf("%d alarms after a used window", n)
		}
		// The next day is not used, and does alarm: the use of one day
		// does not cover the next.
		e.pass(24 * time.Hour)
		if n := len(e.fake.Alarms()); n != 1 {
			t.Errorf("%d alarms for the unused next window, want 1", n)
		}
		_ = tok
		if n := len(entries()); n != 1 {
			t.Errorf("%d entries", n)
		}
	})
}

func TestMissedAlarmGivenBackUseStillMissed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, tok, _ := missedEnv(t)
		defer e.stop()
		e.pass(15*time.Hour + 30*time.Minute)
		h := grantkey.Hash(tok)
		res := e.core.UseStanding(approval.StandingRequest{Client: "laptop", Secrets: []string{"github-token"}, Token: &h})
		checkAllowed(t, res)
		res.Undo() // the use did not happen
		e.pass(2 * time.Hour)
		if n := len(e.fake.Alarms()); n != 1 {
			t.Errorf("%d alarms, want 1: an undone use is no use", n)
		}
	})
}

func TestMissedAlarmSendFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, _, entries := missedEnv(t)
		defer e.stop()
		e.fake.FailAlarm(errors.New("telegram is down"))
		e.pass(17*time.Hour + time.Minute)
		if n := len(e.fake.Alarms()); n != 0 {
			t.Errorf("%d alarms sent although the send fails", n)
		}
		if n := len(entries()); n != 1 {
			t.Errorf("%d entries, want 1: the audit entry is written first", n)
		}
		if h, _, _, _ := e.core.StandingGrants("laptop"); len(h) != 1 {
			t.Error("the grant must stay after a failed send")
		}
		// No second try for that window; the next window works.
		e.fake.FailAlarm(nil)
		e.pass(time.Hour)
		if n := len(e.fake.Alarms()); n != 0 {
			t.Errorf("%d alarms: the window must not be tried again", n)
		}
		e.pass(24 * time.Hour)
		if n := len(e.fake.Alarms()); n != 1 {
			t.Errorf("%d alarms for the next window, want 1", n)
		}
	})
}

func TestNoMissedAlarmAfterTheGrantEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, _, _ := missedEnv(t)
		defer e.stop()
		for range 31 {
			e.pass(24 * time.Hour)
		}
		// The windows up to the end date alarm; none after it.
		n := len(e.fake.Alarms())
		if n < 29 || n > 30 {
			t.Errorf("%d alarms over 30 days", n)
		}
		e.pass(5 * 24 * time.Hour)
		if m := len(e.fake.Alarms()); m != n {
			t.Errorf("%d alarms after the end, was %d", m, n)
		}
	})
}
