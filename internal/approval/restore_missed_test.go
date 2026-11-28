package approval_test

// Tests of the windows and ends that passed while the broker was stopped
// (DESIGN.md section 8, "Windows missed while stopped").

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
)

// alarmLog collects the grant_alarm entries of e.
func alarmLog(e *env) func() []audit.GrantAlarm {
	var mu sync.Mutex
	var got []audit.GrantAlarm
	e.core.OnGrantAlarm(func(ev audit.GrantAlarm) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, ev)
	})
	return func() []audit.GrantAlarm {
		synctest.Wait()
		mu.Lock()
		defer mu.Unlock()
		return append([]audit.GrantAlarm(nil), got...)
	}
}

// TestRestoreMissedWindow: a window of a standing grant that ended while
// the broker was stopped, with no use, raises the missed-window alarm
// after Restore. The window that was used before the stop, and one that
// has not ended, raise nothing.
func TestRestoreMissedWindow(t *testing.T) {
	// The broker stopped at 03:30 on 2026-10-15, in a window it used, and
	// starts at 05:01 on 2026-10-16: the window of 2026-10-16 was missed.
	synctest.Test(t, func(t *testing.T) {
		log, id, _, _ := standingLog(t)
		e := standEnv(t)
		defer e.stop()
		entries := alarmLog(e)
		e.pass(41*time.Hour + time.Minute)
		if open, _, err := e.core.Restore(log.recs, log.recs[len(log.recs)-2].Seq); err != nil || len(open) != 1 {
			t.Fatalf("Restore = %+v, %v; want the standing grant", open, err)
		}
		got := entries()
		if len(got) != 1 || got[0].Cause != audit.AlarmMissedWindow || got[0].Subject.GrantID != id {
			t.Fatalf("alarm entries %+v; want one missed_window of the grant", got)
		}
		al := e.fake.Alarms()
		if len(al) != 1 || al[0].Cause != audit.AlarmMissedWindow || al[0].GrantID != id || al[0].ShortCode == "" ||
			al[0].Client != "laptop" || len(al[0].Secrets) != 1 || al[0].Secrets[0] != "github-token" {
			t.Fatalf("alarms %+v; want one missed-window alarm with a short code", al)
		}
	})
	// The broker starts at 03:45 in the window it used: the end of that
	// window raises nothing; the next window, with no use, does.
	synctest.Test(t, func(t *testing.T) {
		log, _, _, _ := standingLog(t)
		e := standEnv(t)
		defer e.stop()
		entries := alarmLog(e)
		e.pass(15*time.Hour + 45*time.Minute)
		if open, _, _ := e.core.Restore(log.recs, log.recs[len(log.recs)-2].Seq); len(open) != 1 {
			t.Fatal("no grant")
		}
		e.pass(time.Hour + 16*time.Minute) // 05:01
		if got := entries(); len(got) != 0 {
			t.Fatalf("alarm entries %+v after the used window; want none", got)
		}
		e.pass(24 * time.Hour)
		if got := entries(); len(got) != 1 || got[0].Cause != audit.AlarmMissedWindow {
			t.Fatalf("alarm entries %+v after a window with no use; want one", got)
		}
	})
	// A window that ended before the last entry was the old broker's to
	// scan: it raises nothing again.
	synctest.Test(t, func(t *testing.T) {
		log, _, _, _ := standingLog(t)
		last := log.recs[len(log.recs)-1]
		last.Time = noon.Add(42 * time.Hour) // stopped at 06:00 on 2026-10-16
		log.recs[len(log.recs)-1] = last
		e := standEnv(t)
		defer e.stop()
		entries := alarmLog(e)
		e.pass(43 * time.Hour)
		if open, _, _ := e.core.Restore(log.recs, log.recs[len(log.recs)-2].Seq); len(open) != 1 {
			t.Fatal("no grant")
		}
		if got := entries(); len(got) != 0 {
			t.Fatalf("alarm entries %+v for a window before the stop; want none", got)
		}
	})
}

// TestRestoreNotUsed: a scheduled grant whose end passed while the broker
// was stopped, with uses left, gets the "not used" notice after Restore.
// One whose end has not passed, or that ended before the stop, gets none.
func TestRestoreNotUsed(t *testing.T) {
	notUsed := func(e *env) []approval.Prompt {
		synctest.Wait()
		var out []approval.Prompt
		for _, n := range e.fake.Notices() {
			if n.GrantID != "" {
				out = append(out, n)
			}
		}
		return out
	}
	synctest.Test(t, func(t *testing.T) {
		log, id := restoreEnv(t)
		e := preEnv(t)
		defer e.stop()
		e.clock.Advance(3 * time.Hour)
		open, dropped, err := e.core.Restore(log.recs, log.seqOf(t, isDecision))
		if err != nil || len(open) != 0 || len(dropped) != 1 || dropped[0].Reason != approval.DropEnded {
			t.Fatalf("Restore = %+v, %+v, %v; want the grant dropped as ended", open, dropped, err)
		}
		got := notUsed(e)
		if len(got) != 1 {
			t.Fatalf("%d not used notices, want 1", len(got))
		}
		n := got[0]
		if n.GrantID != id || n.UsesLeft != 2 || n.Uses != 3 || n.Client != "laptop" || n.Kind != audit.KindPreapprove ||
			n.ShortCode == "" || n.Once || !n.Expires.IsZero() || len(n.Secrets) != 1 || n.Secrets[0] != "github-token" ||
			!n.From.Equal(noon) || !n.Until.Equal(noon.Add(2*time.Hour)) || n.Claim != (approval.Claim{}) {
			t.Errorf("notice %+v", n)
		}
		if u := e.fake.Ended(); len(u) != 0 {
			t.Errorf("%d message updates; want none, the message is not known", len(u))
		}
	})
	synctest.Test(t, func(t *testing.T) {
		log, _ := restoreEnv(t)
		e := preEnv(t)
		defer e.stop()
		e.clock.Advance(time.Hour)
		if open, _, _ := e.core.Restore(log.recs, log.seqOf(t, isDecision)); len(open) != 1 {
			t.Fatal("no grant")
		}
		if got := notUsed(e); len(got) != 0 {
			t.Errorf("%d not used notices before the end, want 0", len(got))
		}
	})
	synctest.Test(t, func(t *testing.T) {
		log, id := restoreEnv(t)
		log.add(audit.GrantEnded{Subject: audit.Subject{RequestID: log.recs[0].Event.(audit.Request).RequestID, GrantID: id,
			Client: "laptop", Kind: audit.KindPreapprove}, Cause: audit.EndRevoked})
		e := preEnv(t)
		defer e.stop()
		e.clock.Advance(3 * time.Hour)
		if open, dropped, _ := e.core.Restore(log.recs, log.seqOf(t, isDecision)); len(open)+len(dropped) != 0 {
			t.Fatalf("Restore = %+v, %+v; want nothing", open, dropped)
		}
		if got := notUsed(e); len(got) != 0 {
			t.Errorf("%d not used notices for a revoked grant, want 0", len(got))
		}
	})
}
