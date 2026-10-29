package approval_test

// Tests of the warning before the end of a standing grant and of Renew
// (DESIGN.md section 8). The fake clock starts at noon on 2026-10-14; the
// window is 03:00-05:00 each day, the grant lasts 30 days, and warn_days
// is 7, so the warning comes at noon on 2026-11-06.

import (
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/approval/approvaltest"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/grantkey"
)

const day = 24 * time.Hour

// renewRec records the decision entries of Renew taps.
type renewRec struct {
	mu   sync.Mutex
	evs  []audit.Decision
	fail error
}

func (r *renewRec) add(ev audit.Decision) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return r.fail
	}
	r.evs = append(r.evs, ev)
	return nil
}

func (r *renewRec) all() []audit.Decision {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]audit.Decision(nil), r.evs...)
}

// renewEnv starts a core with one standing grant of laptop. It returns the
// token and the result of the grant.
func renewEnv(t *testing.T, edit ...func(*config.Broker)) (*env, grantkey.Token, *approval.Result, *renewRec, *endedRecorder) {
	t.Helper()
	e := standEnv(t, edit...)
	rec, ended := &renewRec{}, &endedRecorder{}
	e.core.OnRenewed(rec.add)
	e.core.OnGrantEnded(ended.add)
	tok := newToken(t)
	res := e.grant(standReq("laptop", tok, "github-token"), 1)
	return e, tok, res, rec, ended
}

// warning waits for the one warning and returns it.
func (e *env) warning() approvaltest.Warned {
	e.t.Helper()
	w := e.fake.Warnings()
	if len(w) != 1 {
		e.t.Fatalf("%d warnings, want 1", len(w))
	}
	return w[0]
}

// renewTap presses Renew on the warning w, as the approver.
func (e *env) renewTap(w approvaltest.Warned) error {
	return e.fake.Answer(approval.Answer{RequestID: w.Warning.RequestID, Action: audit.AnswerRenew,
		Message: w.Message, UserID: approverID})
}

// use uses a standing grant of laptop with tok and returns the result.
func (e *env) use(tok grantkey.Token) *approval.Result {
	h := grantkey.Hash(tok)
	return e.core.UseStanding(approval.StandingRequest{Client: "laptop", Secrets: []string{"github-token"}, Token: &h})
}

func alarmOf(res *approval.Result) audit.AlarmCause {
	for _, ev := range res.Events() {
		if a, ok := ev.(audit.GrantAlarm); ok {
			return a.Cause
		}
	}
	return ""
}

func TestWarningOnceBeforeTheEnd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, _, res, _, _ := renewEnv(t)
		defer e.stop()
		e.pass(23*day - time.Minute)
		if n := len(e.fake.Warnings()); n != 0 {
			t.Fatalf("%d warnings before warn_days", n)
		}
		e.pass(2 * time.Minute)
		w := e.warning().Warning
		if w.RequestID != res.RequestID || w.GrantID != res.GrantID || w.Client != "laptop" || w.Uses != 2 ||
			len(w.Secrets) != 1 || w.Secrets[0] != "github-token" || len(w.Windows) != 1 ||
			w.Windows[0] != "daily 03:00-05:00" || !w.End.Equal(noon.Add(30*day)) || w.ShortCode == "" {
			t.Errorf("warning %+v", w)
		}
		e.pass(day)
		e.pass(5 * day)
		if n := len(e.fake.Warnings()); n != 1 {
			t.Errorf("%d warnings, want one", n)
		}
	})
}

func TestWarningSendFailsNotRepeated(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, _, _, _, _ := renewEnv(t)
		defer e.stop()
		e.fake.FailWarn(errors.New("telegram is down"))
		e.pass(23*day + time.Minute)
		e.fake.FailWarn(nil)
		e.pass(day)
		if n := len(e.fake.Warnings()); n != 0 {
			t.Errorf("%d warnings: a grant gets one try", n)
		}
	})
}

func TestNoWarningForAShortGrant(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := standEnv(t)
		defer e.stop()
		r := standReq("laptop", newToken(t), "github-token")
		r.NotAfter = noon.Add(7 * day) // not longer than warn_days
		e.grant(r, 1)
		e.pass(8 * day)
		if n := len(e.fake.Warnings()); n != 0 {
			t.Errorf("%d warnings for a grant of 7 days", n)
		}
	})
}

func TestNoWarningAfterTheGrantEnded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, _, res, _, _ := renewEnv(t)
		defer e.stop()
		e.pass(day)
		if _, ok := e.core.CancelGrant("laptop", res.GrantID); !ok {
			t.Fatal("cannot cancel the grant")
		}
		e.pass(30 * day)
		if n := len(e.fake.Warnings()); n != 0 {
			t.Errorf("%d warnings for an ended grant", n)
		}
	})
}

// TestRenewHandsOverOnTheNextUse: Renew writes its entry and makes a new
// grant with no token. The next use of the old token gets a token of the
// new grant, and the old grant ends with cause renewed. The old token used
// again is an old_token alarm, which ends the new grant.
func TestRenewHandsOverOnTheNextUse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, tok, old, rec, ended := renewEnv(t)
		defer e.stop()
		e.pass(23*day + time.Minute) // noon on 2026-11-06
		w := e.warning()
		at := e.clock.Wall()
		if err := e.renewTap(w); err != nil {
			t.Fatalf("Renew: %v", err)
		}
		synctest.Wait()
		evs := rec.all()
		if len(evs) != 1 {
			t.Fatalf("%d renew entries", len(evs))
		}
		d := evs[0]
		end := at.Add(30 * day).Truncate(time.Second)
		if d.Answer != audit.AnswerRenew || d.RenewOf != old.GrantID || d.GrantID == "" || d.GrantID == old.GrantID ||
			d.RequestID == old.RequestID || d.Kind != audit.KindStanding || d.UserID != approverID ||
			d.NotAfter != end.UTC().Format(time.RFC3339) || len(d.Secrets) != 1 || d.Uses != 2 || len(d.Windows) != 1 {
			t.Errorf("renew entry %+v", d)
		}
		// The warning now carries the Revoke button of the new grant.
		var hold *approvaltest.Ended
		for _, u := range e.fake.Ended() {
			if u.Message == w.Message {
				hold = &u
			}
		}
		if hold == nil || !hold.Ending.Revoke || hold.Prompt.RequestID != d.RequestID || !hold.Prompt.Until.Equal(end) {
			t.Errorf("the warning message was not given the new grant: %+v", hold)
		}
		if err := e.renewTap(w); !errors.Is(err, approval.ErrUnknownRequest) {
			t.Errorf("a second Renew: %v, want ErrUnknownRequest", err)
		}
		if n := len(ended.all()); n != 0 {
			t.Fatalf("%d ended entries before the handover", n)
		}

		e.pass(15*time.Hour + 30*time.Minute) // 03:30 on 2026-11-07
		res := e.use(tok)
		checkAllowed(t, res)
		next, ok := res.NewToken()
		if !ok {
			t.Fatal("no new token")
		}
		var used audit.GrantUsed
		for _, ev := range res.Events() {
			if u, ok := ev.(audit.GrantUsed); ok {
				used = u
			}
		}
		if used.GrantID != d.GrantID || used.Via != audit.ViaStanding {
			t.Errorf("the use names %+v, want the new grant", used)
		}
		synctest.Wait()
		got := ended.all()
		if len(got) != 1 || got[0].Cause != audit.EndRenewed || got[0].GrantID != old.GrantID {
			t.Fatalf("ended entries %+v; want the old grant, renewed", got)
		}
		if h, _, _, _ := e.core.StandingGrants("laptop"); len(h) != 1 || h[0] != grantkey.Hash(next) {
			t.Error("the new grant must hold the new token")
		}
		// The second use in the same window still counts toward the window.
		next = e.useGrant(next)
		if r := e.use(next); r.Allowed || alarmOf(r) != audit.AlarmOverUses {
			t.Errorf("a third use in the window: allowed %v, alarm %q", r.Allowed, alarmOf(r))
		}
	})
}

func TestOldTokenAfterRenewalIsAnAlarm(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, tok, _, rec, ended := renewEnv(t)
		defer e.stop()
		e.pass(23*day + time.Minute)
		if err := e.renewTap(e.warning()); err != nil {
			t.Fatal(err)
		}
		e.pass(15*time.Hour + 30*time.Minute)
		_ = e.useGrant(tok)
		res := e.use(tok)
		if res.Allowed || alarmOf(res) != audit.AlarmOldToken {
			t.Fatalf("the old token again: allowed %v, alarm %q", res.Allowed, alarmOf(res))
		}
		var alarmEnd []audit.GrantEnded
		for _, ev := range res.Events() {
			if g, ok := ev.(audit.GrantEnded); ok {
				alarmEnd = append(alarmEnd, g)
			}
		}
		if len(alarmEnd) != 1 || alarmEnd[0].Cause != audit.EndAlarm || alarmEnd[0].GrantID != rec.all()[0].GrantID {
			t.Errorf("the alarm ended %+v; want the new grant", alarmEnd)
		}
		if h, _, _, _ := e.core.StandingGrants("laptop"); len(h) != 0 {
			t.Error("a grant is left after the alarm")
		}
		_ = ended
	})
}

// TestRenewHandsOverAtTheOldEnd: with no use before the old grant's end,
// the old token passes to the new grant at that end.
func TestRenewHandsOverAtTheOldEnd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, tok, old, rec, ended := renewEnv(t)
		defer e.stop()
		e.pass(23*day + time.Minute)
		if err := e.renewTap(e.warning()); err != nil {
			t.Fatal(err)
		}
		e.pass(7 * day) // past the old end
		got := ended.all()
		if len(got) != 1 || got[0].Cause != audit.EndRenewed || got[0].GrantID != old.GrantID {
			t.Fatalf("ended entries %+v", got)
		}
		e.pass(15*time.Hour + 30*time.Minute) // 03:30
		res := e.use(tok)
		checkAllowed(t, res)
		var used audit.GrantUsed
		for _, ev := range res.Events() {
			if u, ok := ev.(audit.GrantUsed); ok {
				used = u
			}
		}
		if used.GrantID != rec.all()[0].GrantID {
			t.Errorf("the use names grant %q, want the new grant", used.GrantID)
		}
	})
}

// TestRevokeOfARenewedGrantEndsTheRenewal: the renewal has no token of its
// own, so it ends with its grant.
func TestRevokeOfARenewedGrantEndsTheRenewal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, tok, _, _, ended := renewEnv(t)
		defer e.stop()
		e.pass(23*day + time.Minute)
		if err := e.renewTap(e.warning()); err != nil {
			t.Fatal(err)
		}
		e.tap(1, audit.AnswerRevoke)
		synctest.Wait()
		got := ended.all()
		if len(got) != 2 || got[0].Cause != audit.EndRevoked || got[1].Cause != audit.EndRevoked {
			t.Fatalf("ended entries %+v; want both revoked", got)
		}
		e.pass(15*time.Hour + 30*time.Minute)
		if res := e.use(tok); res.Allowed {
			t.Error("the token works after Revoke")
		}
	})
}

func TestRenewRefused(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, _, old, rec, _ := renewEnv(t)
		defer e.stop()
		// No warning yet: no Renew.
		ans := approval.Answer{RequestID: old.RequestID, Action: audit.AnswerRenew, Message: e.fake.Asked()[0].Message, UserID: approverID}
		if err := e.fake.Answer(ans); !errors.Is(err, approval.ErrWrongMessage) {
			t.Errorf("Renew before the warning: %v", err)
		}
		e.pass(23*day + time.Minute)
		w := e.warning()
		tests := []struct {
			name string
			ans  approval.Answer
			want error
		}{
			{"another user", approval.Answer{RequestID: w.Warning.RequestID, Action: audit.AnswerRenew, Message: w.Message, UserID: approverID + 1}, approval.ErrNotApprover},
			{"no user", approval.Answer{RequestID: w.Warning.RequestID, Action: audit.AnswerRenew, Message: w.Message}, approval.ErrNotApprover},
			{"another message", approval.Answer{RequestID: w.Warning.RequestID, Action: audit.AnswerRenew, Message: e.fake.Asked()[0].Message, UserID: approverID}, approval.ErrWrongMessage},
			{"another chat", approval.Answer{RequestID: w.Warning.RequestID, Action: audit.AnswerRenew, Message: "other:" + w.Message, UserID: approverID}, approval.ErrWrongMessage},
			{"an unknown request", approval.Answer{RequestID: w.Warning.GrantID, Action: audit.AnswerRenew, Message: w.Message, UserID: approverID}, approval.ErrUnknownRequest},
		}
		for _, tt := range tests {
			if err := e.fake.Answer(tt.ans); !errors.Is(err, tt.want) {
				t.Errorf("%s: %v, want %v", tt.name, err, tt.want)
			}
		}
		// The entry cannot be written: no new grant.
		rec.mu.Lock()
		rec.fail = errors.New("disk full")
		rec.mu.Unlock()
		if err := e.renewTap(w); !errors.Is(err, approval.ErrNotAllowed) {
			t.Errorf("Renew without its entry: %v", err)
		}
		if n := len(e.core.ListStanding()); n != 1 {
			t.Errorf("%d grants listed", n)
		}
		if h, _, _, _ := e.core.StandingGrants("laptop"); len(h) != 1 {
			t.Errorf("%d grants after a failed Renew, want 1", len(h))
		}
		if n := len(rec.all()); n != 0 {
			t.Errorf("%d entries", n)
		}
		// An ended grant cannot be renewed.
		if _, ok := e.core.CancelGrant("laptop", old.GrantID); !ok {
			t.Fatal("cannot cancel")
		}
		rec.mu.Lock()
		rec.fail = nil
		rec.mu.Unlock()
		synctest.Wait()
		var last approval.Ending
		for _, u := range e.fake.Ended() {
			if u.Message == w.Message {
				last = u.Ending
			}
		}
		if last.GrantEnd != audit.EndCancelled || last.Revoke {
			t.Errorf("the warning was not updated at the end of its grant: %+v", last)
		}
		if err := e.renewTap(w); !errors.Is(err, approval.ErrUnknownRequest) {
			t.Errorf("Renew of an ended grant: %v", err)
		}
		if n := len(rec.all()); n != 0 {
			t.Errorf("%d entries", n)
		}
	})
}

func TestRenewKeepsToMaxDaysAndMaxGrants(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, _, _, rec, _ := renewEnv(t)
		defer e.stop()
		e.pass(23*day + time.Minute)
		w := e.warning()
		e.cfg.Standing.MaxGrants = 0 // as if the client had too many
		if err := e.renewTap(w); !errors.Is(err, approval.ErrNotAllowed) {
			t.Errorf("Renew over max_grants: %v", err)
		}
		e.cfg.Standing.MaxGrants = 1
		e.cfg.Standing.MaxDays = 10
		at := e.clock.Wall()
		if err := e.renewTap(w); err != nil {
			t.Fatal(err)
		}
		evs := rec.all()
		if len(evs) != 1 || evs[0].NotAfter != at.Add(10*day).Truncate(time.Second).UTC().Format(time.RFC3339) {
			t.Errorf("renew entries %+v; want an end after max_days", evs)
		}
		// The renewal takes the place of its grant: a client at max_grants
		// stays there.
		if n := len(e.core.ListStanding()); n != 1 {
			t.Errorf("%d grants listed, want 1", n)
		}
	})
}
