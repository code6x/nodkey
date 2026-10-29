package broker

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/approval/approvaltest"
	"github.com/code6x/nodkey/internal/audit"
)

// warned moves the clock to the day after the warning of the one standing
// grant of useEnv (it ends at 2026-11-14, warn_days is 7; the clock then
// reads 12:00, inside the daily window) and waits for the warning.
func (e *env) warned() approvaltest.Warned {
	e.t.Helper()
	e.clock.Advance(24 * 24 * time.Hour)
	deadline := time.Now().Add(waitLimit)
	for {
		if w := e.approver.Warnings(); len(w) > 0 {
			return w[0]
		}
		if time.Now().After(deadline) {
			e.t.Fatal("no warning before the end of the standing grant")
		}
		time.Sleep(time.Millisecond)
	}
}

// renewTap presses Renew on the warning w and returns what the core said.
func (e *env) renewTap(w approvaltest.Warned) error {
	return e.approver.Answer(approval.Answer{RequestID: w.Warning.RequestID, Action: audit.AnswerRenew,
		Message: w.Message, UserID: approverID})
}

// TestStandingRenew: a Renew tap goes through the broker's OnRenewed hook.
// Its decision entry is written first, the next use of the old token gets
// a token of the new grant, and the old grant ends as renewed.
func TestStandingRenew(t *testing.T) {
	e, tok0, oldID := useEnv(t)
	w := e.warned()
	if w.Warning.GrantID != oldID {
		t.Fatalf("the warning is for grant %q, want %q", w.Warning.GrantID, oldID)
	}
	if err := e.renewTap(w); err != nil {
		t.Fatalf("the Renew tap: %v", err)
	}
	// A missed window may add an alarm entry; look for the Renew entry.
	var at int
	var d audit.Decision
	for at = 0; ; at++ {
		events := e.audit.waitFor(t, at+1)
		if x, ok := events[at].(audit.Decision); ok && x.Answer == audit.AnswerRenew {
			d = x
			break
		}
	}
	if d.RenewOf != oldID || d.Kind != audit.KindStanding || d.GrantID == "" || d.GrantID == oldID {
		t.Fatalf("the Renew entry is %+v, renew_of %q", d.Subject, d.RenewOf)
	}
	for _, ev := range e.audit.all()[:at] {
		if g, ok := ev.(audit.GrantEnded); ok && g.GrantID == oldID {
			t.Fatalf("the old grant ended before the Renew entry: %s", g.Cause)
		}
	}
	newID, before := d.GrantID, at+1
	res, ans := e.useToken("laptop", tok0)
	mustStatus(t, res, http.StatusOK)
	tok1 := ans.GrantToken
	if tok1 == "" || tok1 == tok0 {
		t.Fatal("the use did not return a new token")
	}
	var ended, used = -1, -1
	all := e.audit.all()
	for i, ev := range all[before:] {
		switch x := ev.(type) {
		case audit.GrantEnded:
			if x.GrantID == oldID && x.Cause == audit.EndRenewed {
				ended = before + i
			}
		case audit.GrantUsed:
			if x.GrantID == newID && x.NewTokenHash == hashHex(tok1) {
				used = before + i
			}
		}
	}
	if ended < 0 || used < 0 {
		t.Fatalf("after the use: grant_ended:renewed at %d, grant_used of the new grant at %d: %s",
			ended, used, eventNames(all))
	}
	// The new token works for the new grant.
	res, _ = e.useToken("laptop", tok1)
	mustStatus(t, res, http.StatusOK)
	// The old token is not valid any more.
	res, _ = e.useToken("laptop", tok0)
	mustStatus(t, res, http.StatusForbidden)
	e.noToken(tok0, tok1)
}

// TestStandingRenewAfterRevoke: a Renew tap after the old grant was
// revoked is refused, and no new grant or entry comes of it.
func TestStandingRenewAfterRevoke(t *testing.T) {
	e, tok0, oldID := useEnv(t)
	w := e.warned()
	e.tap(w.Warning.RequestID, audit.AnswerRevoke)
	for at := 0; ; at++ {
		if g, ok := e.audit.waitFor(t, at+1)[at].(audit.GrantEnded); ok && g.GrantID == oldID && g.Cause == audit.EndRevoked {
			break
		}
	}
	before := len(e.audit.all())
	err := e.renewTap(w)
	if !errors.Is(err, approval.ErrUnknownRequest) {
		t.Errorf("the Renew tap after the revoke: %v, want ErrUnknownRequest", err)
	}
	for _, ev := range e.audit.all() {
		if d, ok := ev.(audit.Decision); ok && d.Answer == audit.AnswerRenew {
			t.Errorf("a Renew entry was written: %+v", d.Subject)
		}
	}
	res, _ := e.useToken("laptop", tok0)
	mustStatus(t, res, http.StatusForbidden)
	for _, ev := range e.audit.all()[before:] {
		if _, ok := ev.(audit.GrantUsed); ok {
			t.Error("the token of a revoked grant was used")
		}
	}
}
