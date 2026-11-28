package broker

import (
	"strings"
	"testing"

	"github.com/code6x/nodkey/internal/audit"
)

// TestPreapproveRevoke: a Revoke tap ends the grant and writes one
// grant_ended entry with cause revoked. A later tap writes nothing.
func TestPreapproveRevoke(t *testing.T) {
	e := newEnv(t, envOptions{config: preapproveOn})
	c := e.httpClient("laptop")
	g := e.preapprove(c, preReq(2, "github-token"), 1)
	before := len(e.audit.all())
	id := e.waitAsked(1)[0].Prompt.RequestID
	e.tap(id, audit.AnswerRevoke)
	events := e.audit.waitFor(t, before+1)[before:]
	mustEvents(t, events, "grant_ended:revoked")
	end := events[0].(audit.GrantEnded)
	if end.GrantID != g.ID || end.UsesLeft != 2 || end.RequestID != id {
		t.Errorf("entry %+v", end)
	}
	if err := e.approver.Tap(id, audit.AnswerRevoke); err == nil {
		t.Error("a second Revoke counted")
	}
	if got := len(e.audit.all()); got != before+1 {
		t.Errorf("%d entries, want %d", got, before+1)
	}
}

// TestRevokeAll: RevokeAll ends a scheduled grant with a grant_ended
// entry (cause revoked) and sends one alert that says who asked.
func TestRevokeAll(t *testing.T) {
	e := newEnv(t, envOptions{config: preapproveOn})
	c := e.httpClient("laptop")
	g := e.preapprove(c, preReq(2, "github-token"), 1)
	before := len(e.audit.all())
	n, err := e.svc.RevokeAll("a test")
	if err != nil || n != 1 {
		t.Fatalf("RevokeAll = %d, %v; want 1, nil", n, err)
	}
	events := e.audit.waitFor(t, before+1)[before:]
	mustEvents(t, events, "grant_ended:revoked")
	if end := events[0].(audit.GrantEnded); end.GrantID != g.ID || end.UsesLeft != 2 {
		t.Errorf("entry %+v", end)
	}
	waitLog(t, e.alerts, "Every grant ended (a test): 1 grant(s)")
	if n, err := e.svc.RevokeAll("a test"); err != nil || n != 0 {
		t.Errorf("a second RevokeAll = %d, %v; want 0, nil", n, err)
	}
}

// TestRevokeAllBeforeRun: before Run the service has no core; RevokeAll
// ends nothing, says how to fix it, and writes no entry.
func TestRevokeAllBeforeRun(t *testing.T) {
	e := newEnv(t, envOptions{config: preapproveOn, noRun: true})
	before := len(e.audit.all())
	n, err := e.svc.RevokeAll("a test")
	if err == nil || n != 0 || !strings.Contains(err.Error(), "nodkey revoke --all again") {
		t.Fatalf("RevokeAll = %d, %v; want 0 and an error with the fix", n, err)
	}
	if got := len(e.audit.all()); got != before {
		t.Errorf("%d entries, want %d", got, before)
	}
}
