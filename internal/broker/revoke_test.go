package broker

import (
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
