package broker

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/audit"
)

// Tests of the stop notice: one notice that lists the scheduled grants that
// a stop dropped (DESIGN.md sections 8 and 15).

// stopAndWait stops Run, as nodkey broker does, and waits until it returned.
func (e *env) stopAndWait() {
	e.t.Helper()
	e.stopRun()
	select {
	case err := <-e.runErr:
		_ = err
		e.runErr <- nil // the cleanup waits for it
	case <-time.After(waitLimit):
		e.t.Fatal("Run did not return")
	}
}

// TestStopNoticeListsGrants: a stop sends one notice with the ID, client,
// secret and uses left of each grant that it dropped, and not of one that
// ended before.
func TestStopNoticeListsGrants(t *testing.T) {
	e := newEnv(t, envOptions{config: preapproveOn})
	c := e.httpClient("laptop")
	a := e.preapprove(c, preReq(3, "github-token"), 1)
	b := e.preapprove(c, preReq(2, "npm-token"), 2)
	gone := e.preapprove(c, preReq(1, "github-token"), 3)
	if _, ok := e.core.CancelGrant("laptop", gone.ID); !ok {
		t.Fatal("the grant was not there")
	}
	e.stopAndWait()
	sent := e.notices.wentOut()
	if len(sent) != 1 {
		t.Fatalf("%d notices, want 1: %q", len(sent), sent)
	}
	msg := sent[0]
	for _, want := range []string{
		"dropped 2 scheduled grant(s)",
		a.ID + ": laptop, github-token, 3 use(s) left",
		b.ID + ": laptop, npm-token, 2 use(s) left",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("notice %q does not hold %q", msg, want)
		}
	}
	if strings.Contains(msg, gone.ID) {
		t.Errorf("notice %q lists a grant that ended before the stop", msg)
	}
}

// TestStopNoticeNoGrants: a stop with no grant sends no notice.
func TestStopNoticeNoGrants(t *testing.T) {
	e := newEnv(t, envOptions{config: preapproveOn})
	c := e.httpClient("laptop")
	g := e.preapprove(c, preReq(1, "github-token"), 1)
	e.clock.Advance(2 * time.Hour) // the grant ends by itself
	e.audit.waitFor(t, 3)
	_ = g
	e.stopAndWait()
	if tries, _ := e.notices.tried(); len(tries) != 0 {
		t.Errorf("tries %q, want none", tries)
	}
}

// TestStopNoticeTelegramSilent: when Telegram does not answer, the stop
// waits only as long as the time limit of the notice, and logs it.
func TestStopNoticeTelegramSilent(t *testing.T) {
	old := stopNoticeTimeout
	stopNoticeTimeout = 100 * time.Millisecond
	t.Cleanup(func() { stopNoticeTimeout = old })
	e := newEnv(t, envOptions{config: preapproveOn})
	c := e.httpClient("laptop")
	e.preapprove(c, preReq(1, "github-token"), 1)
	e.notices.set(func(n *noticeLog) { n.gate = make(chan struct{}) }) // never opens
	start := time.Now()
	e.stopAndWait()
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("the stop took %v", d)
	}
	tries, _ := e.notices.tried()
	if len(tries) != 1 || len(e.notices.wentOut()) != 0 {
		t.Errorf("tries %q, sent %q", tries, e.notices.wentOut())
	}
	if !strings.Contains(e.logs.String(), "cannot send the stop notice") {
		t.Error("the broker did not log the notice that did not go out")
	}
}

// TestStopDeniesBeforeTheNoticeGoesOut: while the stop notice waits for
// Telegram, the broker already denies every request, also one that a grant
// would allow.
func TestStopDeniesBeforeTheNoticeGoesOut(t *testing.T) {
	old := stopNoticeTimeout
	stopNoticeTimeout = 3 * time.Second
	t.Cleanup(func() { stopNoticeTimeout = old })
	e := newEnv(t, envOptions{config: preapproveOn})
	c := e.httpClient("laptop")
	e.preapprove(c, preReq(1, "github-token"), 1)
	// A grant of "Approve 5 min" for another secret.
	p := e.start(c, api.PathSecrets, secretsRequest("NPM_TOKEN", "npm-token"))
	e.tap(e.waitAsked(2)[1].Prompt.RequestID, audit.AnswerApproveWindow)
	mustStatus(t, p.wait(t), http.StatusOK)
	e.notices.set(func(n *noticeLog) { n.gate = make(chan struct{}) }) // never opens
	e.stopRun()
	deadline := time.Now().Add(waitLimit)
	for tries, _ := e.notices.tried(); len(tries) == 0; tries, _ = e.notices.tried() {
		if time.Now().After(deadline) {
			t.Fatal("the stop notice was not tried")
		}
		time.Sleep(time.Millisecond)
	}
	res := e.post(t.Context(), c, api.PathSecrets, secretsRequest("NPM_TOKEN", "npm-token"))
	if res.status == http.StatusOK {
		t.Error("the grant allowed a request while the broker stopped")
	}
	e.stopAndWait()
}
