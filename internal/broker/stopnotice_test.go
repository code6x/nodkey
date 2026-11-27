package broker

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// Tests of the stop notice: one notice that lists the login pre-approvals
// that a stop dropped (DESIGN.md sections 8 and 15). Scheduled and standing
// grants are not dropped: the next start opens them again from the log.

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

// loginPreID asks for a login pre-approval, approves it and returns its
// grant ID.
func (l *loginTest) loginPreID(item, url string) string {
	l.t.Helper()
	res := l.loginPre(item, url)
	mustStatus(l.t, res, http.StatusOK)
	ans, err := api.ReadAnswer[api.PreapproveAnswer](bytes.NewReader(res.body))
	if err != nil {
		l.t.Fatalf("the answer: %v", err)
	}
	return ans.ID
}

// TestStopNoticeListsGrants: a stop sends one notice with the ID, client,
// login and uses left of each login pre-approval that it dropped, and not
// of one that ended before, nor of a scheduled grant, which stays.
func TestStopNoticeListsGrants(t *testing.T) {
	l := newLoginEnv(t, preapproveOn)
	c := l.laptp
	gone := l.loginPreID(itemShop, pageShop)
	if _, ok := l.core.CancelGrant("laptop", gone); !ok {
		t.Fatal("the grant was not there")
	}
	a := l.loginPreID(itemShop, pageShop)
	b := l.loginPreID(itemMail, pageShop)
	kept := l.preapprove(c, preReq(3, "github-token"), 4)
	before := len(l.audit.all())
	l.stopAndWait()
	sent := l.notices.wentOut()
	if len(sent) != 1 {
		t.Fatalf("%d notices, want 1: %q", len(sent), sent)
	}
	msg := sent[0]
	for _, want := range []string{
		"dropped 2 login pre-approval(s)",
		a + ": laptop, login web, 1 use(s) left",
		b + ": laptop, login web, 1 use(s) left",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("notice %q does not hold %q", msg, want)
		}
	}
	for _, id := range []string{gone, kept.ID} {
		if strings.Contains(msg, id) {
			t.Errorf("notice %q lists grant %s, which a stop did not drop", msg, id)
		}
	}
	// Two entries, both for the login pre-approvals, cause stopped.
	events := l.audit.waitFor(t, before+2)[before:]
	mustEvents(t, events, "grant_ended:stopped grant_ended:stopped")
	for _, ev := range events {
		if id := ev.(audit.GrantEnded).GrantID; id != a && id != b {
			t.Errorf("a stop ended grant %s", id)
		}
	}
}

// TestStopKeepsScheduledAndStanding: a stop writes no entry for a scheduled
// or a standing grant, and sends no notice: the next start opens them
// again from the log.
func TestStopKeepsScheduledAndStanding(t *testing.T) {
	e := newEnv(t, envOptions{config: func(cfg *config.Broker) { preapproveOn(cfg); standingOn(cfg) }})
	c := e.httpClient("laptop")
	e.preapprove(c, preReq(3, "github-token"), 1)
	e.preapprove(c, standReq("npm-token"), 2)
	before := len(e.audit.all())
	e.stopAndWait()
	if tries, _ := e.notices.tried(); len(tries) != 0 {
		t.Errorf("the stop tried a notice: %q", tries)
	}
	if got := e.audit.all()[before:]; len(got) != 0 {
		t.Errorf("the stop wrote entries: %+v", got)
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
	e := newLoginEnv(t, preapproveOn)
	mustStatus(t, e.loginPre(itemShop, pageShop), http.StatusOK)
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
	e := newLoginEnv(t, preapproveOn)
	c := e.laptp
	mustStatus(t, e.loginPre(itemShop, pageShop), http.StatusOK)
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
