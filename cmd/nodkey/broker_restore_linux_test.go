package main

import (
	"net/http"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
)

// restoreNotice is the start of the notice after a start that opened
// grants from before again.
const restoreNotice = "grant(s) from before are open again"

// restart stops the broker with SIGTERM, as systemd does, and starts it
// again on the same files. It returns the journal of the run that ended:
// e.stderr has only the journal of the new run.
func (e *brokerEnv) restart() string {
	e.t.Helper()
	e.signal(syscall.SIGTERM)
	e.mustExit(exitOK)
	journal := e.stderr.text()
	e.start()
	e.stderr.wait(e.t, lineListening)
	return journal
}

// githubSecrets is a /secrets request for github-token.
var githubSecrets = api.SecretsRequest{
	Secrets: []api.SecretRef{{Var: "GH_TOKEN", Name: "github-token"}}, Reason: "job nightly-backup",
}

// mustAskAndDeny sends a /secrets request for github-token that the
// broker must ask for, taps Deny, and checks that it is refused.
func (e *brokerEnv) mustAskAndDeny(c *http.Client) {
	e.t.Helper()
	mustStatus(e.t, e.answerWith(c, api.PathSecrets, githubSecrets, "d:"), http.StatusForbidden)
}

// TestBrokerScheduledGrantSurvivesRestart: a scheduled pre-approval with
// two uses is used once, the broker stops and starts again, and the one
// use left still works with no tap. The use after it is asked for again.
// The approver gets one notice about the grant from before.
func TestBrokerScheduledGrantSurvivesRestart(t *testing.T) {
	t.Parallel()
	e := startListening(t, brokerOptions{preapprove: true})
	e.stderr.wait(t, lineListening)
	c := e.httpClient()

	grant := api.PreapproveRequest{
		Secrets: []string{"github-token"}, Uses: 2, Reason: "job nightly-backup",
		From:  time.Now().Add(-time.Minute).UTC().Format(time.RFC3339),
		Until: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}
	mustStatus(t, e.approve(c, api.PathPreapprove, grant), http.StatusOK)
	asked := e.tg.asked()
	mustStatus(t, e.post(c, api.PathSecrets, githubSecrets), http.StatusOK)

	journal := e.restart()
	c = e.httpClient()
	mustStatus(t, e.post(c, api.PathSecrets, githubSecrets), http.StatusOK)
	if e.tg.asked() != asked {
		t.Fatal("the person was asked for a use that the grant covers")
	}
	// The uses left are the same as before the stop: none now.
	e.mustAskAndDeny(c)

	e.signal(syscall.SIGTERM) // the stop waits for the alerts of the start
	e.mustExit(exitOK)
	if n := e.tg.alertCount(restoreNotice); n != 1 {
		t.Errorf("%d notices about the grants from before, want 1", n)
	}
	if strings.Contains(e.tg.bodies()+journal+e.stderr.text(), e.values["github-token"]) {
		t.Error("the secret value is in the calls to Telegram or the journal")
	}
}

// TestBrokerStandingGrantSurvivesRestart: a standing grant is approved,
// the broker stops and starts again, and the token of the grant still
// works with no tap. The token chain is rebuilt too: that token, used
// again after its use, is old, and raises the alarm.
func TestBrokerStandingGrantSurvivesRestart(t *testing.T) {
	t.Parallel()
	e := startListening(t, brokerOptions{standing: true})
	e.stderr.wait(t, lineListening)
	c := e.httpClient()

	// Three windows that cover the whole day but the last minute, as in
	// TestBrokerStandingAlarmThroughTelegram.
	if now := time.Now(); now.Hour() == 23 && now.Minute() >= 55 {
		t.Skip("too close to midnight, outside the windows")
	}
	grant := api.PreapproveRequest{
		Secrets: []string{"github-token"}, Uses: 1, Reason: "job nightly-backup",
		From:  time.Now().Add(-time.Minute).UTC().Format(time.RFC3339),
		Until: time.Now().AddDate(0, 0, 30).UTC().Format(time.RFC3339),
		Windows: []api.Window{
			{Kind: api.WindowDaily, From: "00:00", To: "08:00"},
			{Kind: api.WindowDaily, From: "08:00", To: "16:00"},
			{Kind: api.WindowDaily, From: "16:00", To: "23:59"},
		},
	}
	a := e.approve(c, api.PathPreapprove, grant)
	mustStatus(t, a, http.StatusOK)
	made, err := api.ReadAnswer[api.PreapproveAnswer](strings.NewReader(string(a.body)))
	if err != nil || made.GrantToken == "" {
		t.Fatalf("no token in the answer: %v", err)
	}
	asked := e.tg.asked()
	use := func(token string) brokerAnswer {
		return e.postWithToken(c, api.PathSecrets, githubSecrets, token)
	}

	journal := e.restart()
	c = e.httpClient()
	first := use(made.GrantToken)
	mustStatus(t, first, http.StatusOK)
	rotated, err := api.ReadAnswer[api.SecretsAnswer](strings.NewReader(string(first.body)))
	if err != nil || rotated.GrantToken == "" || rotated.GrantToken == made.GrantToken {
		t.Fatalf("no new token in the answer after the restart: %v", err)
	}
	if e.tg.asked() != asked {
		t.Fatal("the person was asked for a use that the grant covers")
	}
	if e.tg.alertCount("Standing grant alarm") != 0 {
		t.Fatal("an alarm for a good use after the restart")
	}

	// The token is old now: denied, with the alarm.
	mustStatus(t, use(made.GrantToken), http.StatusForbidden)
	e.tg.waitAlert("Standing grant alarm")

	e.signal(syscall.SIGTERM)
	e.mustExit(exitOK)
	if n := e.tg.alertCount(restoreNotice); n != 1 {
		t.Errorf("%d notices about the grants from before, want 1", n)
	}
	if n := e.tg.alertCount("Standing grant alarm"); n != 1 {
		t.Errorf("%d standing grant alarms, want 1: the one of the old token", n)
	}
	texts := e.tg.bodies() + journal + e.stderr.text()
	for _, tok := range []string{made.GrantToken, rotated.GrantToken} {
		if strings.Contains(texts, tok) {
			t.Error("a grant token is in the calls to Telegram or the journal")
		}
	}
	if got := eventNames(e.auditEntries()); !slices.Contains(got, "grant_alarm:old_token") {
		t.Errorf("no grant_alarm:old_token entry in %q", got)
	}
}

// TestBrokerWindowGrantEndsAtRestart: an "Approve N min" window does not
// survive a restart. The same request is asked for again, and the start
// sends no notice about grants from before.
func TestBrokerWindowGrantEndsAtRestart(t *testing.T) {
	t.Parallel()
	e := startListening(t, brokerOptions{window: true})
	e.stderr.wait(t, lineListening)
	c := e.httpClient()

	mustStatus(t, e.answerWith(c, api.PathSecrets, githubSecrets, "w:"), http.StatusOK)
	// The window covers the same request before the restart.
	asked := e.tg.asked()
	mustStatus(t, e.post(c, api.PathSecrets, githubSecrets), http.StatusOK)
	if e.tg.asked() != asked {
		t.Fatal("the window did not cover the same request; the test proves nothing")
	}

	e.restart()
	e.mustAskAndDeny(e.httpClient())

	e.signal(syscall.SIGTERM)
	e.mustExit(exitOK)
	if n := e.tg.alertCount(restoreNotice); n != 0 {
		t.Errorf("%d notices about grants from before, want 0", n)
	}
}
