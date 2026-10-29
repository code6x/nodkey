package main

import (
	"net/http"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/grantkey"
)

// TestBrokerStandingAlarmThroughTelegram: the alarm of an old token reaches
// the fake Telegram as a message with no buttons, the request is denied,
// and the grant ends: even the new token is refused afterwards.
func TestBrokerStandingAlarmThroughTelegram(t *testing.T) {
	t.Parallel()
	e := startListening(t, brokerOptions{standing: true})
	e.stderr.wait(t, lineListening)
	c := e.httpClient()

	// Three windows that cover the whole day, in the broker's local time,
	// but the last minute: To is at most 23:59 and not part of the window.
	if now := time.Now(); now.Hour() == 23 && now.Minute() >= 58 {
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
	if err != nil {
		t.Fatal(err)
	}
	tok0 := made.GrantToken
	if _, err := grantkey.Parse(tok0); err != nil {
		t.Fatalf("the token: %v", err)
	}

	use := func(token string) brokerAnswer {
		return e.postWithToken(c, api.PathSecrets, api.SecretsRequest{
			Secrets: []api.SecretRef{{Var: "GH_TOKEN", Name: "github-token"}}, Reason: "job nightly-backup",
		}, token)
	}
	// A good use: no tap, a new token.
	first := use(tok0)
	mustStatus(t, first, http.StatusOK)
	rotated, err := api.ReadAnswer[api.SecretsAnswer](strings.NewReader(string(first.body)))
	if err != nil || rotated.GrantToken == "" || rotated.GrantToken == tok0 {
		t.Fatalf("no new token in the answer: %v", err)
	}
	if e.tg.alertCount("Standing grant alarm") != 0 {
		t.Fatal("an alarm for a good use")
	}
	asked := e.tg.asked()

	// The old token again: denied, one alarm with the fixed text.
	mustStatus(t, use(tok0), http.StatusForbidden)
	body := e.tg.waitAlert("Standing grant alarm")
	if !strings.Contains(body, "an old token was used again") || !strings.Contains(body, "github-token") {
		t.Errorf("the alarm: %s", body)
	}
	// The grant is over: the new token is refused, and nobody is asked.
	mustStatus(t, use(rotated.GrantToken), http.StatusForbidden)
	if e.tg.asked() != asked {
		t.Error("the person was asked for a request with a token")
	}

	e.signal(syscall.SIGINT)
	e.mustExit(exitOK)
	texts := e.tg.bodies() + e.stderr.text() + strings.Join(eventNames(e.auditEntries()), " ")
	for _, tok := range []string{tok0, rotated.GrantToken} {
		if strings.Contains(texts, tok) {
			t.Error("a grant token is in the calls to Telegram, the journal or the audit log")
		}
	}
	got := eventNames(e.auditEntries())
	for _, want := range []string{"grant_alarm:old_token", "grant_ended:alarm"} {
		if !slices.Contains(got, want) {
			t.Errorf("no %s entry in %q", want, got)
		}
	}
}
