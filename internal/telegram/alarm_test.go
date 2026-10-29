package telegram

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
)

// TestStandingNotice: the notice of a standing use says so, and checkPrompt
// accepts the via only for a secrets notice.
func TestStandingNotice(t *testing.T) {
	p := approval.Prompt{
		RequestID: testID(4), ShortCode: "k3f9", Kind: audit.KindSecrets, Client: "laptop",
		Secrets: []string{"backup-token"}, Via: audit.ViaStanding,
	}
	tx, err := noticeText(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := tx.plain.String(); !strings.Contains(got, "\n"+standingNoticeLine+"\n") {
		t.Errorf("the notice is %q", got)
	}
	if err := checkPrompt(p, false); err == nil {
		t.Error("a standing via in a message with buttons was accepted")
	}
	k := p
	k.Kind, k.Secrets, k.Key, k.Hosts, k.HostKey, k.RemoteUser = audit.KindSSHLogin, nil, "web", []string{"web-1"},
		"SHA256:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ", "deploy"
	if _, err := noticeText(k); err == nil {
		t.Error("a standing via in an SSH notice was accepted")
	}
}

func alarmOf(cause audit.AlarmCause) approval.Alarm {
	a := approval.Alarm{RequestID: testID(5), ShortCode: "k3f9", Client: "laptop",
		Secrets: []string{"github-token"}, GrantID: testID(6), Cause: cause}
	switch cause {
	case audit.AlarmUnknownToken:
		a.GrantID = ""
	case audit.AlarmOldToken, audit.AlarmOverUses:
		a.Ended = true
	}
	return a
}

// TestAlarm: an alarm goes with a sound, with fixed text for the cause, and
// counts toward the notices per minute.
func TestAlarm(t *testing.T) {
	e := newEnv(t)
	for _, cause := range []audit.AlarmCause{audit.AlarmOldToken, audit.AlarmOverUses, audit.AlarmOutsideWindow, audit.AlarmUnknownToken, audit.AlarmMissedWindow} {
		if err := e.a.Alarm(context.Background(), alarmOf(cause)); err != nil {
			t.Fatalf("%s: %v", cause, err)
		}
	}
	calls := e.f.callsOf("sendMessage")
	if len(calls) != 5 {
		t.Fatalf("%d messages", len(calls))
	}
	for _, c := range calls {
		if c.field("disable_notification") == "true" || c.num("chat_id") != noticeChatID || c.has("reply_markup") ||
			!strings.Contains(c.str("text"), "🚨") || !strings.Contains(c.str("text"), "laptop") {
			t.Errorf("alarm %s", c.Raw)
		}
	}
	if !strings.Contains(calls[0].str("text"), "old token") || strings.Contains(calls[3].str("text"), "grant:") {
		t.Errorf("texts: %q, %q", calls[0].str("text"), calls[3].str("text"))
	}
	// The same budget as Notify: 20 in all.
	for i := 5; i < NoticesPerMinute; i++ {
		if err := e.a.Alarm(context.Background(), alarmOf(audit.AlarmOldToken)); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.a.Alarm(context.Background(), alarmOf(audit.AlarmOldToken)); !errors.Is(err, ErrNoticeLimit) {
		t.Errorf("over the limit: %v", err)
	}
	if err := e.a.Notify(context.Background(), approval.Prompt{}); err == nil {
		t.Error("Notify sent a notice after the budget was used")
	}
}

// TestAlarmRefusals: an alarm that is not made by the core is not sent.
func TestAlarmRefusals(t *testing.T) {
	e := newEnv(t)
	for name, change := range map[string]func(*approval.Alarm){
		"a bad request ID":        func(a *approval.Alarm) { a.RequestID = "x" },
		"a bad short code":        func(a *approval.Alarm) { a.ShortCode = "<b>" },
		"a bad client":            func(a *approval.Alarm) { a.Client = "a b" },
		"a bad secret":            func(a *approval.Alarm) { a.Secrets = []string{"<i>"} },
		"unknown with a grant":    func(a *approval.Alarm) { a.Cause, a.Ended = audit.AlarmUnknownToken, false },
		"no grant":                func(a *approval.Alarm) { a.GrantID = "" },
		"an unknown cause":        func(a *approval.Alarm) { a.Cause = "x" },
		"ended, but not ending":   func(a *approval.Alarm) { a.Cause = audit.AlarmOutsideWindow },
		"a bad owner":             func(a *approval.Alarm) { a.Owner = "a b" },
		"the owner is the client": func(a *approval.Alarm) { a.Owner = "laptop" },
		"an owner, no grant": func(a *approval.Alarm) {
			a.Owner, a.Cause, a.GrantID, a.Ended = "ci", audit.AlarmUnknownToken, "", false
		},
	} {
		a := alarmOf(audit.AlarmOldToken)
		change(&a)
		if err := e.a.Alarm(context.Background(), a); err == nil {
			t.Errorf("%s: sent", name)
		}
	}
	if n := len(e.f.allCalls()); n != 0 {
		t.Errorf("%d calls", n)
	}
}

// TestAlarmOwner: an alarm for a token of another machine's grant names
// that machine.
func TestAlarmOwner(t *testing.T) {
	a := alarmOf(audit.AlarmOldToken)
	a.Client, a.Owner = "ci", "laptop"
	txt, err := alarmText(a)
	if err != nil {
		t.Fatal(err)
	}
	if s := txt.plain.String(); !strings.Contains(s, "machine: ci") || !strings.Contains(s, "machine laptop") {
		t.Errorf("text: %q", s)
	}
	if s := alarmOf(audit.AlarmOldToken); s.Owner != "" {
		t.Fatal("alarmOf has an owner")
	}
}
