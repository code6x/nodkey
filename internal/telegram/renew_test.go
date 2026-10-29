package telegram

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
)

// Tests of the warning before the end of a standing grant and of its
// Renew button (DESIGN.md section 8).

func warningOf() approval.Warning {
	return approval.Warning{RequestID: testID(1), ShortCode: "m4k2", Client: "laptop", Secrets: []string{"backup-token"},
		Windows: []string{"daily 03:00-05:00"}, Uses: 1, GrantID: testID(5),
		End: time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)}
}

func TestRenewData(t *testing.T) {
	kb := renewKeyboard(testID(1))
	if len(kb.InlineKeyboard) != 1 || len(kb.InlineKeyboard[0]) != 1 || kb.InlineKeyboard[0][0].Text != "Renew" {
		t.Fatalf("keyboard %+v", kb)
	}
	action, id, ok := parseData(kb.InlineKeyboard[0][0].CallbackData)
	if !ok || action != audit.AnswerRenew || id != testID(1) {
		t.Errorf("parseData = %q, %q, %v", action, id, ok)
	}
	for _, bad := range []string{"n:", "n:" + testID(1) + "x", "N:" + testID(1)} {
		if _, _, ok := parseData(bad); ok {
			t.Errorf("parseData(%q) was accepted", bad)
		}
	}
}

func TestWarningText(t *testing.T) {
	tx, err := warningText(warningOf())
	if err != nil {
		t.Fatal(err)
	}
	got := tx.plain.String()
	for _, want := range []string{"⏳ Standing grant ends soon · request m4k2", "✅ machine: laptop", "✅ secrets: backup-token",
		"✅ windows: daily 03:00-05:00, 1 use(s) in each", "✅ grant: " + testID(5), "✅ ends: 2026-11-13 12:00:00 UTC", "Renew makes"} {
		if !strings.Contains(got, want) {
			t.Errorf("warning\n%s\nwant %q", got, want)
		}
	}
	for name, change := range map[string]func(*approval.Warning){
		"a bad request ID": func(w *approval.Warning) { w.RequestID = "x" },
		"a bad short code": func(w *approval.Warning) { w.ShortCode = "<b>" },
		"a bad client":     func(w *approval.Warning) { w.Client = "a b" },
		"no secrets":       func(w *approval.Warning) { w.Secrets = nil },
		"a bad secret":     func(w *approval.Warning) { w.Secrets = []string{"<i>"} },
		"no windows":       func(w *approval.Warning) { w.Windows = nil },
		"a bad window":     func(w *approval.Warning) { w.Windows = []string{"<b>daily</b>"} },
		"a bad grant ID":   func(w *approval.Warning) { w.GrantID = "" },
		"no uses":          func(w *approval.Warning) { w.Uses = 0 },
		"no end":           func(w *approval.Warning) { w.End = time.Time{} },
	} {
		w := warningOf()
		change(&w)
		if _, err := warningText(w); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestWarnAndRenewTap: the warning goes to the private chat, with a sound
// and one Renew button. A Renew on it reaches the core; a Renew from
// another user or chat, or on a changed warning, does not.
func TestWarnAndRenewTap(t *testing.T) {
	e := newEnv(t)
	core := &stubCore{}
	e.run(t, core.answer)
	m, err := e.a.Warn(context.Background(), warningOf())
	if err != nil {
		t.Fatal(err)
	}
	calls := e.f.callsOf("sendMessage")
	if len(calls) != 1 {
		t.Fatalf("%d messages", len(calls))
	}
	c := calls[0]
	if c.num("chat_id") != approverID || c.field("disable_notification") == "true" ||
		len(c.buttonData()) != 1 || c.buttonData()[0] != dataRenew+testID(1) {
		t.Errorf("warning %s", c.Raw)
	}
	_, msg, ok := parseMessageID(m)
	if !ok {
		t.Fatalf("message ID %q", m)
	}
	data := dataRenew + testID(1)
	for name, tc := range map[string]struct {
		spec  tapSpec
		cause audit.TapCause
	}{
		"other user": {tapSpec{from: otherUserID, chatID: approverID, chatType: "private", msgID: msg, data: data}, audit.TapOtherUser},
		"other chat": {tapSpec{from: approverID, chatID: noticeChatID, chatType: "supergroup", msgID: msg, data: data}, audit.TapOtherChat},
		"edited":     {func() tapSpec { s := goodTap(msg, data); s.edited = true; return s }(), audit.TapEditedMessage},
	} {
		before := len(e.taps.all())
		e.f.waitHandled(e.f.tap(tc.spec))
		taps := e.taps.all()
		if len(taps) != before+1 || taps[before].Cause != tc.cause {
			t.Errorf("%s: reports %+v, want cause %s", name, taps[before:], tc.cause)
		}
	}
	if n := len(core.all()); n != 0 {
		t.Fatalf("the core got %d answers from refused taps", n)
	}
	cb := e.f.tap(goodTap(msg, data))
	if got := e.f.waitAnswer(cb).str("text"); got != tapCountedRenew {
		t.Errorf("the phone shows %q", got)
	}
	got := core.all()
	want := approval.Answer{RequestID: testID(1), Action: audit.AnswerRenew, Message: m, UserID: approverID}
	if len(got) != 1 || got[0] != want {
		t.Errorf("the core got %+v, want %+v", got, want)
	}
}
