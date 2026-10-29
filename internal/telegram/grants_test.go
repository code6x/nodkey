package telegram

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/approval"
)

func testGrants() []approval.GrantInfo {
	return []approval.GrantInfo{
		{Client: "laptop", Secrets: []string{"backup-token", "db-pass"}, Windows: []string{"daily 03:00-05:00"},
			End: time.Date(2026, 12, 1, 3, 0, 0, 0, time.UTC)},
		{Client: "web-1", Secrets: []string{"deploy-key"}, Windows: []string{"mon,thu 01:00-02:00"},
			LastUse: time.Date(2026, 11, 2, 1, 5, 0, 0, time.UTC), End: time.Date(2027, 1, 5, 1, 0, 0, 0, time.UTC)},
	}
}

// TestGrantsText: the list shows client, secrets, windows, last use (or
// never) and end; an empty list has its own text; a bad name is refused.
func TestGrantsText(t *testing.T) {
	tx, err := grantsText(testGrants(), false)
	if err != nil {
		t.Fatal(err)
	}
	got := tx.plain.String()
	for _, want := range []string{"machine: laptop", "backup-token, db-pass", "daily 03:00-05:00",
		"last use: never", "ends: 2026-12-01 03:00", "last use: 2026-11-02 01:05", "mon,thu 01:00-02:00"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	w, _ := grantsText(testGrants(), true)
	if !strings.Contains(w.plain.String(), "Weekly summary") {
		t.Error("the weekly text has no title")
	}
	e, err := grantsText(nil, true)
	if err != nil || !strings.Contains(e.plain.String(), "No standing grants.") {
		t.Errorf("empty list: %v %q", err, e.plain.String())
	}
	bad := testGrants()
	bad[0].Client = "<b>x"
	if _, err := grantsText(bad, false); err == nil {
		t.Error("a bad client name was accepted")
	}
	bad = testGrants()
	bad[0].Secrets = nil
	if _, err := grantsText(bad, false); err == nil {
		t.Error("a grant without secrets was accepted")
	}
}

// TestGrantsTextCut: a long list is cut with a count.
func TestGrantsTextCut(t *testing.T) {
	var l []approval.GrantInfo
	for range 100 {
		l = append(l, testGrants()[0])
	}
	tx, err := grantsText(l, false)
	if err != nil {
		t.Fatal(err)
	}
	if tx.units() > maxAlertUnits+50 || !strings.Contains(tx.plain.String(), "more") {
		t.Errorf("not cut: %d units", tx.units())
	}
}

func (f *fakeTelegram) message(from, chatID int64, chatType, txt string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addUpdateLocked(map[string]any{"message": map[string]any{
		"message_id": 5, "text": txt,
		"from": map[string]any{"id": from},
		"chat": map[string]any{"id": chatID, "type": chatType},
	}})
}

// TestGrantsCommand: /grants from the approver in the private chat gets the
// list, and stays private. Strangers, other chats, other text and no source
// get no answer, and the command is limited per minute.
func TestGrantsCommand(t *testing.T) {
	e := newEnv(t)
	core := &stubCore{}
	// No source yet: no answer.
	e.a.SetGrantSource(nil)
	stop := e.run(t, core.answer)
	e.f.message(approverID, approverID, "private", "/grants")
	e.f.tap(goodTap(1, "x"))
	e.f.waitFor("handled", func() bool { return len(e.f.callsOfLocked("answerCallbackQuery")) >= 1 })
	e.a.SetGrantSource(testGrants)

	e.f.message(approverID+1, approverID+1, "private", "/grants") // a stranger
	e.f.message(approverID+1, approverID, "private", "/grants")   // a stranger in the chat
	e.f.message(approverID, noticeChatID, "group", "/grants")     // another chat
	e.f.message(approverID, approverID, "private", "/grants now") // other text
	e.f.message(approverID, approverID, "private", "grants")
	e.f.message(approverID, approverID, "private", "/grants@somebot")
	e.f.waitCalls("sendMessage", 1)
	// A sentinel: updates go in order, so all before it were handled.
	e.f.tap(goodTap(1, "y"))
	e.f.waitFor("sentinel", func() bool { return len(e.f.callsOfLocked("answerCallbackQuery")) >= 2 })
	calls := e.f.callsOf("sendMessage")
	if len(calls) != 1 {
		t.Fatalf("%d answers, want 1", len(calls))
	}
	if calls[0].num("chat_id") != approverID || !strings.Contains(calls[0].str("text"), "laptop") {
		t.Errorf("the answer: %s", calls[0].Raw)
	}
	for _, bad := range []string{"deadbeef", "hash"} {
		if strings.Contains(calls[0].str("text"), bad) {
			t.Error("the answer has " + bad)
		}
	}

	// The limit: more commands than GrantsPerMinute in a minute.
	for range 5 {
		e.f.message(approverID, approverID, "private", "/grants")
	}
	e.f.tap(goodTap(1, "z"))
	e.f.waitFor("sentinel 2", func() bool { return len(e.f.callsOfLocked("answerCallbackQuery")) >= 3 })
	if n := len(e.f.callsOf("sendMessage")); n != GrantsPerMinute {
		t.Errorf("%d answers, want %d", n, GrantsPerMinute)
	}
	_ = stop()
}

// TestSummary: the summary goes to the notice chat; an empty list says so.
func TestSummary(t *testing.T) {
	e := newEnv(t)
	if err := e.a.Summary(context.Background(), testGrants()); err != nil {
		t.Fatal(err)
	}
	if err := e.a.Summary(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	calls := e.f.callsOf("sendMessage")
	if len(calls) != 2 || calls[0].num("chat_id") != noticeChatID ||
		!strings.Contains(calls[1].str("text"), "No standing grants.") {
		t.Errorf("calls: %d", len(calls))
	}
}
