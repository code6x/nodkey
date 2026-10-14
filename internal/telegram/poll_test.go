package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
)

// TestTapChecks checks the checks of the Telegram code on each button
// press: the user, the private chat, a message (no inline message) and
// strict button data. A press that fails one never reaches the core, gets
// an answer, and is reported for the audit log. Each case has a press
// that passes, to show the core gets it.
func TestTapChecks(t *testing.T) {
	id := testID(7)
	good := goodTap(55, dataOnce+id)
	for _, tc := range []struct {
		name  string
		tap   func() tapSpec
		cause audit.TapCause // "": the press reaches the core
		text  string         // the answer the phone shows
	}{
		{"approver in the private chat", func() tapSpec { return good }, "", tapCountedApprove},
		{"deny", func() tapSpec { s := good; s.data = dataDeny + id; return s }, "", tapCountedDeny},
		{"window", func() tapSpec { s := good; s.data = dataWindow + id; return s }, "", tapCountedApprove},
		{"another user", func() tapSpec { s := good; s.from = otherUserID; return s }, audit.TapOtherUser, ""},
		{"another user in the private chat of the approver", func() tapSpec {
			s := good
			s.from = otherUserID
			s.chatID = approverID
			return s
		}, audit.TapOtherUser, ""},
		{"a group chat", func() tapSpec { s := good; s.chatID, s.chatType = groupChatID, "supergroup"; return s },
			audit.TapOtherChat, tapRefused},
		{"a group with the approver's ID", func() tapSpec { s := good; s.chatType = "group"; return s }, audit.TapOtherChat, tapRefused},
		{"another private chat", func() tapSpec { s := good; s.chatID = otherUserID; return s }, audit.TapOtherChat, tapRefused},
		{"an inline message", func() tapSpec { s := good; s.inline = true; return s }, audit.TapInlineMessage, tapRefused},
		{"no message", func() tapSpec { s := good; s.noMessage = true; return s }, audit.TapNoMessage, tapRefused},
		{"message ID 0", func() tapSpec { s := good; s.msgID = 0; return s }, audit.TapNoMessage, tapRefused},
		{"a game button", func() tapSpec { s := good; s.game = "game"; return s }, audit.TapBadData, tapRefused},
		{"no data", func() tapSpec { s := good; s.data = ""; return s }, audit.TapBadData, tapRefused},
		{"unknown action", func() tapSpec { s := good; s.data = "a:" + id; return s }, audit.TapBadData, tapRefused},
		{"the short code", func() tapSpec { s := good; s.data = "o:k3f9"; return s }, audit.TapBadData, tapRefused},
		{"data with more", func() tapSpec { s := good; s.data = dataOnce + id + "x"; return s }, audit.TapBadData, tapRefused},
		{"data with a space", func() tapSpec { s := good; s.data = dataOnce + id[:21] + " "; return s }, audit.TapBadData, tapRefused},
		{"long data", func() tapSpec { s := good; s.data = strings.Repeat("é", 50); return s }, audit.TapBadData, tapRefused},
		{"an edited message", func() tapSpec { s := good; s.edited = true; return s }, audit.TapUnknownRequest, tapEnded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			core := &stubCore{}
			e.run(t, core.answer)
			s := tc.tap()
			ans := e.f.waitAnswer(e.f.tap(s))
			if got := ans.str("text"); got != tc.text {
				t.Errorf("the phone shows %q, want %q", got, tc.text)
			}
			// A press that passes, to be sure the first one was handled.
			e.f.waitAnswer(e.f.tap(goodTap(56, dataDeny+testID(8))))
			answers := core.all()
			if tc.cause != "" {
				if len(answers) != 1 || answers[0].RequestID != testID(8) {
					t.Errorf("the core got %+v, want only the second press", answers)
				}
				taps := e.taps.all()
				if len(taps) != 1 {
					t.Fatalf("%d reports, want 1", len(taps))
				}
				want := audit.ForeignTap{UserID: s.from, Data: cutData(s.data), Cause: tc.cause}
				if !s.inline && !s.noMessage {
					want.ChatID, want.MessageID = s.chatID, s.msgID
				}
				if taps[0] != want {
					t.Errorf("report %+v, want %+v", taps[0], want)
				}
				if len(taps[0].Data) > maxTapData {
					t.Errorf("the report holds %d bytes of data", len(taps[0].Data))
				}
				if !strings.Contains(e.logs.String(), "refused a button press") {
					t.Error("the refused press is not logged")
				}
				return
			}
			if len(answers) != 2 {
				t.Fatalf("the core got %d answers, want 2", len(answers))
			}
			action, _, _ := parseData(s.data)
			want := approval.Answer{RequestID: id, Action: action, Message: messageID(approverID, 55), UserID: approverID}
			if answers[0] != want {
				t.Errorf("the core got %+v, want %+v", answers[0], want)
			}
			if taps := e.taps.all(); len(taps) != 0 {
				t.Errorf("reports %+v, want none", taps)
			}
		})
	}
}

// TestTapRefusedByCore checks what Run does with each answer of the core:
// the text on the phone, the report for the audit log with its cause, and
// the update of the message. Only ErrUnknownRequest updates the message,
// and for a message that this broker did not send, it only removes the
// buttons. ErrTooEarly is no foreign tap and changes nothing.
func TestTapRefusedByCore(t *testing.T) {
	for _, tc := range []struct {
		err    error
		text   string
		cause  audit.TapCause // "": not reported
		edited bool
	}{
		{approval.ErrTooEarly, tapTooEarly, "", false},
		{approval.ErrUnknownRequest, tapEnded, audit.TapUnknownRequest, true},
		{approval.ErrExpired, tapExpired, audit.TapExpired, false},
		{approval.ErrWrongMessage, tapRefused, audit.TapWrongMessage, false},
		{approval.ErrNotAllowed, tapRefused, audit.TapNotAllowed, false},
		{approval.ErrNotApprover, tapRefused, audit.TapRefused, false},
		{approval.ErrStopped, tapRefused, audit.TapRefused, false},
		{errors.New("something else"), tapRefused, audit.TapRefused, false},
	} {
		t.Run(tc.err.Error(), func(t *testing.T) {
			e := newEnv(t)
			core := &stubCore{err: tc.err}
			e.run(t, core.answer)
			ans := e.f.waitAnswer(e.f.tap(goodTap(60, dataOnce+testID(1))))
			if got := ans.str("text"); got != tc.text {
				t.Errorf("the phone shows %q, want %q", got, tc.text)
			}
			// A second press shows when the first is done.
			core.setErr(nil)
			e.f.waitAnswer(e.f.tap(goodTap(61, dataDeny+testID(2))))
			taps := e.taps.all()
			switch {
			case tc.cause == "" && len(taps) != 0:
				t.Errorf("reports %+v, want none", taps)
			case tc.cause != "" && (len(taps) != 1 || taps[0].Cause != tc.cause):
				t.Errorf("reports %+v, want one with cause %s", taps, tc.cause)
			}
			if n := len(e.f.callsOf("editMessageText")); n != 0 {
				t.Errorf("%d text edits, want 0: the text of the message stays", n)
			}
			edits := e.f.callsOf("editMessageReplyMarkup")
			if (len(edits) == 1) != tc.edited {
				t.Fatalf("%d edits of the buttons, want edited %v", len(edits), tc.edited)
			}
			if tc.edited {
				ed := edits[0]
				if ed.num("chat_id") != approverID || ed.num("message_id") != 60 ||
					ed.field("reply_markup") != `{"inline_keyboard":[]}` {
					t.Errorf("edit %s, want the buttons of %d:60 removed", ed.Raw, approverID)
				}
			}
		})
	}
}

// cbUpdate returns an update with a button press by the approver, as
// JSON.
func cbUpdate(t *testing.T, updateID int64, cbID string, msgID int64, data string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"update_id": updateID,
		"callback_query": map[string]any{
			"id": cbID, "from": map[string]any{"id": approverID}, "data": data, "chat_instance": "42",
			"message": map[string]any{
				"message_id": msgID, "date": 1, "text": "t",
				"chat": map[string]any{"id": approverID, "type": "private"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestPolling checks the getUpdates calls: long polling of 50 s, only
// button presses, at most 10 updates, and offsets that confirm each
// update once. An update before the offset is not handled again.
func TestPolling(t *testing.T) {
	e := newEnv(t)
	e.f.reply("getUpdates", 200, `{"ok":true,"result":[`+
		cbUpdate(t, 5, "a", 70, dataOnce+testID(1))+","+cbUpdate(t, 6, "b", 71, dataOnce+testID(2))+`]}`)
	e.f.reply("getUpdates", 200, `{"ok":true,"result":[`+
		cbUpdate(t, 5, "again", 70, dataOnce+testID(1))+","+cbUpdate(t, 7, "c", 72, dataOnce+testID(3))+`]}`)
	core := &stubCore{}
	e.run(t, core.answer)
	calls := e.f.waitCalls("getUpdates", 3)
	for i, want := range []int64{0, 7, 8} {
		c := calls[i]
		if c.num("offset") != want || c.num("timeout") != 50 || c.num("limit") != pollLimit ||
			c.field("allowed_updates") != `["callback_query"]` {
			t.Errorf("getUpdates %d: %s, want offset %d", i, c.Raw, want)
		}
	}
	for _, id := range []string{"a", "b", "c"} {
		e.f.waitAnswer(id)
	}
	for _, c := range e.f.callsOf("answerCallbackQuery") {
		if c.str("callback_query_id") == "again" {
			t.Error("an update before the offset was handled again")
		}
	}
	if n := len(core.all()); n != 3 {
		t.Errorf("the core got %d answers, want 3", n)
	}
}

// TestPollingSkipsOtherUpdates checks that an update that is not a button
// press, or does not have the expected form, is skipped, and the offset
// moves past it.
func TestPollingSkipsOtherUpdates(t *testing.T) {
	e := newEnv(t)
	core := &stubCore{}
	e.run(t, core.answer)
	e.f.addRawUpdate(2001, `{"update_id":2001,"message":{"message_id":1,"chat":{"id":7000001,"type":"private"},"text":"approve"}}`)
	e.f.addRawUpdate(2002, `{"update_id":2002,"callback_query":{"id":"bad","from":"not a user"}}`)
	e.f.addRawUpdate(2003, `{"update_id":2003,"callback_query":{"id":"x","from":{"id":1.5}}}`)
	e.f.waitFor("the offset after the updates", func() bool {
		calls := e.f.callsOfLocked("getUpdates")
		return len(calls) > 0 && calls[len(calls)-1].num("offset") == 2004
	})
	if n := len(core.all()); n != 0 {
		t.Errorf("the core got %d answers, want 0", n)
	}
	if !strings.Contains(e.logs.String(), "skipped an update") {
		t.Error("the update with the wrong form is not logged")
	}
}

// TestPollConflict checks that a conflict from getUpdates stops Run with
// ErrPollConflict, after an alert in the log and an alert message to the
// approver, with a sound.
func TestPollConflict(t *testing.T) {
	for _, desc := range []string{
		"Conflict: terminated by other getUpdates request; make sure that only one bot instance is running",
		"Conflict: can't use getUpdates method while webhook is active; use deleteWebhook to delete the webhook first",
	} {
		t.Run(desc[:30], func(t *testing.T) {
			e := newEnv(t)
			e.f.reply("getUpdates", 409, `{"ok":false,"error_code":409,"description":"`+desc+`"}`)
			stop := e.run(t, (&stubCore{}).answer)
			alert := e.f.waitCalls("sendMessage", 1)[0]
			err := stop()
			if !errors.Is(err, ErrPollConflict) {
				t.Errorf("Run: %v, want ErrPollConflict", err)
			}
			if alert.num("chat_id") != approverID || alert.has("disable_notification") ||
				!strings.Contains(alert.str("text"), "may be stolen") {
				t.Errorf("alert %s", alert.Raw)
			}
			if !strings.Contains(e.logs.String(), "ALERT") {
				t.Error("no alert in the log")
			}
			if n := len(e.f.callsOf("getUpdates")); n != 1 {
				t.Errorf("%d getUpdates calls after the conflict, want 1", n)
			}
		})
	}
}

// TestPollConflictAlertFails checks that Run still stops with
// ErrPollConflict when the alert message cannot be sent.
func TestPollConflictAlertFails(t *testing.T) {
	e := newEnv(t)
	e.f.reply("getUpdates", 409, `{"ok":false,"error_code":409,"description":"Conflict"}`)
	for range maxTries {
		e.f.reply("sendMessage", 500, `{"ok":false,"error_code":500,"description":"Internal Server Error"}`)
	}
	stop := e.run(t, (&stubCore{}).answer)
	e.f.waitCalls("sendMessage", maxTries)
	if err := stop(); !errors.Is(err, ErrPollConflict) {
		t.Errorf("Run: %v, want ErrPollConflict", err)
	}
	if !strings.Contains(e.logs.String(), "cannot send the alert message") {
		t.Error("the failed alert is not logged")
	}
}

// TestPollStopsWhenRefused checks that Run stops when Telegram refuses
// getUpdates, for example because the token is no longer valid: then no
// answer can come any more.
func TestPollStopsWhenRefused(t *testing.T) {
	for _, code := range []string{"400", "401", "403", "404"} {
		t.Run(code, func(t *testing.T) {
			e := newEnv(t)
			status := map[string]int{"400": 400, "401": 401, "403": 403, "404": 404}[code]
			e.f.reply("getUpdates", status, `{"ok":false,"error_code":`+code+`,"description":"no"}`)
			err := e.runToEnd(t, (&stubCore{}).answer)
			var ae *apiError
			if !errors.As(err, &ae) || ae.code != status || errors.Is(err, ErrPollConflict) || errors.Is(err, context.Canceled) {
				t.Errorf("Run: %v, want the %s error", err, code)
			}
			if n := len(e.f.callsOf("sendMessage")); n != 0 {
				t.Errorf("%d messages, want 0", n)
			}
		})
	}
}

// TestPollRetries checks that Run keeps polling after server errors,
// network errors, answers it cannot read and code 429, with a growing,
// bounded wait that is never shorter than Telegram asks for.
func TestPollRetries(t *testing.T) {
	e := newEnv(t)
	e.f.reply("getUpdates", 500, `{"ok":false,"error_code":500,"description":"Internal Server Error"}`)
	e.f.reply("getUpdates", 502, `<html>Bad Gateway</html>`)
	e.f.reply("getUpdates", 200, `not json`)
	e.f.reply("getUpdates", 429, `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 7","parameters":{"retry_after":7}}`)
	for range 6 {
		e.f.reply("getUpdates", 503, `{"ok":false,"error_code":503,"description":"Service Unavailable"}`)
	}
	core := &stubCore{}
	e.run(t, core.answer)
	e.f.waitAnswer(e.f.tap(goodTap(80, dataOnce+testID(1))))
	want := []time.Duration{
		time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, // 8 s is longer than the 7 s that Telegram asks
		16 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second,
	}
	got := e.sleeps.all()
	if len(got) != len(want) {
		t.Fatalf("waits %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("wait %d is %s, want %s", i, got[i], want[i])
		}
	}
	if n := len(core.all()); n != 1 {
		t.Errorf("the core got %d answers, want 1", n)
	}
}

// TestPoll429WithoutJSONWaits: a 429 whose body is not the JSON of the Bot
// API, such as the page of a proxy, must not make the poll loop call
// again at once. It waits as after any error, at least 1 second, and
// longer each time.
func TestPoll429WithoutJSONWaits(t *testing.T) {
	e := newEnv(t)
	for range 3 {
		e.f.reply("getUpdates", 429, `<html><body><h1>429 Too Many Requests</h1></body></html>`)
	}
	e.run(t, (&stubCore{}).answer)
	e.f.waitAnswer(e.f.tap(goodTap(80, dataOnce+testID(1))))
	checkWaits(t, e.sleeps.all(), time.Second, 2*time.Second, 4*time.Second)
}

// TestRunNeverPanics checks that a panic while an update is handled, in
// the core or in the report for the audit log, stops Run with an error,
// and that the panic value is not logged.
func TestRunNeverPanics(t *testing.T) {
	const secret = "panic value from the update"
	for _, tc := range []struct {
		name string
		edit func(e *testEnv) func(approval.Answer) error
		tap  tapSpec
	}{
		{"core", func(*testEnv) func(approval.Answer) error {
			return func(approval.Answer) error { panic(secret) }
		}, goodTap(90, dataOnce+testID(1))},
		{"report", func(e *testEnv) func(approval.Answer) error {
			e.a.foreignTap = func(audit.ForeignTap) { panic(secret) }
			return (&stubCore{}).answer
		}, tapSpec{from: otherUserID, chatID: otherUserID, chatType: "private", msgID: 1, data: "x"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			answer := tc.edit(e)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- e.a.Run(ctx, answer) }()
			e.f.tap(tc.tap)
			select {
			case err := <-done:
				if !errors.Is(err, errPanic) {
					t.Errorf("Run: %v, want errPanic", err)
				}
			case <-time.After(waitLimit):
				t.Fatal("Run did not return")
			}
			if strings.Contains(e.logs.String(), secret) {
				t.Error("the panic value is in the log")
			}
			if !strings.Contains(e.logs.String(), "polling stopped after a panic") {
				t.Error("the panic is not logged")
			}
		})
	}
}

// TestRunOnce checks that only one Run polls at a time, and that Run needs
// an answer function.
func TestRunOnce(t *testing.T) {
	e := newEnv(t)
	if err := e.a.Run(context.Background(), nil); err == nil {
		t.Error("Run without an answer function did not fail")
	}
	stop := e.run(t, (&stubCore{}).answer)
	e.f.waitCalls("getUpdates", 1)
	if err := e.a.Run(context.Background(), (&stubCore{}).answer); err == nil {
		t.Error("a second Run did not fail")
	}
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Errorf("Run: %v, want context.Canceled", err)
	}
	// After Run returned, it may run again.
	stop2 := e.run(t, (&stubCore{}).answer)
	e.f.waitCalls("getUpdates", 2)
	if err := stop2(); !errors.Is(err, context.Canceled) {
		t.Errorf("Run: %v, want context.Canceled", err)
	}
}
