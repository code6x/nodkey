package telegram

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/approval/approvaltest"
	"github.com/code6x/nodkey/internal/audit"
)

// Attacks from the security review of issue #10, kept as regression tests.

// waitReports waits until n refused taps were reported, and returns them.
// A report comes after the answer to the tap.
func (e *testEnv) waitReports(t *testing.T, n int) []audit.ForeignTap {
	t.Helper()
	deadline := time.Now().Add(waitLimit)
	for len(e.taps.all()) < n {
		if time.Now().After(deadline) {
			t.Fatalf("waited %s in vain for %d reports", waitLimit, n)
		}
		time.Sleep(time.Millisecond)
	}
	return e.taps.all()
}

// alertsSent returns the alert messages about a changed message.
func alertsSent(f *fakeTelegram) []fakeCall {
	var out []fakeCall
	for _, c := range f.callsOf("sendMessage") {
		if strings.Contains(c.str("text"), "Someone else changed a message") {
			out = append(out, c)
		}
	}
	return out
}

// TestCoreApproveOnEditedMessageDoesNotCount: with a stolen token, someone
// can edit the text of a message that waits for an answer, for example to
// show a harmless secret name, and keep its buttons. The broker never
// edits a message while its request waits, so no Approve on it counts,
// also not one of a button that the request does not offer. Each tap is
// reported, the approver gets one alert, and without a Deny the request
// can only expire. End then writes the true text again.
func TestCoreApproveOnEditedMessageDoesNotCount(t *testing.T) {
	ce := newCoreEnv(t, newFake(t))
	ch := ce.decide(secretsRequest("db-password"))
	id, msg := ce.asked(t, 1)
	ce.f.editByOther(msg, nil, true)
	for _, data := range []string{dataOnce + id, dataWindow + id} {
		if got := ce.f.waitAnswer(ce.f.tap(goodTap(msg, data))).str("text"); got != tapChanged {
			t.Errorf("the phone shows %q, want %q", got, tapChanged)
		}
	}
	taps := ce.waitReports(t, 2)
	if len(taps) != 2 || taps[0].Cause != audit.TapEditedMessage || taps[1].Cause != audit.TapEditedMessage {
		t.Errorf("reports %+v, want two with cause edited_message", taps)
	}
	alerts := alertsSent(ce.f)
	if len(alerts) != 1 {
		t.Fatalf("%d alerts, want 1 for two taps", len(alerts))
	}
	if alerts[0].num("chat_id") != approverID || alerts[0].has("disable_notification") {
		t.Errorf("alert %s", alerts[0].Raw)
	}
	if !strings.Contains(ce.logs.String(), "ALERT: someone else changed a message") {
		t.Error("no alert in the log")
	}
	ce.clock.Advance(120 * time.Second)
	if r := waitResult(t, ch); r.Allowed || r.Cause != audit.CauseExpired {
		t.Errorf("result %+v, want expired", r)
	}
	text := ce.f.waitCalls("editMessageText", 1)[0].str("text")
	if !strings.Contains(text, "✅ secrets: db-password") || !strings.HasSuffix(text, "⌛ expired — denied") {
		t.Errorf("End wrote %q", text)
	}
}

// TestCoreChangedButtonsDoNotCount: someone with the token swaps the labels
// of the buttons, so that "Deny" approves. Even if Telegram set no edit
// date for that, the buttons differ from the ones Ask sent, so the tap
// does not count. The button with the label "Approve once" now carries
// the data of Deny. A tap on it denies: that is safe whatever the label
// says.
func TestCoreChangedButtonsDoNotCount(t *testing.T) {
	ce := newCoreEnv(t, newFake(t))
	ch := ce.decide(secretsRequest("db-password"))
	id, msg := ce.asked(t, 1)
	ce.f.editByOther(msg, map[string]any{"inline_keyboard": [][]map[string]any{{
		{"text": "Deny", "callback_data": dataOnce + id},
		{"text": "Approve once", "callback_data": dataDeny + id},
	}}}, false)
	if got := ce.f.waitAnswer(ce.f.tap(goodTap(msg, dataOnce+id))).str("text"); got != tapChanged {
		t.Errorf("the phone shows %q, want %q", got, tapChanged)
	}
	if taps := ce.waitReports(t, 1); len(taps) != 1 || taps[0].Cause != audit.TapEditedMessage {
		t.Errorf("reports %+v, want one with cause edited_message", taps)
	}
	ce.f.waitCalls("sendMessage", 2) // the message and the alert
	if n := len(alertsSent(ce.f)); n != 1 {
		t.Errorf("%d alerts, want 1", n)
	}
	cb := ce.f.tap(goodTap(msg, dataDeny+id))
	checkDeniedBy(t, waitResult(t, ch))
	if got := ce.f.waitAnswer(cb).str("text"); got != tapChangedDenied {
		t.Errorf("the phone shows %q, want %q", got, tapChangedDenied)
	}
	ce.f.waitHandled(cb)
	if n := len(alertsSent(ce.f)); n != 1 {
		t.Errorf("%d alerts, want still 1: at most one in %s", n, changedAlertEvery)
	}
	taps := ce.taps.all()
	if len(taps) != 2 || taps[0].Data != dataOnce+id || taps[1].Data != dataDeny+id ||
		taps[1].Cause != audit.TapEditedMessage {
		t.Errorf("reports %+v, want the refused tap and the Deny, both with cause edited_message", taps)
	}
}

// TestCoreDenyOnEditedMessageCounts: a Deny is safe whatever the message
// shows. So the Deny button that Ask sent counts also on a message that
// someone else edited: it denies the request, starts the pause after a
// Deny, and ends the client's grants for the secrets of the request
// (THREAT-MODEL.md T8). Before, it was refused like an Approve, and the
// request only expired. The approver still gets the alert, the phone says
// that the message was changed, and the Deny is reported with cause
// edited_message, so the audit log shows the edit. (Issue #48.)
func TestCoreDenyOnEditedMessageCounts(t *testing.T) {
	ce := newCoreEnv(t, newFake(t))
	// A grant for github-token.
	ch := ce.decide(secretsRequest("github-token"))
	id, msg := ce.asked(t, 1)
	ce.f.tap(goodTap(msg, dataWindow+id))
	r := waitResult(t, ch)
	if !r.Allowed || r.Answer != audit.AnswerApproveWindow {
		t.Fatalf("result %+v, want approved for 15 min", r)
	}
	r.StartGrants()
	if r := waitResult(t, ce.decide(secretsRequest("github-token"))); !r.Allowed || r.Answer != "" {
		t.Fatalf("result %+v, want allowed by the grant", r)
	}

	// db-password has no grant, so this request needs a tap.
	both := secretsRequest("github-token")
	both.Secrets = []string{"github-token", "db-password"}
	ch = ce.decide(both)
	id, msg = ce.asked(t, 2)
	ce.f.editByOther(msg, nil, true)
	cb := ce.f.tap(goodTap(msg, dataDeny+id))
	checkDeniedBy(t, waitResult(t, ch))
	if got := ce.f.waitAnswer(cb).str("text"); got != tapChangedDenied {
		t.Errorf("the phone shows %q, want %q", got, tapChangedDenied)
	}
	ce.f.waitHandled(cb) // the alert goes out after the answer
	if n := len(alertsSent(ce.f)); n != 1 {
		t.Errorf("%d alerts, want 1", n)
	}
	if !strings.Contains(ce.logs.String(), "ALERT: someone else changed a message") ||
		!strings.Contains(ce.logs.String(), "a Deny counted on a message that someone else changed") {
		t.Errorf("the log does not show the alert and the Deny:\n%s", ce.logs.String())
	}
	want := audit.ForeignTap{UserID: approverID, ChatID: approverID, MessageID: msg, Data: dataDeny + id,
		Cause: audit.TapEditedMessage}
	if taps := ce.taps.all(); len(taps) != 1 || taps[0] != want {
		t.Errorf("reports %+v, want %+v next to the counted Deny", taps, want)
	}
	ce.f.waitCalls("editMessageText", 2)
	if texts := ce.edits(msg); len(texts) != 1 || !strings.Contains(texts[0], "db-password") ||
		!strings.HasSuffix(texts[0], "⛔ denied by you at 12:00:00") {
		t.Errorf("End wrote %q, want the true text with the Deny", texts)
	}

	// The grant has ended, and the pause holds new requests for both
	// secrets: with the grant, github-token would be allowed, and without
	// the pause, both would get a message.
	sent := len(ce.f.callsOf("sendMessage"))
	for _, s := range []string{"github-token", "db-password"} {
		if r := waitResult(t, ce.decide(secretsRequest(s))); r.Allowed || r.Cause != audit.CauseLimit {
			t.Errorf("%s: result %+v, want denied by the pause", s, r)
		}
	}
	if n := len(ce.f.callsOf("sendMessage")) - sent; n != 0 {
		t.Errorf("%d messages during the pause, want 0", n)
	}

	// After the pause, github-token needs a tap again: its grant is gone.
	ce.clock.Advance(approval.DenyPause)
	ch = ce.decide(secretsRequest("github-token"))
	id, msg = ce.asked(t, 4) // the third message is the alert
	ce.f.tap(goodTap(msg, dataOnce+id))
	if r := waitResult(t, ch); !r.Allowed || r.Answer != audit.AnswerApproveOnce {
		t.Errorf("result %+v, want approved once by a tap", r)
	}
}

// TestCoreFloodKeepsEditedReport: someone with the bot token taps more
// forged buttons than the budget of reports allows, and then edits a
// waiting message. The person's tap on it is refused and the alert goes
// out, and its foreign_tap report with cause edited_message is not
// dropped: the approver's own taps have a budget of their own. (Issue
// #48, from the second security review of issue #10.)
func TestCoreFloodKeepsEditedReport(t *testing.T) {
	ce := newCoreEnv(t, newFake(t))
	ce.setNow((&fakeNow{t: noon}).now) // all the taps come in one minute
	ch := ce.decide(secretsRequest("github-token"))
	id, msg := ce.asked(t, 1)
	extra := 5
	for i := range refusedTapsPerMinute + extra {
		s := tapSpec{from: otherUserID, chatID: otherUserID, chatType: "private", msgID: int64(9000 + i), data: "x"}
		ce.f.waitAnswer(ce.f.tap(s))
	}
	ce.f.editByOther(msg, nil, true)
	cb := ce.f.tap(goodTap(msg, dataOnce+id))
	if got := ce.f.waitAnswer(cb).str("text"); got != tapChanged {
		t.Errorf("the phone shows %q, want %q", got, tapChanged)
	}
	ce.f.waitHandled(cb)
	taps := ce.taps.all()
	if len(taps) != refusedTapsPerMinute+1 {
		t.Fatalf("%d reports, want %d forged taps and the tap on the edited message", len(taps), refusedTapsPerMinute+1)
	}
	for _, tap := range taps[:refusedTapsPerMinute] {
		if tap.Cause != audit.TapOtherUser {
			t.Errorf("report %+v, want cause other_user", tap)
		}
	}
	want := audit.ForeignTap{UserID: approverID, ChatID: approverID, MessageID: msg, Data: dataOnce + id,
		Cause: audit.TapEditedMessage}
	if taps[refusedTapsPerMinute] != want {
		t.Errorf("report %+v, want %+v", taps[refusedTapsPerMinute], want)
	}
	ce.a.mu.Lock()
	others, own := ce.a.reports, ce.a.ownReports
	ce.a.mu.Unlock()
	if others.dropped != extra || own.dropped != 0 {
		t.Errorf("dropped %d reports of other users and %d of the approver, want %d and 0",
			others.dropped, own.dropped, extra)
	}
	if n := len(alertsSent(ce.f)); n != 1 {
		t.Errorf("%d alerts, want 1", n)
	}
	ce.f.tap(goodTap(msg, dataDeny+id))
	checkDeniedBy(t, waitResult(t, ch))
}

// TestDenyOnChangedMessageIsAlwaysReported: on a message that someone else
// changed, every Deny is reported with cause edited_message: the first
// one, which counts, and the second one of a double tap, which the core
// refuses because the request has ended. Before, only the second one was,
// so a single Deny left no trace of the edit in the audit log. Both
// reports use the approver's budget. (Issue #48, from its review.)
func TestDenyOnChangedMessageIsAlwaysReported(t *testing.T) {
	e := newEnv(t)
	e.a.now = (&fakeNow{t: noon}).now // both taps come in one minute
	p := secretsPrompt()
	e.a.remember(messageID(approverID, 70), keyboard(p).InlineKeyboard)
	core := &stubCore{}
	e.run(t, core.answer)
	s := goodTap(70, dataDeny+p.RequestID)
	s.edited = true
	first := e.f.tap(s)
	if got := e.f.waitAnswer(first).str("text"); got != tapChangedDenied {
		t.Errorf("the first Deny: the phone shows %q, want %q", got, tapChangedDenied)
	}
	e.f.waitHandled(first)
	core.setErr(approval.ErrUnknownRequest) // the first Deny ended the request
	second := e.f.tap(s)
	if got := e.f.waitAnswer(second).str("text"); got != tapEnded {
		t.Errorf("the second Deny: the phone shows %q, want %q", got, tapEnded)
	}
	e.f.waitHandled(second)
	if n := len(core.all()); n != 2 {
		t.Errorf("the core got %d answers, want both Denies", n)
	}
	want := audit.ForeignTap{UserID: approverID, ChatID: approverID, MessageID: 70, Data: dataDeny + p.RequestID,
		Cause: audit.TapEditedMessage}
	if taps := e.taps.all(); len(taps) != 2 || taps[0] != want || taps[1] != want {
		t.Errorf("reports %+v, want two of %+v", taps, want)
	}
	logs := e.logs.String()
	if strings.Count(logs, "a Deny counted on a message that someone else changed") != 1 ||
		strings.Count(logs, "refused a button press") != 1 {
		t.Errorf("the log does not say that the first Deny counted and the second was refused:\n%s", logs)
	}
	e.a.mu.Lock()
	own, others := e.a.ownReports.n, e.a.reports.n
	e.a.mu.Unlock()
	if own != 2 || others != 0 {
		t.Errorf("reports in the budget of the approver %d, of other users %d; want 2 and 0", own, others)
	}
	if n := len(alertsSent(e.f)); n != 1 {
		t.Errorf("%d alerts, want 1 in %s", n, changedAlertEvery)
	}
}

// btn is an inline button, as JSON.
func btn(text, data string) map[string]any {
	return map[string]any{"text": text, "callback_data": data}
}

// TestCoreDenyPathCannotApprove: on a message that someone else changed,
// only the Deny data that Ask sent on that very message reaches the core.
// Approve data under a "Deny" label is refused, and the Deny data of
// another waiting request, on another message, does not deny that
// request. (From the review of issue #48.)
func TestCoreDenyPathCannotApprove(t *testing.T) {
	ce := newCoreEnv(t, newFake(t))
	chA := ce.decide(secretsRequest("github-token"))
	idA, msgA := ce.asked(t, 1)
	chB := ce.decide(secretsRequest("db-password"))
	cB := ce.f.waitCalls("sendMessage", 2)[1]
	idB := cB.requestID()
	ce.waitTimers(t, 2)

	// The thief puts B's Deny and A's Approve data under A's labels, on A.
	ce.f.editByOther(msgA, map[string]any{"inline_keyboard": [][]map[string]any{{
		btn("Approve once", dataDeny+idB), btn("Approve 15 min", dataWindow+idA), btn("Deny", dataOnce+idA)}}}, true)
	taps := []string{dataDeny + idB, dataWindow + idA, dataOnce + idA}
	for _, data := range taps {
		cb := ce.f.tap(goodTap(msgA, data))
		// This text comes only when the tap is refused before the core.
		if got := ce.f.waitAnswer(cb).str("text"); got != tapChanged {
			t.Errorf("%s on the changed message: the phone shows %q, want %q", data[:2], got, tapChanged)
		}
		ce.f.waitHandled(cb)
	}
	select {
	case r := <-chA:
		t.Fatalf("request A ended: %+v", r)
	case r := <-chB:
		t.Fatalf("request B ended by data on A's message: %+v", r)
	default: // the results below show it for sure
	}
	reports := ce.taps.all()
	if len(reports) != len(taps) {
		t.Fatalf("reports %+v, want one for each tap", reports)
	}
	for i, tap := range reports {
		if tap.Cause != audit.TapEditedMessage || tap.Data != taps[i] {
			t.Errorf("report %+v, want data %q with cause edited_message", tap, taps[i])
		}
	}
	// A's own Deny data still denies A, whatever the label.
	ce.f.tap(goodTap(msgA, dataDeny+idA))
	checkDeniedBy(t, waitResult(t, chA))
	// B was not touched: its own Approve on its own message counts.
	ce.f.tap(goodTap(cB.MsgID, dataOnce+idB))
	if r := waitResult(t, chB); !r.Allowed || r.Answer != audit.AnswerApproveOnce {
		t.Errorf("request B: %+v, want approved once", r)
	}
}

// TestCoreTapAfterEndIsNoAttack: the second tap of a double tap can reach
// Telegram after End edited the message: then it has an edit date and no
// buttons. The broker made that edit itself, so this is a late tap, not an
// attack: no alert, and the message keeps its result.
func TestCoreTapAfterEndIsNoAttack(t *testing.T) {
	ce := newCoreEnv(t, newFake(t))
	ch := ce.decide(secretsRequest("github-token"))
	id, msg := ce.asked(t, 1)
	ce.f.waitAnswer(ce.f.tap(goodTap(msg, dataOnce+id)))
	if r := waitResult(t, ch); !r.Allowed {
		t.Fatalf("result %+v, want approved", r)
	}
	first := ce.f.waitCalls("editMessageText", 1)[0].str("text")
	if got := ce.f.waitAnswer(ce.f.tap(goodTap(msg, dataDeny+id))).str("text"); got != tapEnded {
		t.Errorf("the phone shows %q, want %q", got, tapEnded)
	}
	edits := ce.f.waitCalls("editMessageText", 2)
	if edits[1].str("text") != first || !strings.HasSuffix(first, "👍 approved once by you at 12:00:00") {
		t.Errorf("the message shows %q after the late tap", edits[1].str("text"))
	}
	if n := len(alertsSent(ce.f)); n != 0 {
		t.Errorf("%d alerts, want none", n)
	}
	if taps := ce.taps.all(); len(taps) != 1 || taps[0].Cause != audit.TapUnknownRequest {
		t.Errorf("reports %+v, want one with cause unknown_request", taps)
	}
}

// TestChangedAlertIsRateLimited checks that at most one alert about a
// changed message goes out in changedAlertEvery.
func TestChangedAlertIsRateLimited(t *testing.T) {
	e := newEnv(t)
	now := noon
	e.a.now = func() time.Time { return now }
	if !e.a.takeChangedAlert() {
		t.Error("the first alert was refused")
	}
	now = now.Add(changedAlertEvery - time.Second)
	if e.a.takeChangedAlert() {
		t.Error("a second alert within the limit was allowed")
	}
	now = now.Add(time.Second)
	if !e.a.takeChangedAlert() {
		t.Error("an alert after the limit was refused")
	}
}

// TestCoreRedeliveredTapKeepsResult: the broker approves a request, End
// shows "approved", and the broker stops before its next getUpdates
// confirmed the tap. After the restart, Telegram sends the tap again, with
// the message as it was at the tap. The new broker only removes the
// buttons: it must not replace the result that the person sees.
func TestCoreRedeliveredTapKeepsResult(t *testing.T) {
	f := newFake(t)
	old := newCoreEnv(t, f)
	ch := old.decide(secretsRequest("github-token"))
	id, msg := old.asked(t, 1)
	sent := f.callsOf("sendMessage")[0]
	raw, err := json.Marshal(map[string]any{"update_id": 5000, "callback_query": map[string]any{
		"id": "approve", "from": map[string]any{"id": approverID}, "chat_instance": "1", "data": dataOnce + id,
		"message": map[string]any{
			"message_id": msg, "date": 1, "text": "the text",
			"chat":         map[string]any{"id": approverID, "type": "private"},
			"reply_markup": json.RawMessage(sent.field("reply_markup")),
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	f.addRawUpdate(5000, string(raw))
	if r := waitResult(t, ch); !r.Allowed {
		t.Fatalf("result %+v, want approved", r)
	}
	approved := f.waitCalls("editMessageText", 1)[0].str("text")
	f.waitAnswer("approve")
	// The getUpdates after the tap confirms it. When the broker stops, that
	// call may still be on its way. If it reached the fake after the tap
	// below, the fake would take that tap as confirmed and drop it. After
	// exit, no call of the old broker reaches the fake any more.
	old.exit(t)

	f.addRawUpdate(5000, string(raw)) // Telegram sends the tap again
	ce := newCoreEnv(t, f)
	if got := f.waitAnswers("approve", 2)[1].str("text"); got != tapEnded {
		t.Errorf("after the restart, the phone shows %q, want %q", got, tapEnded)
	}
	edit := f.waitCalls("editMessageReplyMarkup", 1)[0]
	if edit.num("message_id") != msg || edit.field("reply_markup") != `{"inline_keyboard":[]}` {
		t.Errorf("edit %s, want the buttons of message %d removed", edit.Raw, msg)
	}
	texts := ce.edits(msg)
	if len(texts) != 1 || texts[0] != approved || !strings.Contains(approved, "👍 approved once by you") {
		t.Errorf("the text edits of the message: %q, want only the approval", texts)
	}
	// The report comes before the update of the message.
	if taps := ce.taps.all(); len(taps) != 1 || taps[0].Cause != audit.TapUnknownRequest {
		t.Errorf("reports %+v, want one with cause unknown_request", taps)
	}
}

// dropFirstSend serves the fake Telegram, but for the first sendMessage
// the fake sends the message and the answer is lost: the connection
// closes. So the client tries again, and the person gets two messages.
type dropFirstSend struct {
	f       *fakeTelegram
	dropped atomic.Bool
}

func (d *dropFirstSend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/sendMessage") && !d.dropped.Swap(true) {
		d.f.ServeHTTP(httptest.NewRecorder(), r)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
		return
	}
	d.f.ServeHTTP(w, r)
}

// TestCoreDuplicateAfterRetry: only the message that Telegram confirmed
// counts. A tap on the copy whose answer was lost is refused, End edits
// only the confirmed one, and a late tap on the copy removes its buttons.
func TestCoreDuplicateAfterRetry(t *testing.T) {
	f := newFake(t)
	srv := httptest.NewServer(&dropFirstSend{f: f})
	t.Cleanup(srv.Close)
	e := newEnvFor(t, f)
	e.a.api.base = srv.URL
	clock := approvaltest.NewClock(noon)
	core, err := approval.New(coreConfig(), e.a, approval.Options{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- core.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-runErr })
	f.waitCalls("getUpdates", 1)

	ch := make(chan *approval.Result, 1)
	go func() { ch <- core.Decide(context.Background(), secretsRequest("github-token")) }()
	calls := f.waitCalls("sendMessage", 2)
	lost, confirmed := calls[0], calls[1]
	id := confirmed.requestID()
	if lost.requestID() != id {
		t.Fatal("the two copies have other IDs")
	}
	deadline := time.Now().Add(waitLimit)
	for clock.Timers() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("the request does not wait")
		}
		time.Sleep(time.Millisecond)
	}
	if got := f.waitAnswer(f.tap(goodTap(lost.MsgID, dataOnce+id))).str("text"); got != tapRefused {
		t.Errorf("a tap on the lost copy: the phone shows %q", got)
	}
	f.tap(goodTap(confirmed.MsgID, dataDeny+id))
	if r := waitResult(t, ch); r.Allowed || r.Answer != audit.AnswerDeny {
		t.Errorf("result %+v, want the Deny on the confirmed message", r)
	}
	f.waitCalls("editMessageText", 1)
	for _, c := range f.callsOf("editMessageText") {
		if c.num("message_id") != confirmed.MsgID {
			t.Errorf("End edited message %d, want only %d", c.num("message_id"), confirmed.MsgID)
		}
	}
	if got := f.waitAnswer(f.tap(goodTap(lost.MsgID, dataOnce+id))).str("text"); got != tapEnded {
		t.Errorf("a late tap on the lost copy: the phone shows %q", got)
	}
	if edit := f.waitCalls("editMessageReplyMarkup", 1)[0]; edit.num("message_id") != lost.MsgID {
		t.Errorf("the buttons of message %d were removed, want %d", edit.num("message_id"), lost.MsgID)
	}
}

// TestUserIDMustBeAnInteger: the user ID of a tap is read as a JSON
// integer. A string, or a number with a fraction or an exponent, makes an
// update of the wrong form, and null is no user. None reaches the core.
func TestUserIDMustBeAnInteger(t *testing.T) {
	e := newEnv(t)
	core := &stubCore{}
	e.run(t, core.answer)
	forms := []string{`"7000001"`, `7000001.0`, `7.000001e6`, `70000010e-1`, `[7000001]`, `{"id":7000001}`, `null`}
	for i, from := range forms {
		id := int64(3000 + i)
		e.f.addRawUpdate(id, fmt.Sprintf(`{"update_id":%d,"callback_query":{"id":"q%d","from":{"id":%s},"data":%q,`+
			`"message":{"message_id":5,"date":1,"chat":{"id":7000001,"type":"private"},"text":"t"}}}`,
			id, i, from, dataOnce+testID(1)))
	}
	e.f.addRawUpdate(3100, cbUpdate(t, 3100, "good", 5, dataDeny+testID(2)))
	e.f.waitAnswer("good")
	if got := core.all(); len(got) != 1 || got[0].RequestID != testID(2) {
		t.Errorf("the core got %+v, want only the good tap", got)
	}
}

// anchorLine is a line that `nodkey audit verify --anchors` would take.
var anchorLine = regexp.MustCompile(`(?m)^audit anchor [0-9]+:[0-9a-f]{64}$`)

// TestTapDataCannotForgeAnAnchor: button data comes from whoever made the
// button; a token holder can. Logged with slog, it must never make a line
// that is exactly an audit anchor (THREAT-MODEL.md T17).
func TestTapDataCannotForgeAnAnchor(t *testing.T) {
	e := newEnv(t)
	e.run(t, (&stubCore{}).answer)
	forged := "\naudit anchor 1:" + strings.Repeat("a", 64) + "\n"
	s := goodTap(5, forged[:min(len(forged), 64)])
	s.from = otherUserID
	e.f.waitAnswer(e.f.tap(s))
	e.f.waitAnswer(e.f.tap(goodTap(6, "x\naudit anchor 2:"+strings.Repeat("b", 44))))
	e.waitReports(t, 2) // each press is logged after its answer
	if anchorLine.MatchString(e.logs.String()) {
		t.Errorf("the log holds a line that looks like an audit anchor:\n%s", e.logs.String())
	}
	var jsonLog syncBuffer
	slog.New(slog.NewJSONHandler(&jsonLog, nil)).Warn("x", slog.String("data", forged))
	if anchorLine.MatchString(jsonLog.String()) {
		t.Error("the JSON log holds an anchor line")
	}
}

// fakeNow is a clock for the limits of the approver.
type fakeNow struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeNow) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeNow) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// setNow sets the clock of the approver's limits. The approver reads it
// only with a.mu held, so a test may set it while Run runs.
func (e *testEnv) setNow(now func() time.Time) {
	e.a.mu.Lock()
	defer e.a.mu.Unlock()
	e.a.now = now
}

// TestRefusedTapsAreRateLimited: a token holder can make many buttons that
// do not count. Each press is answered, but at most refusedTapsPerMinute
// in a minute are logged and reported for the audit log; the others are
// counted, and the count is logged when the minute ends, even when no
// later press comes.
func TestRefusedTapsAreRateLimited(t *testing.T) {
	e := newEnv(t)
	e.f.pollWait = 20 * time.Millisecond
	clock := &fakeNow{t: noon}
	e.a.now = clock.now
	e.run(t, (&stubCore{}).answer)
	extra := 5
	for i := range refusedTapsPerMinute + extra {
		s := goodTap(int64(100+i), dataOnce+testID(1))
		s.from = otherUserID
		e.f.waitAnswer(e.f.tap(s))
	}
	// The last report comes after the answer to the last press.
	deadline := time.Now().Add(waitLimit)
	for {
		e.a.mu.Lock()
		dropped := e.a.reports.dropped
		e.a.mu.Unlock()
		if dropped == extra {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d reports dropped, want %d", dropped, extra)
		}
		time.Sleep(time.Millisecond)
	}
	if n := len(e.taps.all()); n != refusedTapsPerMinute {
		t.Errorf("%d reports, want %d", n, refusedTapsPerMinute)
	}
	if n := strings.Count(e.logs.String(), "refused a button press"); n != refusedTapsPerMinute {
		t.Errorf("%d log lines, want %d", n, refusedTapsPerMinute)
	}
	clock.add(time.Minute)
	deadline = time.Now().Add(waitLimit)
	logged := fmt.Sprintf("dropped=%d limit_per_minute=%d from=other_users", extra, refusedTapsPerMinute)
	for !strings.Contains(e.logs.String(), logged) {
		if time.Now().After(deadline) {
			t.Fatalf("the dropped reports are not logged:\n%s", e.logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	// A new minute: reports go out again.
	s := goodTap(200, dataOnce+testID(1))
	s.from = otherUserID
	e.f.waitAnswer(e.f.tap(s))
	e.waitReports(t, refusedTapsPerMinute+1)
}

// TestApproverTapsHaveTheirOwnBudget: the approver's own refused taps have
// a budget of their own, with the same cap. A person taps only a few times
// a minute, and an account that someone else uses (THREAT-MODEL.md T7)
// must not fill the journal either. The taps of other users still get
// their reports, and the count of dropped reports names its budget.
// (Issue #48.)
func TestApproverTapsHaveTheirOwnBudget(t *testing.T) {
	e := newEnv(t)
	clock := &fakeNow{t: noon}
	e.a.now = clock.now
	e.run(t, (&stubCore{}).answer)
	extra := 3
	for i := range refusedTapsPerMinute + extra {
		e.f.waitAnswer(e.f.tap(goodTap(int64(100+i), "x"))) // bad data
	}
	other := tapSpec{from: otherUserID, chatID: otherUserID, chatType: "private", msgID: 300, data: "x"}
	cb := e.f.tap(other)
	e.f.waitHandled(cb)
	taps := e.taps.all()
	if len(taps) != refusedTapsPerMinute+1 {
		t.Fatalf("%d reports, want %d of the approver and 1 of another user", len(taps), refusedTapsPerMinute+1)
	}
	for _, tap := range taps[:refusedTapsPerMinute] {
		if tap.UserID != approverID || tap.Cause != audit.TapBadData {
			t.Errorf("report %+v, want the approver's tap with cause bad_data", tap)
		}
	}
	if last := taps[refusedTapsPerMinute]; last.UserID != otherUserID || last.Cause != audit.TapOtherUser {
		t.Errorf("report %+v, want the tap of the other user", last)
	}
	e.a.mu.Lock()
	others, own := e.a.reports, e.a.ownReports
	e.a.mu.Unlock()
	if own.dropped != extra || others.dropped != 0 || others.n != 1 {
		t.Errorf("budgets: approver %+v, other users %+v; want %d dropped of the approver, and 1 report of others",
			own, others, extra)
	}

	// When the minute has ended, the count is logged with its budget.
	clock.add(time.Minute)
	e.f.waitHandled(e.f.tap(other))
	logs := e.logs.String()
	if want := fmt.Sprintf("dropped=%d limit_per_minute=%d from=approver", extra, refusedTapsPerMinute); !strings.Contains(logs, want) {
		t.Errorf("the log does not hold %q:\n%s", want, logs)
	}
	if strings.Contains(logs, "from=other_users") {
		t.Errorf("the log holds a count of dropped reports of other users:\n%s", logs)
	}
	if n := len(e.taps.all()); n != refusedTapsPerMinute+2 {
		t.Errorf("%d reports, want %d: a new minute", n, refusedTapsPerMinute+2)
	}
}
