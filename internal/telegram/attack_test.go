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

// TestCoreEditedMessageDoesNotCount: with a stolen token, someone can edit
// the text of a message that waits for an answer, for example to show a
// harmless secret name, and keep its buttons. The broker never edits a
// message while its request waits, so no tap on it counts. Each tap is
// reported, the approver gets one alert, and the request can only expire.
// End then writes the true text again.
func TestCoreEditedMessageDoesNotCount(t *testing.T) {
	ce := newCoreEnv(t, newFake(t))
	ch := ce.decide(secretsRequest("db-password"))
	id, msg := ce.asked(t, 1)
	ce.f.editByOther(msg, nil, true)
	for _, data := range []string{dataOnce + id, dataDeny + id} {
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
// does not count.
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
	ce.clock.Advance(120 * time.Second)
	if r := waitResult(t, ch); r.Allowed {
		t.Errorf("result %+v, want denied", r)
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
	old.stop()
	select {
	case err := <-old.runErr:
		old.runErr <- err // for the cleanup
	case <-time.After(waitLimit):
		t.Fatal("the old core did not stop")
	}

	f.addRawUpdate(5000, string(raw)) // Telegram sends the tap again
	ce := newCoreEnv(t, f)
	f.waitAnswer("approve")
	edit := f.waitCalls("editMessageReplyMarkup", 1)[0]
	if edit.num("message_id") != msg || edit.field("reply_markup") != `{"inline_keyboard":[]}` {
		t.Errorf("edit %s, want the buttons of message %d removed", edit.Raw, msg)
	}
	texts := ce.edits(msg)
	if len(texts) != 1 || texts[0] != approved || !strings.Contains(approved, "👍 approved once by you") {
		t.Errorf("the text edits of the message: %q, want only the approval", texts)
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
	for !strings.Contains(e.logs.String(), fmt.Sprintf("dropped=%d", extra)) {
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
