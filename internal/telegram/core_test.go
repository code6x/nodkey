package telegram

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/approval/approvaltest"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/claim"
	"github.com/code6x/nodkey/internal/config"
)

// These tests run the real approval core with the Telegram approver and a
// fake Telegram server (DESIGN.md section 17): a tap from the wrong user,
// chat or message, an unknown ID, an early, a late and a double tap, and a
// polling conflict. Each one also shows the deny path.

// noon is the start of the fake clock of the core.
var noon = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

// coreEnv is a running core whose approver talks to a fake server.
type coreEnv struct {
	*testEnv
	clock  *approvaltest.Clock
	core   *approval.Core
	runErr chan error
	stop   context.CancelFunc
}

// coreConfig is a broker config as LoadBroker would make it: clients
// laptop and ci; secrets github-token (window 15m), db-password (always)
// and backup-token (never, with a notice, for ci only).
func coreConfig() *config.Broker {
	return &config.Broker{
		Telegram: testTelegramConfig(),
		Clients:  map[string]config.Client{"laptop": {Name: "laptop"}, "ci": {Name: "ci"}},
		Secrets: map[string]config.Secret{
			"github-token": {Name: "github-token", Clients: []string{"laptop"},
				Rule: config.Rule{Ask: config.AskWindow, Window: 15 * time.Minute}},
			"db-password": {Name: "db-password", Clients: []string{"laptop"}, Rule: config.Rule{Ask: config.AskAlways}},
			"backup-token": {Name: "backup-token", Clients: []string{"ci"},
				Rule: config.Rule{Ask: config.AskNever, Notify: true}},
		},
	}
}

// newCoreEnv starts a core with a Telegram approver for the fake f.
func newCoreEnv(t *testing.T, f *fakeTelegram) *coreEnv {
	t.Helper()
	e := newEnvFor(t, f)
	clock := approvaltest.NewClock(noon)
	core, err := approval.New(coreConfig(), e.a, approval.Options{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ce := &coreEnv{testEnv: e, clock: clock, core: core, runErr: make(chan error, 1), stop: cancel}
	polls := len(f.callsOf("getUpdates"))
	go func() { ce.runErr <- core.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-ce.runErr:
		case <-time.After(waitLimit):
			t.Error("the core's Run did not return")
		}
	})
	f.waitCalls("getUpdates", polls+1)
	return ce
}

// secretsRequest is a request of laptop for one secret.
func secretsRequest(secret string) *approval.Request {
	return &approval.Request{
		Client:  "laptop",
		Kind:    audit.KindSecrets,
		Secrets: []string{secret},
		Claim: approval.Claim{
			Vars: "GH_TOKEN", Command: "gh release create v1.2.0", Dir: "/home/dev/src/app",
			Reason: "publish the release the user asked for",
		},
	}
}

// decide starts Decide for r.
func (ce *coreEnv) decide(r *approval.Request) <-chan *approval.Result {
	ch := make(chan *approval.Result, 1)
	go func() { ch <- ce.core.Decide(context.Background(), r) }()
	return ch
}

// asked waits for the n-th message, and until its request waits for an
// answer: Ask has returned, and the core waits on a timer of the fake
// clock. It returns the request ID and the message ID.
func (ce *coreEnv) asked(t *testing.T, n int) (string, int64) {
	t.Helper()
	c := ce.f.waitCalls("sendMessage", n)[n-1]
	id := c.requestID()
	if !validRequestID(id) {
		t.Fatalf("message %d has no request ID in its buttons: %s", n, c.Raw)
	}
	ce.waitTimers(t, 1)
	return id, c.MsgID
}

// waitTimers waits until n timers of the fake clock wait to fire.
func (ce *coreEnv) waitTimers(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(waitLimit)
	for ce.clock.Timers() < n {
		if time.Now().After(deadline) {
			t.Fatalf("waited %s in vain for %d timers", waitLimit, n)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitResult(t *testing.T, ch <-chan *approval.Result) *approval.Result {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(waitLimit):
		t.Fatal("no decision")
		return nil
	}
}

// checkDeniedBy checks that r is the Deny of the approver: the last tap
// of a test, after taps that must not count.
func checkDeniedBy(t *testing.T, r *approval.Result) {
	t.Helper()
	if r.Allowed || r.Answer != audit.AnswerDeny || r.UserID != approverID || r.Cause != audit.CauseApprover {
		t.Errorf("result %+v, want the approver's Deny", r)
	}
}

// edits returns the texts of the edits of message msgID.
func (ce *coreEnv) edits(msgID int64) []string {
	var texts []string
	for _, c := range ce.f.callsOf("editMessageText") {
		if c.num("message_id") == msgID {
			texts = append(texts, c.str("text"))
		}
	}
	return texts
}

func TestCoreApproveOnce(t *testing.T) {
	ce := newCoreEnv(t, newFake(t))
	ch := ce.decide(secretsRequest("github-token"))
	id, msg := ce.asked(t, 1)
	sent := ce.f.callsOf("sendMessage")[0]
	if sent.num("chat_id") != approverID || sent.str("parse_mode") != "HTML" ||
		sent.field("link_preview_options") != `{"is_disabled":true}` || sent.has("disable_notification") {
		t.Errorf("sendMessage %s", sent.Raw)
	}
	cb := ce.f.tap(goodTap(msg, dataOnce+id))
	r := waitResult(t, ch)
	if !r.Allowed || r.Answer != audit.AnswerApproveOnce || r.UserID != approverID {
		t.Errorf("result %+v, want approve once", r)
	}
	if got := ce.f.waitAnswer(cb).str("text"); got != tapCountedApprove {
		t.Errorf("the phone shows %q", got)
	}
	wantText := "🔑 Secrets · request " + r.ShortCode + "\n✅ machine: laptop\n✅ secrets: github-token\n" +
		"— claimed by the agent —\nas: GH_TOKEN\ncommand: gh release create v1.2.0\nin: /home/dev/src/app\n" +
		"reason: publish the release the user asked for\nexpires 12:02:00 (120 s)\n" +
		"[ Approve once ] [ Approve 15 min ] [ Deny ]"
	if r.Message != wantText {
		t.Errorf("the text for the audit log:\n%s\nwant:\n%s", r.Message, wantText)
	}
	edit := ce.f.waitCalls("editMessageText", 1)[0]
	if edit.num("message_id") != msg || edit.field("reply_markup") != `{"inline_keyboard":[]}` ||
		!strings.HasSuffix(edit.str("text"), "\n👍 approved once by you at 12:00:00") ||
		strings.Contains(edit.str("text"), "expires") {
		t.Errorf("edit %s", edit.Raw)
	}
	if taps := ce.taps.all(); len(taps) != 0 {
		t.Errorf("reports %+v, want none", taps)
	}
}

func TestCoreApproveWindowAndDeny(t *testing.T) {
	ce := newCoreEnv(t, newFake(t))
	ch := ce.decide(secretsRequest("github-token"))
	id, msg := ce.asked(t, 1)
	ce.f.tap(goodTap(msg, dataWindow+id))
	r := waitResult(t, ch)
	if !r.Allowed || r.Answer != audit.AnswerApproveWindow || r.WindowMinutes != 15 {
		t.Errorf("result %+v, want approve for 15 min", r)
	}
	ce.f.waitFor("the edit", func() bool { return len(ce.f.callsOfLocked("editMessageText")) == 1 })
	if texts := ce.edits(msg); len(texts) != 1 || !strings.HasSuffix(texts[0], "👍 approved for 15 min by you at 12:00:00") {
		t.Errorf("edits %q", texts)
	}

	ch = ce.decide(secretsRequest("db-password"))
	id, msg = ce.asked(t, 2)
	cb := ce.f.tap(goodTap(msg, dataDeny+id))
	checkDeniedBy(t, waitResult(t, ch))
	if got := ce.f.waitAnswer(cb).str("text"); got != tapCountedDeny {
		t.Errorf("the phone shows %q", got)
	}
	ce.f.waitFor("the edit", func() bool { return len(ce.f.callsOfLocked("editMessageText")) == 2 })
	if texts := ce.edits(msg); len(texts) != 1 || !strings.HasSuffix(texts[0], "⛔ denied by you at 12:00:00") {
		t.Errorf("edits %q", texts)
	}
}

// TestCoreEarlyTap checks a tap that comes while the message is still
// being sent: it does not count, the message is not marked expired, it is
// no foreign tap, and the person can tap again.
func TestCoreEarlyTap(t *testing.T) {
	f := newFake(t)
	ce := newCoreEnv(t, f)
	release := f.hold("sendMessage")
	defer release()
	ch := ce.decide(secretsRequest("github-token"))
	held := f.waitCalls("sendMessage", 1)[0]
	id, msg := held.requestID(), held.MsgID
	cb := f.tap(goodTap(msg, dataOnce+id))
	if got := f.waitAnswer(cb).str("text"); got != tapTooEarly {
		t.Errorf("the phone shows %q, want %q", got, tapTooEarly)
	}
	if n := len(f.callsOf("editMessageText")); n != 0 {
		t.Errorf("%d edits after an early tap, want 0", n)
	}
	if taps := ce.taps.all(); len(taps) != 0 {
		t.Errorf("reports %+v after an early tap, want none", taps)
	}
	release()
	// Ask returns, and the request waits. Taps until one counts.
	for i := 0; ; i++ {
		cb = f.tap(goodTap(msg, dataDeny+id))
		if f.waitAnswer(cb).str("text") != tapTooEarly {
			break
		}
		if i > 100 {
			t.Fatal("the request never took a tap")
		}
		time.Sleep(10 * time.Millisecond)
	}
	checkDeniedBy(t, waitResult(t, ch))
}

// TestCoreLateTap checks a tap after the request expired: it does not
// count, it is reported, and the message keeps its result. It is not
// marked "expired: no longer waits", because this approver ended it.
func TestCoreLateTap(t *testing.T) {
	ce := newCoreEnv(t, newFake(t))
	ch := ce.decide(secretsRequest("github-token"))
	id, msg := ce.asked(t, 1)
	ce.clock.Advance(120 * time.Second)
	r := waitResult(t, ch)
	if r.Allowed || r.Cause != audit.CauseExpired || r.Answer != "" {
		t.Fatalf("result %+v, want expired", r)
	}
	ce.f.waitCalls("editMessageText", 1)
	cb := ce.f.tap(goodTap(msg, dataOnce+id))
	if got := ce.f.waitAnswer(cb).str("text"); got != tapEnded {
		t.Errorf("the phone shows %q", got)
	}
	edits := ce.f.waitCalls("editMessageText", 2)
	for _, ed := range edits {
		if !strings.HasSuffix(ed.str("text"), "\n⌛ expired — denied") || ed.num("message_id") != msg ||
			ed.field("reply_markup") != `{"inline_keyboard":[]}` {
			t.Errorf("edit %s", ed.Raw)
		}
	}
	taps := ce.taps.all()
	want := audit.ForeignTap{UserID: approverID, ChatID: approverID, MessageID: msg, Data: dataOnce + id,
		Cause: audit.TapUnknownRequest}
	if len(taps) != 1 || taps[0] != want {
		t.Errorf("reports %+v, want %+v", taps, want)
	}
}

// TestCoreDoubleTap checks two taps on one message in a row: the first
// counts, the second does not, and the message shows the first result,
// never "expired".
func TestCoreDoubleTap(t *testing.T) {
	ce := newCoreEnv(t, newFake(t))
	ch := ce.decide(secretsRequest("github-token"))
	id, msg := ce.asked(t, 1)
	cb1 := ce.f.tap(goodTap(msg, dataOnce+id))
	cb2 := ce.f.tap(goodTap(msg, dataDeny+id))
	r := waitResult(t, ch)
	if !r.Allowed || r.Answer != audit.AnswerApproveOnce {
		t.Errorf("result %+v, want the first tap: approve once", r)
	}
	if got := ce.f.waitAnswer(cb1).str("text"); got != tapCountedApprove {
		t.Errorf("first tap: the phone shows %q", got)
	}
	if got := ce.f.waitAnswer(cb2).str("text"); got != tapEnded {
		t.Errorf("second tap: the phone shows %q", got)
	}
	ce.f.waitCalls("editMessageText", 1)
	// The core is done when Decide returned; give a late edit time to come.
	time.Sleep(50 * time.Millisecond)
	for _, text := range ce.edits(msg) {
		if !strings.HasSuffix(text, "👍 approved once by you at 12:00:00") {
			t.Errorf("an edit shows %q", text)
		}
	}
	if taps := ce.taps.all(); len(taps) != 1 || taps[0].Data != dataDeny+id {
		t.Errorf("reports %+v, want the second tap", taps)
	}
}

// TestCoreTapFromBeforeRestart checks a tap on a message that this broker
// did not send, such as one from before a crash: no request waits, so the
// tap is reported, and only the buttons of the message are removed. Its
// text stays as the old broker left it.
func TestCoreTapFromBeforeRestart(t *testing.T) {
	f := newFake(t)
	old := newCoreEnv(t, f)
	old.decide(secretsRequest("github-token"))
	id, msg := old.asked(t, 1)
	// A crash: the old broker cannot update its message before it is gone.
	for range maxTries {
		f.reply("editMessageText", 500, `{"ok":false,"error_code":500,"description":"Internal Server Error"}`)
	}
	old.stop()
	f.waitCalls("editMessageText", maxTries)
	ce := newCoreEnv(t, f)
	cb := f.tap(goodTap(msg, dataOnce+id))
	if got := f.waitAnswer(cb).str("text"); got != tapEnded {
		t.Errorf("the phone shows %q", got)
	}
	edit := f.waitCalls("editMessageReplyMarkup", 1)[0]
	if edit.num("message_id") != msg || edit.field("reply_markup") != `{"inline_keyboard":[]}` {
		t.Errorf("edit %s, want the buttons of message %d removed", edit.Raw, msg)
	}
	if n := len(f.callsOf("editMessageText")); n != maxTries {
		t.Errorf("%d text edits, want only the %d of the old broker", n, maxTries)
	}
	if taps := ce.taps.all(); len(taps) != 1 || taps[0].Cause != audit.TapUnknownRequest {
		t.Errorf("reports %+v, want 1 with cause unknown_request", taps)
	}
}

// TestCoreWrongMessage checks a tap with the right button data on another
// message in the private chat, such as a copy of the message: it does not
// count, and the request still waits.
func TestCoreWrongMessage(t *testing.T) {
	ce := newCoreEnv(t, newFake(t))
	ch := ce.decide(secretsRequest("github-token"))
	id, msg := ce.asked(t, 1)
	cb := ce.f.tap(goodTap(msg+100, dataOnce+id))
	if got := ce.f.waitAnswer(cb).str("text"); got != tapRefused {
		t.Errorf("the phone shows %q", got)
	}
	if n := len(ce.f.callsOf("editMessageText")); n != 0 {
		t.Errorf("%d edits, want 0", n)
	}
	ce.f.tap(goodTap(msg, dataDeny+id))
	checkDeniedBy(t, waitResult(t, ch))
	want := audit.ForeignTap{UserID: approverID, ChatID: approverID, MessageID: msg + 100, Data: dataOnce + id,
		Cause: audit.TapWrongMessage}
	if taps := ce.taps.all(); len(taps) != 1 || taps[0] != want {
		t.Errorf("reports %+v, want %+v", taps, want)
	}
}

// TestCoreForeignTaps checks taps from another user, in another chat and
// on an inline message: the core never sees them, and the request still
// waits.
func TestCoreForeignTaps(t *testing.T) {
	ce := newCoreEnv(t, newFake(t))
	ch := ce.decide(secretsRequest("github-token"))
	id, msg := ce.asked(t, 1)
	other := goodTap(msg, dataOnce+id)
	other.from = otherUserID
	group := goodTap(msg, dataOnce+id)
	group.chatID, group.chatType = groupChatID, "supergroup"
	inline := goodTap(msg, dataOnce+id)
	inline.inline = true
	for _, s := range []tapSpec{other, group, inline} {
		ce.f.waitAnswer(ce.f.tap(s))
	}
	ce.f.tap(goodTap(msg, dataDeny+id))
	checkDeniedBy(t, waitResult(t, ch))
	if n := len(ce.taps.all()); n != 3 {
		t.Errorf("%d reports, want 3", n)
	}
}

// TestCoreExpiredTap checks a tap after the request's time is up on the
// wall clock, before the core ended the request: it does not count, and
// the message is left for End, which marks it expired.
func TestCoreExpiredTap(t *testing.T) {
	ce := newCoreEnv(t, newFake(t))
	ch := ce.decide(secretsRequest("github-token"))
	id, msg := ce.asked(t, 1)
	ce.clock.JumpWall(120 * time.Second) // as a host that slept
	cb := ce.f.tap(goodTap(msg, dataOnce+id))
	if got := ce.f.waitAnswer(cb).str("text"); got != tapExpired {
		t.Errorf("the phone shows %q", got)
	}
	if n := len(ce.f.callsOf("editMessageText")); n != 0 {
		t.Errorf("%d edits, want 0", n)
	}
	ce.clock.Advance(120 * time.Second)
	r := waitResult(t, ch)
	if r.Allowed || r.Cause != audit.CauseExpired {
		t.Errorf("result %+v, want expired", r)
	}
	edit := ce.f.waitCalls("editMessageText", 1)[0]
	if !strings.HasSuffix(edit.str("text"), "⌛ expired — denied") {
		t.Errorf("edit %q", edit.str("text"))
	}
	if n := len(ce.taps.all()); n != 1 {
		t.Errorf("%d reports, want 1", n)
	}
}

// TestCoreButtonNotOffered checks a press of a button that the request
// does not offer, such as "Approve N min" for a secret that is always
// asked for.
func TestCoreButtonNotOffered(t *testing.T) {
	ce := newCoreEnv(t, newFake(t))
	ch := ce.decide(secretsRequest("db-password"))
	id, msg := ce.asked(t, 1)
	if data := ce.f.callsOf("sendMessage")[0].buttonData(); len(data) != 2 ||
		data[0] != dataOnce+id || data[1] != dataDeny+id {
		t.Errorf("buttons %q, want Approve once and Deny", data)
	}
	cb := ce.f.tap(goodTap(msg, dataWindow+id))
	if got := ce.f.waitAnswer(cb).str("text"); got != tapRefused {
		t.Errorf("the phone shows %q", got)
	}
	ce.f.tap(goodTap(msg, dataDeny+id))
	checkDeniedBy(t, waitResult(t, ch))
	if n := len(ce.taps.all()); n != 1 {
		t.Errorf("%d reports, want 1", n)
	}
}

// TestCorePollConflict checks that a polling conflict stops the core: the
// waiting request is denied, its message says why, and the approver gets
// an alert.
func TestCorePollConflict(t *testing.T) {
	f := newFake(t)
	f.pollWait = 50 * time.Millisecond
	ce := newCoreEnv(t, f)
	ch := ce.decide(secretsRequest("github-token"))
	_, msg := ce.asked(t, 1)
	f.reply("getUpdates", 409, `{"ok":false,"error_code":409,"description":"Conflict: terminated by other getUpdates request"}`)
	select {
	case err := <-ce.runErr:
		if !errors.Is(err, ErrPollConflict) {
			t.Errorf("the core's Run: %v, want ErrPollConflict", err)
		}
		ce.runErr <- err // for the cleanup
	case <-time.After(waitLimit):
		t.Fatal("the core's Run did not return")
	}
	r := waitResult(t, ch)
	if r.Allowed || r.Cause != audit.CauseError || r.ErrorCode != audit.CodeApproverFailed {
		t.Errorf("result %+v, want denied with approver_failed", r)
	}
	alert := f.callsOf("sendMessage")[1]
	if !strings.Contains(alert.str("text"), "may be stolen") || alert.num("chat_id") != approverID {
		t.Errorf("alert %s", alert.Raw)
	}
	f.waitCalls("editMessageText", 1)
	if texts := ce.edits(msg); len(texts) != 1 || !strings.HasSuffix(texts[0], "⛔ denied: the broker stopped taking answers") {
		t.Errorf("edits %q", texts)
	}
	// No new request gets a message now.
	r = waitResult(t, ce.decide(secretsRequest("db-password")))
	if r.Allowed || len(f.callsOf("sendMessage")) != 2 {
		t.Errorf("a new request after the conflict: %+v", r)
	}
}

// TestCoreNotice checks that a "never ask" use sends a silent notice to
// the notice chat, and that the use is denied when the notice cannot be
// sent.
func TestCoreNotice(t *testing.T) {
	ce := newCoreEnv(t, newFake(t))
	req := &approval.Request{Client: "ci", Kind: audit.KindSecrets, Secrets: []string{"backup-token"},
		Claim: approval.Claim{Command: "restic backup /srv"}}
	r := waitResult(t, ce.decide(req))
	if !r.Allowed {
		t.Errorf("result %+v, want allowed", r)
	}
	notice := ce.f.callsOf("sendMessage")[0]
	if notice.num("chat_id") != noticeChatID || notice.field("disable_notification") != "true" || notice.has("reply_markup") ||
		!strings.Contains(notice.str("text"), claim.HTML(noticeLine)) {
		t.Errorf("notice %s", notice.Raw)
	}
	ce.f.reply("sendMessage", 400, `{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`)
	r = waitResult(t, ce.decide(req))
	if r.Allowed || r.Cause != audit.CauseError || r.ErrorCode != audit.CodeApproverFailed {
		t.Errorf("result %+v, want denied with approver_failed", r)
	}
}

// TestCoreSendFails checks that a request is denied when its message
// cannot be sent, and that nothing is edited then.
func TestCoreSendFails(t *testing.T) {
	ce := newCoreEnv(t, newFake(t))
	ce.f.reply("sendMessage", 403, `{"ok":false,"error_code":403,"description":"Forbidden: bot was blocked by the user"}`)
	r := waitResult(t, ce.decide(secretsRequest("github-token")))
	if r.Allowed || r.Cause != audit.CauseError || r.ErrorCode != audit.CodeApproverFailed || r.Message != "" {
		t.Errorf("result %+v, want denied with approver_failed", r)
	}
	if r.Err == nil || !strings.Contains(r.Err.Error(), "(403)") {
		t.Errorf("the error %v does not say why", r.Err)
	}
	if n := len(ce.f.callsOf("editMessageText")); n != 0 {
		t.Errorf("%d edits, want 0", n)
	}
}

// TestCoreGlobalNoticeLimit checks a "never ask" use when Notify refuses
// it because of the limit for all clients together. For the core,
// ErrNoticeLimit is a limit: it denies the use with cause limit, as for
// its own limit per client, without an error, and the use does not count
// for max_per_day. So with max_per_day = 1, the next use on the same day
// still goes without a tap once the limit has room, and the one after it
// asks the person. Before, the refused use was an approver failure, and
// it used up the one use of the day. DESIGN.md section 7 says so. (Issue
// #47.)
func TestCoreGlobalNoticeLimit(t *testing.T) {
	f := newFake(t)
	e := newEnvFor(t, f)
	cfg := coreConfig()
	s := cfg.Secrets["backup-token"]
	s.Rule.MaxPerDay = 1
	cfg.Secrets["backup-token"] = s
	clock := &fakeNow{t: time.Now()}
	e.a.now = clock.now
	for range NoticesPerMinute {
		e.a.takeNotice() // other clients used the notices of this minute
	}
	core, err := approval.New(cfg, e.a, approval.Options{Clock: approvaltest.NewClock(noon)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- core.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-runErr })
	f.waitCalls("getUpdates", 1)

	req := &approval.Request{Client: "ci", Kind: audit.KindSecrets, Secrets: []string{"backup-token"},
		Claim: approval.Claim{Command: "restic backup /srv"}}
	r := core.Decide(context.Background(), req)
	if r.Allowed || r.Cause != audit.CauseLimit || r.ErrorCode != "" || r.Err != nil {
		t.Errorf("result %+v, want denied with cause limit, and no error", r)
	}
	if n := len(f.callsOf("sendMessage")); n != 0 {
		t.Errorf("%d messages, want 0", n)
	}
	if !strings.Contains(e.logs.String(), "too many notices") {
		t.Error("the refused notice is not logged")
	}

	// The limit has room again. The refused use did not count, so this use
	// goes without a tap, and its notice goes out. (If it asked the person,
	// the context would end it after waitLimit.)
	clock.add(2 * time.Minute)
	actx, acancel := context.WithTimeout(context.Background(), waitLimit)
	defer acancel()
	r = core.Decide(actx, req)
	if !r.Allowed || r.Answer != "" {
		t.Fatalf("result %+v, want allowed without a tap", r)
	}
	if notice := f.waitCalls("sendMessage", 1)[0]; notice.num("chat_id") != noticeChatID || notice.has("reply_markup") {
		t.Errorf("notice %s", notice.Raw)
	}

	// That was the one use of the day: the next use asks the person.
	dctx, dcancel := context.WithCancel(context.Background())
	done := make(chan *approval.Result, 1)
	go func() { done <- core.Decide(dctx, req) }()
	asked := f.waitCalls("sendMessage", 2)[1]
	dcancel()
	<-done
	if asked.num("chat_id") != approverID || !asked.has("reply_markup") {
		t.Errorf("the next use did not ask the person: %s", asked.Raw)
	}
}
