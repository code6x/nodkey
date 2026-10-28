package telegram

import (
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/claim"
)

// Tests of the Revoke button of a scheduled grant, of the lines that tell
// how a grant ended, and of the notice of a grant that was not used
// (DESIGN.md sections 7 and 8).

// TestRevokeData: the Revoke button carries the request ID, as the other
// buttons do, and only that.
func TestRevokeData(t *testing.T) {
	p := preapprovePrompt()
	kb := revokeKeyboard(p)
	if len(kb.InlineKeyboard) != 1 || len(kb.InlineKeyboard[0]) != 1 ||
		kb.InlineKeyboard[0][0].Text != "Revoke" || kb.InlineKeyboard[0][0].CallbackData != dataRevoke+p.RequestID {
		t.Fatalf("keyboard %+v", kb)
	}
	action, id, ok := parseData(kb.InlineKeyboard[0][0].CallbackData)
	if !ok || action != audit.AnswerRevoke || id != p.RequestID {
		t.Errorf("parseData = %q, %q, %v", action, id, ok)
	}
	for _, bad := range []string{"r:", "r:" + p.RequestID + "x", "R:" + p.RequestID, "x:" + p.RequestID,
		"r:" + strings.Repeat("!", requestIDLen), "r:" + testID(3)[:21] + "=", ""} {
		if _, _, ok := parseData(bad); ok {
			t.Errorf("parseData(%q) was accepted", bad)
		}
	}
}

// TestGrantEndLines: every end of a grant says how and when, in the last
// lines of the message, and the approval stays above it.
func TestGrantEndLines(t *testing.T) {
	p := preapprovePrompt()
	p.Uses = 3
	at := time.Date(2026, 10, 28, 3, 30, 0, 0, time.UTC)
	for cause, want := range map[audit.EndCause]string{
		audit.EndUsedUp:    "all 3 use(s) used",
		audit.EndEnded:     "ended at 2026-10-28 03:30:00 UTC with 2 of 3 use(s) left",
		audit.EndCancelled: "cancelled by the client at 2026-10-28 03:30:00 UTC",
		audit.EndDenied:    "ended by a later Deny at 2026-10-28 03:30:00 UTC",
		audit.EndRevoked:   "revoked by you at 2026-10-28 03:30:00 UTC",
		audit.EndStopped:   "the broker stopped at 2026-10-28 03:30:00 UTC",
	} {
		approved := at.Add(-time.Hour)
		tx := endingText(p, approval.Ending{Answer: audit.AnswerApproveOnce, At: at, Approved: approved, GrantEnd: cause, UsesLeft: 2})
		got := tx.plain.String()
		if !strings.Contains(got, "\n👍 approved by you at 02:30:00, for 3 use(s) until ") || !strings.Contains(got, want) ||
			strings.Contains(got, "expires") || !strings.HasPrefix(got, "🗓 Pre-approval") {
			t.Errorf("%s: message\n%s\nwant %q", cause, got, want)
		}
	}
}

// TestNotUsedNoticeText: the notice names the grant and the uses left, and
// the prompt checks refuse a notice that is not one.
func TestNotUsedNoticeText(t *testing.T) {
	p := noticeOf(preapprovePrompt())
	p.Uses, p.GrantID, p.UsesLeft = 3, testID(9), 2
	tx, err := noticeText(p)
	if err != nil {
		t.Fatal(err)
	}
	got := tx.plain.String()
	want := "🔔 Pre-approval · request m4k2\nnot used: grant " + p.GrantID + " ended with 2 of 3 uses left\n" +
		"✅ machine: laptop\n✅ secrets: backup-token\n✅ uses: 3\n"
	if !strings.HasPrefix(got, want) || strings.Contains(got, "[") || strings.Contains(got, "expires") {
		t.Errorf("notice\n%s\nwant it to start with\n%s", got, want)
	}
	for name, change := range map[string]func(*approval.Prompt){
		"no grant ID":        func(p *approval.Prompt) { p.GrantID = "" },
		"a bad grant ID":     func(p *approval.Prompt) { p.GrantID = "short" },
		"no uses left":       func(p *approval.Prompt) { p.UsesLeft = 0 },
		"more left than had": func(p *approval.Prompt) { p.UsesLeft = 4 },
		"a via":              func(p *approval.Prompt) { p.Via = audit.ViaScheduled },
		"a button":           func(p *approval.Prompt) { p.Once = true },
	} {
		q := p
		change(&q)
		if _, err := noticeText(q); err == nil {
			t.Errorf("%s: the notice was accepted", name)
		}
	}
	// The ID of a grant is for a notice only.
	m := preapprovePrompt()
	m.GrantID = testID(9)
	if _, _, err := promptMessage(m); err == nil {
		t.Error("a message with a grant ID was accepted")
	}
	s := secretsPrompt()
	s.UsesLeft = 1
	if _, _, err := promptMessage(s); err == nil {
		t.Error("a secrets message with uses left was accepted")
	}
}

// grantEnv starts a core with a fake Telegram, asks for a scheduled grant
// of github-token with uses uses from now to an hour from now, taps
// Approve, and starts the grant. It returns the ID of the request, the
// number of its message, and the result. It waits for the Revoke button.
func (ce *coreEnv) grantEnv(t *testing.T, uses int) (string, int64, *approval.Result) {
	t.Helper()
	req := &approval.Request{
		Client: "laptop", Kind: audit.KindPreapprove, Secrets: []string{"github-token"}, Uses: uses,
		NotBefore: noon, NotAfter: noon.Add(time.Hour), Claim: approval.Claim{Reason: "job nightly-backup"},
	}
	n := len(ce.f.callsOf("sendMessage")) + 1
	ch := ce.decide(req)
	id, msg := ce.asked(t, n)
	ce.f.tap(goodTap(msg, dataOnce+id))
	res := waitResult(t, ch)
	if !res.Allowed {
		t.Fatalf("result %+v, want allowed", res)
	}
	edits := len(ce.edits(msg))
	res.StartGrants()
	if !res.GrantStarted() {
		t.Fatal("the grant did not start")
	}
	ce.f.waitFor("the Revoke button", func() bool {
		return len(ce.f.callsOfLocked("editMessageText")) > edits && strings.Contains(string(ce.f.messages[msg].markup), dataRevoke+id)
	})
	return id, msg, res
}

// TestCoreRevoke: the message of an approved scheduled grant keeps one
// Revoke button. A tap on it ends the grant; the message shows that and
// has no button; a second tap is late; and a use needs a tap again.
func TestCoreRevoke(t *testing.T) {
	ce := newCoreEnv(t, newFake(t))
	var ended []audit.GrantEnded
	endedCh := make(chan audit.GrantEnded, 4)
	ce.core.OnGrantEnded(func(ev audit.GrantEnded) { endedCh <- ev })
	id, msg, res := ce.grantEnv(t, 2)
	edits := ce.edits(msg)
	if len(edits) != 2 || !strings.Contains(edits[1], "👍 approved by you") || strings.Contains(edits[1], "revoked") {
		t.Fatalf("edits %q", edits)
	}
	if got := ce.f.messages[msg].markup; string(got) != `{"inline_keyboard":[[{"text":"Revoke","callback_data":"`+dataRevoke+id+`"}]]}` {
		t.Errorf("buttons %s", got)
	}
	cb := ce.f.tap(goodTap(msg, dataRevoke+id))
	if got := ce.f.waitAnswer(cb).str("text"); got != tapCountedRevoke {
		t.Errorf("the phone shows %q", got)
	}
	var ev audit.GrantEnded
	select {
	case ev = <-endedCh:
	case <-time.After(waitLimit):
		t.Fatal("no grant_ended entry")
	}
	ended = append(ended, ev)
	if ev.Cause != audit.EndRevoked || ev.GrantID != res.GrantID || ev.UsesLeft != 2 {
		t.Errorf("entry %+v", ev)
	}
	ce.f.waitFor("the end of the message", func() bool { return len(ce.f.callsOfLocked("editMessageText")) >= 3 })
	last := ce.edits(msg)[2]
	if !strings.Contains(last, "revoked by you at") || !strings.Contains(last, "2 use(s) left") ||
		!emptyMarkup(ce.f.messages[msg].markup) {
		t.Errorf("last edit %q", last)
	}
	// A second tap is late: the phone says so, the message is shown again,
	// and the tap is reported.
	cb = ce.f.tap(goodTap(msg, dataRevoke+id))
	if got := ce.f.waitAnswer(cb).str("text"); got != tapEnded {
		t.Errorf("the second tap shows %q", got)
	}
	ce.f.waitHandled(cb)
	if taps := ce.taps.all(); len(taps) != 1 || taps[0].Cause != audit.TapUnknownRequest {
		t.Errorf("reports %+v", taps)
	}
	if len(ended) != 1 || len(endedCh) != 0 {
		t.Errorf("%d entries; want 1", len(ended)+len(endedCh))
	}
	// The grant is gone: the use asks.
	ch := ce.decide(secretsRequest("github-token"))
	ce.asked(t, 2)
	ce.f.tap(goodTap(ce.f.callsOf("sendMessage")[1].MsgID, dataDeny+ce.f.callsOf("sendMessage")[1].requestID()))
	checkDeniedBy(t, waitResult(t, ch))
}

// TestCoreRevokeRefused: a Revoke from another user, in another chat, on
// another message or on a message that someone else edited does not count.
// The grant stays and can be used.
func TestCoreRevokeRefused(t *testing.T) {
	ce := newCoreEnv(t, newFake(t))
	id, msg, res := ce.grantEnv(t, 1)
	other := msg + 100
	for name, tc := range map[string]struct {
		spec  tapSpec
		cause audit.TapCause
	}{
		"other user": {tapSpec{from: approverID + 1, chatID: approverID, chatType: "private", msgID: msg, data: dataRevoke + id}, audit.TapOtherUser},
		"other chat": {tapSpec{from: approverID, chatID: noticeChatID, chatType: "supergroup", msgID: msg, data: dataRevoke + id}, audit.TapOtherChat},
		"inline":     {tapSpec{from: approverID, inline: true, data: dataRevoke + id}, audit.TapInlineMessage},
		"bad data":   {goodTap(msg, dataRevoke+id+"x"), audit.TapBadData},
		"other message": {tapSpec{from: approverID, chatID: approverID, chatType: "private", msgID: other, data: dataRevoke + id,
			bare: true}, audit.TapWrongMessage},
	} {
		before := len(ce.taps.all())
		cb := ce.f.tap(tc.spec)
		ce.f.waitHandled(cb)
		taps := ce.taps.all()
		if len(taps) != before+1 || taps[before].Cause != tc.cause {
			t.Errorf("%s: reports %+v, want cause %s", name, taps[before:], tc.cause)
		}
		for _, c := range ce.f.callsOf("editMessageText") {
			if strings.Contains(c.str("text"), "revoked") {
				t.Errorf("%s: the message says the grant was revoked", name)
			}
		}
	}
	// The grant still works: its use sends a notice, and needs no tap.
	r := waitResult(t, ce.decide(secretsRequest("github-token")))
	if !r.Allowed || len(r.Events()) < 3 {
		t.Fatalf("result %+v; want a use of the grant %s", r, res.GrantID)
	}
}

// TestCoreRevokeSkipsEditedCheck: a Revoke only takes a right away, so it
// counts on a message that someone else edited, on one with an edit date
// that the broker does not know, and on one that Telegram sends without
// content (older than 48 hours). It raises no alert.
func TestCoreRevokeSkipsEditedCheck(t *testing.T) {
	for name, tc := range map[string]struct {
		prepare func(f *fakeTelegram, msg int64)
		spec    func(msg int64, data string) tapSpec
	}{
		"edited by someone": {func(f *fakeTelegram, msg int64) { f.editByOther(msg, nil, true) }, goodTap},
		"unknown edit date": {nil, func(msg int64, data string) tapSpec { s := goodTap(msg, data); s.edited = true; return s }},
		"no content":        {nil, func(msg int64, data string) tapSpec { s := goodTap(msg, data); s.bare = true; return s }},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			ce := newCoreEnv(t, f)
			id, msg, _ := ce.grantEnv(t, 1)
			if tc.prepare != nil {
				tc.prepare(f, msg)
			}
			messages := len(f.callsOf("sendMessage"))
			cb := f.tap(tc.spec(msg, dataRevoke+id))
			if got := f.waitAnswer(cb).str("text"); got != tapCountedRevoke {
				t.Errorf("the phone shows %q", got)
			}
			f.waitHandled(cb)
			if got := len(f.callsOf("sendMessage")); got != messages {
				t.Errorf("%d messages (an alert?) went out", got-messages)
			}
			if taps := ce.taps.all(); len(taps) != 0 {
				t.Errorf("reports %+v", taps)
			}
			f.waitFor("the end of the message", func() bool { return len(f.callsOfLocked("editMessageText")) >= 3 })
			// The grant is gone: the use asks, and the person denies it.
			ch := ce.decide(secretsRequest("github-token"))
			id2, m2 := ce.asked(t, 2)
			f.tap(goodTap(m2, dataDeny+id2))
			checkDeniedBy(t, waitResult(t, ch))
		})
	}
}

// TestCoreGrantEndMessages: each end of a grant edits its message, with no
// button, and a later Deny says so.
func TestCoreGrantEndMessages(t *testing.T) {
	ce := newCoreEnv(t, newFake(t))
	_, msg, _ := ce.grantEnv(t, 1)
	// A later Deny for the secret ends the grant.
	ch := ce.decide(&approval.Request{Client: "laptop", Kind: audit.KindSecrets, Secrets: []string{"db-password", "github-token"}})
	id, m := ce.asked(t, 2)
	ce.waitTimers(t, 2) // the grant's and the request's
	ce.f.tap(goodTap(m, dataDeny+id))
	checkDeniedBy(t, waitResult(t, ch))
	ce.f.waitFor("the end of the message", func() bool {
		return len(ce.f.callsOfLocked("editMessageText")) >= 4 && emptyMarkup(ce.f.messages[msg].markup)
	})
	var last string
	for _, c := range ce.f.callsOf("editMessageText") {
		if c.num("message_id") == msg {
			last = c.str("text")
		}
	}
	if !strings.Contains(last, "ended by a later Deny at") || !strings.Contains(last, "1 use(s) left") {
		t.Errorf("last edit of the grant message: %q", last)
	}
}

// TestCoreNotUsedNotice: a grant that reaches its end with uses left sends
// one silent notice to the notice chat. A grant that was used up sends
// none.
func TestCoreNotUsedNotice(t *testing.T) {
	ce := newCoreEnv(t, newFake(t))
	_, msg, res := ce.grantEnv(t, 2)
	ce.clock.Advance(time.Hour)
	ce.f.waitFor("the notice", func() bool { return len(ce.f.callsOfLocked("sendMessage")) >= 2 })
	notice := ce.f.callsOf("sendMessage")[1]
	text := notice.str("text")
	if notice.num("chat_id") != noticeChatID || notice.field("disable_notification") != "true" || notice.has("reply_markup") ||
		!strings.Contains(text, claim.HTML("not used: grant "+res.GrantID+" ended with 2 of 2 uses left")) {
		t.Errorf("notice %s", notice.Raw)
	}
	ce.f.waitFor("the end of the message", func() bool { return emptyMarkup(ce.f.messages[msg].markup) })
	if last := ce.edits(msg); !strings.Contains(last[len(last)-1], "ended at") {
		t.Errorf("edits %q", last)
	}
	// Used up: no notice. The use sends its own notice only.
	n := len(ce.f.callsOf("sendMessage"))
	ce.clock.Advance(time.Minute)
	req := &approval.Request{
		Client: "laptop", Kind: audit.KindPreapprove, Secrets: []string{"github-token"}, Uses: 1,
		NotBefore: noon.Add(time.Hour + time.Minute), NotAfter: noon.Add(2 * time.Hour), Claim: approval.Claim{Reason: "job"},
	}
	ch := ce.decide(req)
	id, m := ce.asked(t, n+1)
	ce.f.tap(goodTap(m, dataOnce+id))
	r := waitResult(t, ch)
	r.StartGrants()
	waitResult(t, ce.decide(secretsRequest("github-token")))
	ce.f.waitFor("the use notice", func() bool { return len(ce.f.callsOfLocked("sendMessage")) >= n+2 })
	for _, c := range ce.f.callsOf("sendMessage")[n:] {
		if strings.Contains(c.str("text"), "not used") {
			t.Errorf("a grant that was used up sent %s", c.Raw)
		}
	}
}

// TestCoreLateTapOnGrantMessage: the second tap of a double tap on Approve,
// or a tap on Deny, that reaches the broker after the message got its
// Revoke button, is a late tap. It is no sign of an edit: no alert goes
// out, and the Revoke button stays.
func TestCoreLateTapOnGrantMessage(t *testing.T) {
	f := newFake(t)
	ce := newCoreEnv(t, f)
	id, msg, _ := ce.grantEnv(t, 1)
	alerts := len(f.callsOf("sendMessage"))
	for _, data := range []string{dataOnce + id, dataDeny + id} {
		cb := f.tap(goodTap(msg, data))
		if got := f.waitAnswer(cb).str("text"); got != tapEnded {
			t.Errorf("the phone shows %q for %s", got, data)
		}
		f.waitHandled(cb)
	}
	if got := len(f.callsOf("sendMessage")); got != alerts {
		t.Errorf("%d messages went out after the late taps, want none", got-alerts)
	}
	if emptyMarkup(f.messages[msg].markup) {
		t.Error("a late tap removed the Revoke button")
	}
	cb := f.tap(goodTap(msg, dataRevoke+id))
	if got := f.waitAnswer(cb).str("text"); got != tapCountedRevoke {
		t.Errorf("the Revoke shows %q", got)
	}
}

// TestCoreOtherRequestButtonOnGrantMessage: a button of another request on
// a grant message is not the broker's doing. The tap is refused as a
// changed message, with the alert, and the Revoke button stays.
func TestCoreOtherRequestButtonOnGrantMessage(t *testing.T) {
	f := newFake(t)
	ce := newCoreEnv(t, f)
	id, msg, _ := ce.grantEnv(t, 1)
	messages := len(f.callsOf("sendMessage"))
	cb := f.tap(goodTap(msg, dataOnce+testID(5)))
	if got := f.waitAnswer(cb).str("text"); got != tapChanged {
		t.Errorf("the phone shows %q", got)
	}
	f.waitHandled(cb)
	if taps := ce.taps.all(); len(taps) != 1 || taps[0].Cause != audit.TapEditedMessage {
		t.Errorf("reports %+v", taps)
	}
	f.waitFor("the alert", func() bool { return len(f.callsOfLocked("sendMessage")) > messages })
	if emptyMarkup(f.messages[msg].markup) || id == "" {
		t.Error("the Revoke button went")
	}
}

// TestGrantEndMessageFits: the message of a grant with the longest body
// and the longest last lines is not over the limit of Telegram.
func TestGrantEndMessageFits(t *testing.T) {
	// Find a body that fills the room of a message with one last line, so
	// that two last lines would not fit there.
	var p approval.Prompt
	for n := 1; n <= 64; n++ {
		q := preapprovePrompt()
		q.Secrets = nil
		for range 32 {
			q.Secrets = append(q.Secrets, strings.Repeat("s", n))
		}
		q.Uses = 1 << 20
		q.Claim = approval.Claim{Vars: strings.Repeat("😀", 400), Command: strings.Repeat("😀", 2000),
			Dir: strings.Repeat("😀", 600), Reason: strings.Repeat("😀", 1000)}
		if tx, err := fitBody(q, false, maxTextUnits-lastLineRoom); err == nil && tx.units() > maxTextUnits-lastLineRoom-60 {
			p = q
			break
		}
	}
	if p.Client == "" {
		t.Fatal("no body of the size to test")
	}
	at := time.Date(2026, 10, 28, 3, 30, 0, 0, time.UTC)
	for _, cause := range []audit.EndCause{audit.EndEnded, audit.EndStopped, audit.EndDenied} {
		tx := endingText(p, approval.Ending{Answer: audit.AnswerApproveOnce, At: at, Approved: at, GrantEnd: cause, UsesLeft: 1 << 20})
		if n := tx.units(); n > maxTextUnits || !strings.Contains(tx.plain.String(), "use(s) left") {
			t.Errorf("%s: %d units", cause, n)
		}
	}
	tx, _, err := promptMessage(p)
	if err != nil || tx.units() > maxTextUnits {
		t.Errorf("message: %v, %d units", err, tx.units())
	}
}

// TestCoreRevokeOnWaitingMessage: someone with the bot token puts Revoke
// data on the message of a request that still waits. A tap on it skips
// nothing: it is refused as a changed message, with the alert, and the
// request still waits.
func TestCoreRevokeOnWaitingMessage(t *testing.T) {
	f := newFake(t)
	ce := newCoreEnv(t, f)
	ch := ce.decide(secretsRequest("github-token"))
	id, msg := ce.asked(t, 1)
	messages := len(f.callsOf("sendMessage"))
	cb := f.tap(goodTap(msg, dataRevoke+id))
	if got := f.waitAnswer(cb).str("text"); got != tapChanged {
		t.Errorf("the phone shows %q", got)
	}
	f.waitHandled(cb)
	if taps := ce.taps.all(); len(taps) != 1 || taps[0].Cause != audit.TapEditedMessage {
		t.Errorf("reports %+v", taps)
	}
	f.waitFor("the alert", func() bool { return len(f.callsOfLocked("sendMessage")) > messages })
	f.tap(goodTap(msg, dataDeny+id)) // it still waits
	checkDeniedBy(t, waitResult(t, ch))
}
