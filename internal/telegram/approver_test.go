package telegram

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// TestAskEndedContext checks that Ask sends nothing when its context has
// ended, and returns the context's error.
func TestAskEndedContext(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.a.Ask(ctx, secretsPrompt()); !errors.Is(err, context.Canceled) {
		t.Errorf("Ask: %v, want context.Canceled", err)
	}
	dctx, dcancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer dcancel()
	if _, err := e.a.Ask(dctx, secretsPrompt()); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Ask: %v, want context.DeadlineExceeded", err)
	}
	if err := e.a.Notify(ctx, noticeOf(secretsPrompt())); !errors.Is(err, context.Canceled) {
		t.Errorf("Notify: %v, want context.Canceled", err)
	}
	if err := e.a.Alert(ctx, "alert"); !errors.Is(err, context.Canceled) {
		t.Errorf("Alert: %v, want context.Canceled", err)
	}
	if n := len(e.f.allCalls()); n != 0 {
		t.Errorf("%d calls to Telegram, want 0", n)
	}
}

// TestAskContextEndsWhileSending checks that Ask stops and fails when its
// context ends while Telegram does not answer.
func TestAskContextEndsWhileSending(t *testing.T) {
	e := newEnv(t)
	release := e.f.hold("sendMessage")
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := e.a.Ask(ctx, secretsPrompt())
		done <- err
	}()
	e.f.waitCalls("sendMessage", 1)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Ask: %v, want context.Canceled", err)
		}
	case <-time.After(waitLimit):
		t.Fatal("Ask did not return")
	}
}

// TestAskChecksTheAnswer checks that Ask fails when Telegram's answer
// names another chat or no message: the core then denies the request.
func TestAskChecksTheAnswer(t *testing.T) {
	for name, body := range map[string]string{
		"another chat": `{"ok":true,"result":{"message_id":5,"chat":{"id":7000002,"type":"private"}}}`,
		"no message":   `{"ok":true,"result":{"chat":{"id":7000001,"type":"private"}}}`,
		"no result":    `{"ok":true}`,
		"null result":  `{"ok":true,"result":null}`,
		"wrong form":   `{"ok":true,"result":{"message_id":"5"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.f.reply("sendMessage", 200, body)
			if _, err := e.a.Ask(context.Background(), secretsPrompt()); err == nil {
				t.Error("Ask did not fail")
			}
			if n := len(e.f.callsOf("sendMessage")); n != 1 {
				t.Errorf("%d tries, want 1: the message may be out", n)
			}
		})
	}
}

// TestEndSendsEmptyKeyboard checks that End removes the buttons with an
// empty keyboard for every ending, and that a message that shows the text
// already is no error.
func TestEndSendsEmptyKeyboard(t *testing.T) {
	at := time.Date(2026, 10, 14, 14, 2, 41, 0, time.UTC)
	endings := []approval.Ending{
		{Answer: audit.AnswerApproveOnce, At: at},
		{Answer: audit.AnswerApproveWindow, WindowMinutes: 15, At: at},
		{Answer: audit.AnswerDeny, Cause: audit.CauseApprover, At: at},
		{Cause: audit.CauseExpired, At: at},
		{Cause: audit.CauseCancelled, At: at},
		{Cause: audit.CauseError, At: at},
		{Cause: audit.CauseLimit, At: at},
		{At: at},
	}
	e := newEnv(t)
	for _, p := range []approval.Prompt{secretsPrompt(), loginPrompt(), grantPrompt(), {}} {
		for _, end := range endings {
			if err := e.a.End(context.Background(), messageID(approverID, 9), p, end); err != nil {
				t.Errorf("End: %v", err)
			}
		}
	}
	calls := e.f.callsOf("editMessageText")
	if len(calls) != 4*len(endings) {
		t.Fatalf("%d edits, want %d", len(calls), 4*len(endings))
	}
	for _, c := range calls {
		if c.field("reply_markup") != `{"inline_keyboard":[]}` || c.num("chat_id") != approverID ||
			c.num("message_id") != 9 || c.str("parse_mode") != "HTML" {
			t.Errorf("edit %s", c.Raw)
		}
		if strings.Contains(c.str("text"), "expires ") {
			t.Errorf("the edit still shows the expiry: %q", c.str("text"))
		}
	}
	e.f.reply("editMessageText", 400, `{"ok":false,"error_code":400,"description":"Bad Request: message is not modified: specified new message content and reply markup are exactly the same"}`)
	if err := e.a.End(context.Background(), messageID(approverID, 9), secretsPrompt(), endings[0]); err != nil {
		t.Errorf("End of a message that shows the text: %v", err)
	}
	e.f.reply("editMessageText", 400, `{"ok":false,"error_code":400,"description":"Bad Request: message to edit not found"}`)
	if err := e.a.End(context.Background(), messageID(approverID, 9), secretsPrompt(), endings[0]); err == nil {
		t.Error("End of a message that is gone did not fail")
	}
}

// TestEndRefusesOtherMessages checks that End edits only messages in the
// approver's private chat, in the form that Ask returns.
func TestEndRefusesOtherMessages(t *testing.T) {
	e := newEnv(t)
	for _, m := range []approval.MessageID{"", "message-1", messageID(otherUserID, 9), messageID(noticeChatID, 9), "7000001:0"} {
		if err := e.a.End(context.Background(), m, secretsPrompt(), approval.Ending{Cause: audit.CauseExpired}); err == nil {
			t.Errorf("End(%q) did not fail", m)
		}
	}
	if n := len(e.f.allCalls()); n != 0 {
		t.Errorf("%d calls to Telegram, want 0", n)
	}
}

// TestNotifyIsSilent checks that a notice goes to the notice chat, without
// a sound, without buttons and with link previews off.
func TestNotifyIsSilent(t *testing.T) {
	e := newEnv(t)
	if err := e.a.Notify(context.Background(), noticeOf(loginPrompt())); err != nil {
		t.Fatal(err)
	}
	c := e.f.callsOf("sendMessage")[0]
	if c.num("chat_id") != noticeChatID || c.field("disable_notification") != "true" || c.has("reply_markup") ||
		c.field("link_preview_options") != `{"is_disabled":true}` || c.str("parse_mode") != "HTML" {
		t.Errorf("notice %s", c.Raw)
	}
}

// TestNotifyRateLimit checks that Notify sends at most NoticesPerMinute
// notices in any 60 seconds, and refuses more without a call.
func TestNotifyRateLimit(t *testing.T) {
	e := newEnv(t)
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	e.a.now = func() time.Time { return now }
	p := noticeOf(secretsPrompt())
	for i := range NoticesPerMinute {
		if err := e.a.Notify(context.Background(), p); err != nil {
			t.Fatalf("notice %d: %v", i+1, err)
		}
		now = now.Add(time.Second)
	}
	if err := e.a.Notify(context.Background(), p); !errors.Is(err, ErrNoticeLimit) || !errors.Is(err, approval.ErrLimit) {
		t.Errorf("notice %d: %v, want ErrNoticeLimit, a limit for the core", NoticesPerMinute+1, err)
	}
	if n := len(e.f.callsOf("sendMessage")); n != NoticesPerMinute {
		t.Errorf("%d notices sent, want %d", n, NoticesPerMinute)
	}
	// 60 seconds after the first notice, one more may go out, then no more.
	now = now.Add(time.Minute - NoticesPerMinute*time.Second)
	if err := e.a.Notify(context.Background(), p); err != nil {
		t.Errorf("after a minute: %v", err)
	}
	if err := e.a.Notify(context.Background(), p); !errors.Is(err, ErrNoticeLimit) {
		t.Errorf("after a minute, the second: %v, want ErrNoticeLimit", err)
	}
	// A notice that cannot be sent counts too.
	now = now.Add(time.Hour)
	for range NoticesPerMinute {
		e.f.reply("sendMessage", 400, `{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`)
	}
	for range NoticesPerMinute {
		if err := e.a.Notify(context.Background(), p); err == nil || errors.Is(err, approval.ErrLimit) {
			t.Fatalf("Notify: %v, want the error of Telegram, not a limit", err)
		}
	}
	if err := e.a.Notify(context.Background(), p); !errors.Is(err, ErrNoticeLimit) {
		t.Errorf("Notify: %v, want ErrNoticeLimit", err)
	}
	if !strings.Contains(e.logs.String(), "too many notices") {
		t.Error("the refused notice is not logged")
	}
}

// TestNoticeLimitIsALimit checks which errors of Notify the approval core
// takes as a limit of the approver (approval.ErrLimit): ErrNoticeLimit,
// when Notify sent nothing. An error of Telegram is not one, also not its
// code 429 "too many requests": an earlier try may have sent the notice.
// (Issue #47.)
func TestNoticeLimitIsALimit(t *testing.T) {
	if !errors.Is(ErrNoticeLimit, approval.ErrLimit) {
		t.Error("ErrNoticeLimit does not wrap approval.ErrLimit")
	}
	e := newEnv(t)
	e.f.reply("sendMessage", 429, `{"ok":false,"error_code":429,"description":"Too Many Requests","parameters":{"retry_after":60}}`)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := e.a.Notify(ctx, noticeOf(secretsPrompt()))
	if ce := callErr(t, err); ce.code != 429 || errors.Is(err, approval.ErrLimit) {
		t.Errorf("Notify after a 429: %v, want the 429 error, not a limit", err)
	}
}

// TestAlert checks that an alert goes to the approver with a sound, and
// that its text is escaped.
func TestAlert(t *testing.T) {
	e := newEnv(t)
	if err := e.a.Alert(context.Background(), "the audit log had a torn line <b>&</b>\nsee the journal"); err != nil {
		t.Fatal(err)
	}
	c := e.f.callsOf("sendMessage")[0]
	want := "⚠️ nodkey: the audit log had a torn line &lt;b&gt;&amp;&lt;/b&gt;\nsee the journal"
	if c.num("chat_id") != approverID || c.has("disable_notification") || c.str("text") != want {
		t.Errorf("alert %s", c.Raw)
	}
}

// TestAlertWaitIsBounded: Alert is exported, and the broker may call it
// with a context without a deadline, such as for a torn line at start. A
// 429 must not make it wait for many minutes: it has its own limit.
func TestAlertWaitIsBounded(t *testing.T) {
	e := newEnv(t)
	for range maxTries {
		e.f.reply("sendMessage", 429, `{"ok":false,"error_code":429,"description":"Too Many Requests","parameters":{"retry_after":600}}`)
	}
	start := time.Now()
	if err := e.a.Alert(context.Background(), "the audit log had a torn line"); err == nil {
		t.Error("Alert did not fail")
	}
	var total time.Duration
	for _, w := range e.sleeps.all() {
		total += w
	}
	if total > alertTimeout || time.Since(start) > alertTimeout {
		t.Errorf("Alert would wait %s, and took %s", total, time.Since(start))
	}
	if n := len(e.f.callsOf("sendMessage")); n != 1 {
		t.Errorf("%d tries, want 1: no time for a second", n)
	}
}

// TestRememberIsBounded checks that the approver forgets old messages, so
// its memory stays small, and that it forgets a message whose request
// ended before one whose request may still wait.
func TestRememberIsBounded(t *testing.T) {
	e := newEnv(t)
	kb := keyboard(secretsPrompt()).InlineKeyboard
	waiting := messageID(approverID, 1)
	e.a.remember(waiting, kb) // the oldest, and its request still waits
	for i := 2; i <= maxRemembered+10; i++ {
		m := messageID(approverID, int64(i))
		e.a.remember(m, kb)
		e.a.setFinal(m, "final")
	}
	if sent, known := e.a.lookup(waiting); !known || !slices.Equal(sent.keyboard[0], kb[0]) || sent.final != "" {
		t.Errorf("the message whose request waits: %+v, %v", sent, known)
	}
	if _, known := e.a.lookup(messageID(approverID, 2)); known {
		t.Error("the oldest message whose request ended is still known")
	}
	if sent, known := e.a.lookup(messageID(approverID, maxRemembered+10)); !known || sent.final != "final" {
		t.Errorf("the newest message: %+v, %v", sent, known)
	}
	if len(e.a.sent) != maxRemembered || len(e.a.order) != maxRemembered {
		t.Errorf("%d and %d messages kept, want %d", len(e.a.sent), len(e.a.order), maxRemembered)
	}
	// When no request has ended, the oldest message goes.
	e = newEnv(t)
	for i := 1; i <= maxRemembered+1; i++ {
		e.a.remember(messageID(approverID, int64(i)), kb)
	}
	if _, known := e.a.lookup(messageID(approverID, 1)); known || len(e.a.sent) != maxRemembered {
		t.Errorf("the oldest message is still known, or %d are kept", len(e.a.sent))
	}
}

// TestNewChecksConfig checks that New refuses a config without the
// approver or the notice chat, and a token file that does not hold a
// token, without showing its content.
func TestNewChecksConfig(t *testing.T) {
	token := newCanaryToken(t)
	read := func(string) ([]byte, error) { return []byte(token), nil }
	cfg := testTelegramConfig()
	if _, err := newApprover(cfg, Options{}, read, "http://127.0.0.1:1"); err != nil {
		t.Fatalf("a good config: %v", err)
	}
	noUser := cfg
	noUser.UserID = 0
	noNotice := cfg
	noNotice.NoticeChatID = 0
	for name, c := range map[string]struct {
		cfg  config.Telegram
		read func(string) ([]byte, error)
	}{
		"no user":   {noUser, read},
		"no notice": {noNotice, read},
		"read error": {cfg, func(string) ([]byte, error) {
			return nil, errors.New("/run/credentials/nodkey.service/telegram-token: others have access")
		}},
	} {
		if _, err := newApprover(c.cfg, Options{}, c.read, "http://127.0.0.1:1"); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// New itself reads through the checked reader of package config.
	if _, err := New(config.Telegram{TokenFile: "/nonexistent/telegram-token", UserID: 1, NoticeChatID: 1}, Options{}); err == nil {
		t.Error("New with a missing token file did not fail")
	}

	secret := token[strings.IndexByte(token, ':')+1:]
	for name, content := range map[string]string{
		"empty":         "",
		"no colon":      strings.ReplaceAll(token, ":", ""),
		"no bot ID":     ":" + secret,
		"short":         token[:20],
		"slash":         token + "/x",
		"query":         token + "?x",
		"space inside":  strings.Replace(token, ":", ": ", 1),
		"two lines":     token + "\n" + token,
		"percent":       token[:len(token)-3] + "%2F",
		"letters in ID": "x" + token,
		"too long":      token + strings.Repeat("a", 64),
	} {
		_, err := newApprover(cfg, Options{}, func(string) ([]byte, error) { return []byte(content), nil }, "http://127.0.0.1:1")
		if err == nil {
			t.Errorf("%s: the token was taken", name)
			continue
		}
		if strings.Contains(err.Error(), secret[:10]) {
			t.Errorf("%s: the error shows the token", name)
		}
	}
	// Space around the token is fine.
	if _, err := newApprover(cfg, Options{}, func(string) ([]byte, error) { return []byte("  " + token + "\r\n"), nil },
		"http://127.0.0.1:1"); err != nil {
		t.Errorf("a token with space around: %v", err)
	}
}
