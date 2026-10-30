package telegram

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/approval"
)

// TestInform: a notice of the broker goes to the notice chat, without a
// sound, without buttons and with link previews off. Its text is the
// broker's, escaped.
func TestInform(t *testing.T) {
	e := newEnv(t)
	if err := e.a.Inform(context.Background(), "The client laptop <b>&</b> says that it runs nodkey 0.1.0."); err != nil {
		t.Fatal(err)
	}
	c := e.f.callsOf("sendMessage")[0]
	want := "ℹ️ nodkey: The client laptop &lt;b&gt;&amp;&lt;/b&gt; says that it runs nodkey 0.1.0."
	if c.num("chat_id") != noticeChatID || c.field("disable_notification") != "true" || c.has("reply_markup") ||
		c.field("link_preview_options") != `{"is_disabled":true}` || c.str("parse_mode") != "HTML" ||
		c.str("text") != want {
		t.Errorf("notice %s", c.Raw)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.a.Inform(ctx, "a notice"); !errors.Is(err, context.Canceled) {
		t.Errorf("Inform with a context that ended: %v, want context.Canceled", err)
	}
	if n := len(e.f.allCalls()); n != 1 {
		t.Errorf("%d calls to Telegram, want 1", n)
	}
}

// TestInformTriesOnce: a notice that Telegram refuses, or that fails on
// the way, is not sent again, also after a 429 or a server error, which
// Notify and Alert try again. Inform does not wait either.
func TestInformTriesOnce(t *testing.T) {
	for _, r := range []struct {
		status int
		body   string
	}{
		{429, `{"ok":false,"error_code":429,"description":"Too Many Requests","parameters":{"retry_after":5}}`},
		{500, `{"ok":false,"error_code":500,"description":"Internal Server Error"}`},
		{502, `<html>bad gateway</html>`},
		{400, `{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`},
	} {
		e := newEnv(t)
		e.f.reply("sendMessage", r.status, r.body)
		if err := e.a.Inform(context.Background(), "a notice"); err == nil {
			t.Errorf("%d: Inform did not fail", r.status)
		}
		if n := len(e.f.callsOf("sendMessage")); n != 1 {
			t.Errorf("%d: %d tries, want 1", r.status, n)
		}
		if w := e.sleeps.all(); len(w) != 0 {
			t.Errorf("%d: Inform waited %v", r.status, w)
		}
	}
}

// TestInformLimit: Inform sends at most InformsPerMinute notices in any 60
// seconds; a notice that failed counts too. Over the limit it makes no
// call. Its count is its own: notices of "never ask" uses do not take
// from it, and it does not take from theirs. So a "never ask" use right
// after notices of the broker still gets all of its notices.
func TestInformLimit(t *testing.T) {
	e := newEnv(t)
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	e.a.now = func() time.Time { return now }
	e.f.reply("sendMessage", 400, `{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`)
	if err := e.a.Inform(context.Background(), "a notice"); err == nil {
		t.Fatal("the first notice did not fail")
	}
	for i := 1; i < InformsPerMinute; i++ {
		now = now.Add(time.Second)
		if err := e.a.Inform(context.Background(), "a notice"); err != nil {
			t.Fatalf("notice %d: %v", i+1, err)
		}
	}
	if err := e.a.Inform(context.Background(), "a notice"); !errors.Is(err, ErrInformLimit) {
		t.Errorf("notice %d: %v, want ErrInformLimit", InformsPerMinute+1, err)
	}
	if n := len(e.f.callsOf("sendMessage")); n != InformsPerMinute {
		t.Errorf("%d calls, want %d", n, InformsPerMinute)
	}
	p := noticeOf(secretsPrompt())
	for i := range NoticesPerMinute {
		if err := e.a.Notify(context.Background(), p); err != nil {
			t.Fatalf("notice of a \"never ask\" use %d after the notices of the broker: %v", i+1, err)
		}
	}
	if err := e.a.Notify(context.Background(), p); !errors.Is(err, ErrNoticeLimit) {
		t.Errorf("Notify over its limit: %v, want ErrNoticeLimit", err)
	}
	if errors.Is(ErrInformLimit, approval.ErrLimit) {
		t.Error("ErrInformLimit is a limit for the approval core; Inform has nothing to do with the core")
	}
	// 60 seconds after the first notice of the broker, one more may go
	// out, also while the notices of "never ask" uses are at their limit.
	now = now.Add(time.Minute - time.Duration(InformsPerMinute-1)*time.Second)
	if err := e.a.Inform(context.Background(), "a notice"); err != nil {
		t.Errorf("after a minute: %v", err)
	}
	if err := e.a.Inform(context.Background(), "a notice"); !errors.Is(err, ErrInformLimit) {
		t.Errorf("after a minute, the second: %v, want ErrInformLimit", err)
	}
}

// TestInformLoud: the notice about a security release goes to the notice
// chat with a sound, and shares the count of Inform.
func TestInformLoud(t *testing.T) {
	e := newEnv(t)
	if err := e.a.InformLoud(context.Background(), "SECURITY UPDATE: nodkey 0.3.1 <b>"); err != nil {
		t.Fatal(err)
	}
	c := e.f.callsOf("sendMessage")[0]
	if c.num("chat_id") != noticeChatID || c.has("disable_notification") || c.has("reply_markup") ||
		c.str("text") != "⚠️ SECURITY UPDATE: nodkey 0.3.1 &lt;b&gt;" {
		t.Errorf("notice %s", c.Raw)
	}
	for i := 1; i < InformsPerMinute; i++ {
		if err := e.a.Inform(context.Background(), "a notice"); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.a.InformLoud(context.Background(), "SECURITY UPDATE"); !errors.Is(err, ErrInformLimit) {
		t.Errorf("a loud notice over the limit: %v, want ErrInformLimit", err)
	}
}
