package telegram

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

const testPairCode = "abcdefghij0123456789"

// newTestPairing returns a Pairing for the fake f, after getMe.
func newTestPairing(t *testing.T, f *fakeTelegram) *Pairing {
	t.Helper()
	f.reply("getMe", http.StatusOK, `{"ok":true,"result":{"id":42,"is_bot":true,"username":"try_test_bot"}}`)
	p, err := newPairing(t.Context(), []byte(f.token+"\n"), f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	p.api.sleep = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	return p
}

func startUpdate(id int64, chatID, fromID int64, chatType, text string) string {
	return fmt.Sprintf(`{"update_id":%d,"message":{"message_id":1,"chat":{"id":%d,"type":%q},`+
		`"from":{"id":%d,"first_name":"Ann\u001b[31m","username":"ann_x"},"text":%q}}`, id, chatID, chatType, fromID, text)
}

// Only "/start CODE" from a private chat with its sender counts.
func TestPairingWait(t *testing.T) {
	f := newFake(t)
	p := newTestPairing(t, f)
	if got, want := p.Link(testPairCode), "https://t.me/try_test_bot?start="+testPairCode; got != want {
		t.Fatalf("link %q, want %q", got, want)
	}
	f.addRawUpdate(1, startUpdate(1, 7, 7, "private", "/start wrong-code-0123456789"))
	f.addRawUpdate(2, startUpdate(2, -100, 8, "group", "/start "+testPairCode))
	f.addRawUpdate(3, startUpdate(3, 9, 10, "private", "/start "+testPairCode))
	f.addRawUpdate(4, startUpdate(4, 11, 11, "private", "/start "+testPairCode+" x"))
	f.addRawUpdate(5, `{"update_id":5,"message":"not an object"}`)
	f.addRawUpdate(6, startUpdate(6, 12, 12, "private", "/start "+testPairCode))
	got, err := p.Wait(t.Context(), testPairCode)
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != 12 || got.Name != "Ann?[31m (@ann_x)" {
		t.Fatalf("paired %+v, want user 12, a clean name", got)
	}
}

func TestPairingDeny(t *testing.T) {
	t.Run("bad code", func(t *testing.T) {
		p := newTestPairing(t, newFake(t))
		for _, code := range []string{"", "short", "abc def ghi jkl mno", strings.Repeat("a", 65)} {
			if _, err := p.Wait(t.Context(), code); err == nil {
				t.Errorf("code %q: no error", code)
			}
		}
	})
	t.Run("conflict", func(t *testing.T) {
		f := newFake(t)
		p := newTestPairing(t, f)
		f.reply("getUpdates", http.StatusConflict, `{"ok":false,"error_code":409,"description":"Conflict"}`)
		if _, err := p.Wait(t.Context(), testPairCode); !errors.Is(err, ErrPollConflict) {
			t.Fatalf("Wait: %v, want ErrPollConflict", err)
		}
	})
	t.Run("token refused", func(t *testing.T) {
		f := newFake(t)
		_, err := newPairing(t.Context(), []byte(newCanaryToken(t)), f.srv.URL)
		if !errors.Is(err, ErrTokenRefused) {
			t.Fatalf("newPairing: %v, want ErrTokenRefused", err)
		}
	})
	t.Run("no bot name", func(t *testing.T) {
		f := newFake(t)
		f.reply("getMe", http.StatusOK, `{"ok":true,"result":{"id":42,"username":"bad name/x"}}`)
		if _, err := newPairing(t.Context(), []byte(f.token), f.srv.URL); err == nil {
			t.Fatal("no error")
		}
	})
	t.Run("not a token", func(t *testing.T) {
		if _, err := NewPairing(t.Context(), []byte("not a token")); err == nil {
			t.Fatal("no error")
		}
	})
	t.Run("cancel", func(t *testing.T) {
		p := newTestPairing(t, newFake(t))
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := p.Wait(ctx, testPairCode); !errors.Is(err, context.Canceled) {
			t.Fatalf("Wait: %v", err)
		}
	})
}

// The prefix goes, escaped, before every message and edit.
func TestPrefix(t *testing.T) {
	f := newFake(t)
	read := func(string) ([]byte, error) { return []byte(f.token), nil }
	a, err := newApprover(testTelegramConfig(), Options{Prefix: "TRY <MODE> · "}, read, f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Inform(t.Context(), "hello"); err != nil {
		t.Fatal(err)
	}
	if got := f.callsOf("sendMessage")[0].str("text"); !strings.HasPrefix(got, "TRY &lt;MODE&gt; · ") {
		t.Fatalf("text %q", got)
	}
	edit, ok := a.api.withPrefix(editMessageTextParams{Text: "x"}).(editMessageTextParams)
	if !ok || edit.Text != "TRY &lt;MODE&gt; · x" {
		t.Fatalf("edit %+v", edit)
	}
	if got, ok := a.api.withPrefix(getUpdatesParams{Offset: 3}).(getUpdatesParams); !ok || got.Offset != 3 {
		t.Fatalf("getUpdates params changed: %+v", got)
	}
}

// NewWithToken keeps its own copy of the token, and checks it.
func TestNewWithToken(t *testing.T) {
	if _, err := NewWithToken(testTelegramConfig(), []byte("not a token"), Options{}); err == nil {
		t.Fatal("no error for a bad token")
	}
	token := []byte(newCanaryToken(t))
	want := string(token)
	a, err := NewWithToken(testTelegramConfig(), token, Options{})
	if err != nil {
		t.Fatal(err)
	}
	clear(token)
	if a.api.token.value != want {
		t.Fatal("the Approver does not hold its own copy of the token")
	}
}
