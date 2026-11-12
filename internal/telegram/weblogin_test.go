package telegram

import (
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
)

func webLoginPrompt() approval.Prompt {
	return approval.Prompt{
		RequestID: testID(3), ShortCode: "w4x8", Kind: audit.KindWebLogin, Client: "laptop",
		Login:         &approval.LoginPrompt{Name: "Example shop", Username: "alice@example.com", Origin: "https://example.com"},
		Claim:         approval.Claim{Reason: "check the order"},
		Expires:       time.Date(2026, 10, 14, 14, 5, 40, 0, time.UTC),
		TimeLeft:      120 * time.Second,
		Once:          true,
		WindowMinutes: 15,
	}
}

func webPreapprovePrompt() approval.Prompt {
	p := webLoginPrompt()
	p.Kind, p.Uses, p.WindowMinutes = audit.KindPreapprove, 1, 0
	p.Login.For = approval.LoginPreapproveTime
	return p
}

func TestWebLoginMessage(t *testing.T) {
	tx, kb, err := promptMessage(webLoginPrompt())
	if err != nil {
		t.Fatal(err)
	}
	want := "🌐 Website login · request w4x8\n" +
		"✅ machine: laptop\n✅ login: Example shop\n✅ username: alice@example.com\n" +
		claimedHead + "\npage: https://example.com\nreason: check the order\n" +
		"expires 14:05:40 (120 s)"
	if got := tx.plain.String(); got != want {
		t.Errorf("text:\n%s\nwant:\n%s", got, want)
	}
	if len(kb.InlineKeyboard) != 1 || len(kb.InlineKeyboard[0]) != 3 {
		t.Errorf("buttons %+v, want once, window and deny", kb)
	}
}

// TestWebLoginPreapproveMessage: the message says what the tap allows,
// and shows no time limit for the tap itself.
func TestWebLoginPreapproveMessage(t *testing.T) {
	tx, kb, err := promptMessage(webPreapprovePrompt())
	if err != nil {
		t.Fatal(err)
	}
	got := tx.plain.String()
	want := "🗓 Pre-approval · request w4x8\n" +
		"✅ machine: laptop\n✅ login: Example shop\n✅ username: alice@example.com\n" +
		"allows: one login in the next 60 s after the tap\n" +
		claimedHead + "\npage: https://example.com\nreason: check the order"
	if got != want {
		t.Errorf("text:\n%s\nwant:\n%s", got, want)
	}
	if strings.Contains(got, "expire") || strings.Contains(got, "14:05") {
		t.Errorf("the message shows a time limit for the tap:\n%s", got)
	}
	if kb.InlineKeyboard[0][0].Text != "Approve" {
		t.Errorf("buttons %+v", kb)
	}
	// The pre-approval of a secret keeps its expiry line.
	tx, _, err = promptMessage(secretsPrompt())
	if err != nil || !strings.Contains(tx.plain.String(), "expires ") {
		t.Errorf("a secrets message lost its expiry: %v", err)
	}
	// The line after the tap.
	end := resultLine(webPreapprovePrompt(), approval.Ending{Answer: audit.AnswerApproveOnce, At: time.Date(2026, 10, 14, 14, 4, 0, 0, time.UTC)})
	if !strings.Contains(end, "one login in the next 60 s") {
		t.Errorf("result line %q", end)
	}
}

func TestWebLoginHostileText(t *testing.T) {
	p := webLoginPrompt()
	p.Login.Name = "Shop\n✅ machine: fake\u202e<b>&"
	if _, _, err := promptMessage(p); err == nil {
		t.Error("the prompt with a line break in the item name was taken")
	}
	// The HTML of a clean but hostile name is escaped.
	p = webLoginPrompt()
	p.Login.Name = "<b>Shop</b> & Co"
	p.Login.Username = "a<i>@example.com"
	tx, _, err := promptMessage(p)
	if err != nil {
		t.Fatal(err)
	}
	h := tx.html.String()
	if strings.Contains(h, "<b>Shop") || strings.Contains(h, "<i>") || !strings.Contains(h, "&lt;b&gt;Shop&lt;/b&gt; &amp; Co") {
		t.Errorf("html not escaped:\n%s", h)
	}
}

func TestWebLoginBadPrompts(t *testing.T) {
	edits := map[string]func(p *approval.Prompt){
		"no login":            func(p *approval.Prompt) { p.Login = nil },
		"no name":             func(p *approval.Prompt) { p.Login.Name = "" },
		"RTL in the name":     func(p *approval.Prompt) { p.Login.Name = "a\u202eb" },
		"newline in the user": func(p *approval.Prompt) { p.Login.Username = "a\nb" },
		"long name":           func(p *approval.Prompt) { p.Login.Name = strings.Repeat("x", 129) },
		"http origin":         func(p *approval.Prompt) { p.Login.Origin = "http://example.com" },
		"origin with a path":  func(p *approval.Prompt) { p.Login.Origin = "https://example.com/a" },
		"secrets":             func(p *approval.Prompt) { p.Secrets = []string{"a"} },
		"key":                 func(p *approval.Prompt) { p.Key = "deploy" },
		"for in a login":      func(p *approval.Prompt) { p.Login.For = time.Minute },
	}
	for name, ed := range edits {
		t.Run(name, func(t *testing.T) {
			p := webLoginPrompt()
			ed(&p)
			if _, _, err := promptMessage(p); err == nil {
				t.Error("the prompt was taken")
			}
		})
	}
	pre := map[string]func(p *approval.Prompt){
		"two uses":     func(p *approval.Prompt) { p.Uses = 2 },
		"a span":       func(p *approval.Prompt) { p.Until = time.Now() },
		"another time": func(p *approval.Prompt) { p.Login.For = time.Hour },
		"no time":      func(p *approval.Prompt) { p.Login.For = 0 },
		"secrets":      func(p *approval.Prompt) { p.Secrets = []string{"a"} },
		"a window":     func(p *approval.Prompt) { p.WindowMinutes = 15 },
	}
	for name, ed := range pre {
		t.Run("pre-approval "+name, func(t *testing.T) {
			p := webPreapprovePrompt()
			ed(&p)
			if _, _, err := promptMessage(p); err == nil {
				t.Error("the prompt was taken")
			}
		})
	}
	t.Run("a login in a secrets prompt", func(t *testing.T) {
		p := secretsPrompt()
		p.Login = webLoginPrompt().Login
		if _, _, err := promptMessage(p); err == nil {
			t.Error("the prompt was taken")
		}
	})
}

func TestWebLoginNotice(t *testing.T) {
	p := webLoginPrompt()
	p.Via, p.Expires, p.TimeLeft, p.Once, p.WindowMinutes = audit.ViaScheduled, time.Time{}, 0, false, 0
	tx, err := noticeText(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := tx.plain.String(); !strings.Contains(got, "🔔 Website login") || !strings.Contains(got, "login: Example shop") {
		t.Errorf("notice:\n%s", got)
	}
}
