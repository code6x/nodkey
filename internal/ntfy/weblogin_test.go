package ntfy

import (
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
)

func webLoginPrompt(t *testing.T) approval.Prompt {
	return approval.Prompt{
		RequestID: newRequestID(t), ShortCode: "w4x8", Kind: audit.KindWebLogin, Client: "laptop",
		Login:    &approval.LoginPrompt{Name: "Example shop", Username: "alice@example.com", Origin: "https://example.com"},
		Claim:    approval.Claim{Reason: "check the order"},
		Expires:  time.Date(2026, 10, 14, 14, 5, 40, 0, time.UTC),
		TimeLeft: 120 * time.Second, Once: true, WindowMinutes: 15,
	}
}

func webPreapprovePrompt(t *testing.T) approval.Prompt {
	p := webLoginPrompt(t)
	p.Kind, p.Uses, p.WindowMinutes = audit.KindPreapprove, 1, 0
	p.Login.For = approval.LoginPreapproveTime
	return p
}

func TestWebLoginText(t *testing.T) {
	p := webLoginPrompt(t)
	if err := checkPrompt(p, false); err != nil {
		t.Fatal(err)
	}
	if got := title(p, false); got != "🌐 Website login · request w4x8" {
		t.Errorf("title %q", got)
	}
	want := "✅ machine: laptop\n✅ login: Example shop\n✅ username: alice@example.com\n" +
		claimedHead + "\npage: https://example.com\nreason: check the order"
	if got := body(p, false, fullCaps); got != want {
		t.Errorf("body:\n%s\nwant:\n%s", got, want)
	}
	if got := withExpiry(want, p); !strings.HasSuffix(got, "expires 14:05:40 (120 s)") {
		t.Errorf("message:\n%s", got)
	}
}

func TestWebLoginPreapproveText(t *testing.T) {
	p := webPreapprovePrompt(t)
	if err := checkPrompt(p, false); err != nil {
		t.Fatal(err)
	}
	if got := title(p, false); got != "🗓 Pre-approval · request w4x8" {
		t.Errorf("title %q", got)
	}
	b := body(p, false, fullCaps)
	want := "✅ machine: laptop\n✅ login: Example shop\n✅ username: alice@example.com\n" +
		"allows: one login in the next 60 s after the tap\n" +
		claimedHead + "\npage: https://example.com\nreason: check the order"
	if b != want {
		t.Errorf("body:\n%s\nwant:\n%s", b, want)
	}
	if got := withExpiry(b, p); got != b || strings.Contains(got, "expire") {
		t.Errorf("the message shows a time limit for the tap:\n%s", got)
	}
	// The other kinds keep theirs.
	s := approval.Prompt{Expires: p.Expires, TimeLeft: p.TimeLeft}
	if got := withExpiry("x", s); !strings.Contains(got, "expires ") {
		t.Errorf("a message lost its expiry: %q", got)
	}
	if got := resultLine(p, approval.Ending{Answer: audit.AnswerApproveOnce, At: p.Expires}); !strings.Contains(got, "one login in the next 60 s") {
		t.Errorf("result line %q", got)
	}
}

func TestWebLoginBadPrompts(t *testing.T) {
	edits := map[string]func(p *approval.Prompt){
		"no login":            func(p *approval.Prompt) { p.Login = nil },
		"no name":             func(p *approval.Prompt) { p.Login.Name = "" },
		"RTL in the name":     func(p *approval.Prompt) { p.Login.Name = "a\u202eb" },
		"newline in the name": func(p *approval.Prompt) { p.Login.Name = "a\n✅ machine: x" },
		"newline in the user": func(p *approval.Prompt) { p.Login.Username = "a\nb" },
		"long name":           func(p *approval.Prompt) { p.Login.Name = strings.Repeat("x", 129) },
		"http origin":         func(p *approval.Prompt) { p.Login.Origin = "http://example.com" },
		"origin with a path":  func(p *approval.Prompt) { p.Login.Origin = "https://example.com/a" },
		"secrets":             func(p *approval.Prompt) { p.Secrets = []string{"a"} },
		"for in a login":      func(p *approval.Prompt) { p.Login.For = time.Minute },
	}
	for name, ed := range edits {
		t.Run(name, func(t *testing.T) {
			p := webLoginPrompt(t)
			ed(&p)
			if checkPrompt(p, false) == nil {
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
			p := webPreapprovePrompt(t)
			ed(&p)
			if checkPrompt(p, false) == nil {
				t.Error("the prompt was taken")
			}
		})
	}
	p := approval.Prompt{
		RequestID: newRequestID(t), ShortCode: "k3f9", Kind: audit.KindSecrets, Client: "laptop",
		Secrets: []string{"a"}, Login: webLoginPrompt(t).Login, Expires: time.Now(), TimeLeft: time.Second,
	}
	if checkPrompt(p, false) == nil {
		t.Error("a login in a secrets prompt was taken")
	}
}
