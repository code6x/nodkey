package telegram

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
)

// designPreapprove is the example of a scheduled grant in DESIGN.md
// section 8, as the person sees it. It is the message of
//
//	nodkey preapprove --secret backup-token --from 2026-10-28T03:00 \
//	                  --until 2026-10-28T04:00 --uses 1 --reason "job nightly-backup"
const designPreapprove = `🗓 Pre-approval · request m4k2
✅ machine: laptop
✅ secrets: backup-token
✅ uses: 1
✅ from: 2026-10-28 03:00:00 UTC
✅ until: 2026-10-28 04:00:00 UTC
— claimed by the agent —
reason: job nightly-backup
expires 14:07:00 (120 s)
[ Approve ] [ Deny ]`

// preapprovePrompt is the prompt that the core makes for that command.
func preapprovePrompt() approval.Prompt {
	return approval.Prompt{
		RequestID: testID(3),
		ShortCode: "m4k2",
		Kind:      audit.KindPreapprove,
		Client:    "laptop",
		Secrets:   []string{"backup-token"},
		Uses:      1,
		From:      time.Date(2026, 10, 28, 3, 0, 0, 0, time.UTC),
		Until:     time.Date(2026, 10, 28, 4, 0, 0, 0, time.UTC),
		Claim:     approval.Claim{Reason: "job nightly-backup"},
		Expires:   time.Date(2026, 10, 14, 14, 7, 0, 0, time.UTC),
		TimeLeft:  120 * time.Second,
		Once:      true,
	}
}

// TestPreapproveMessageAsInDesign: the message of nodkey preapprove is
// exactly the example of DESIGN.md, which still shows it. It has only
// "Approve" and "Deny".
func TestPreapproveMessageAsInDesign(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "DESIGN.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc), "```\n"+designPreapprove+"\n```") {
		t.Errorf("DESIGN.md does not show this message any more:\n%s", designPreapprove)
	}
	e := newEnv(t)
	shown, err := e.a.Ask(context.Background(), preapprovePrompt())
	if err != nil {
		t.Fatal(err)
	}
	if shown.Text != designPreapprove {
		t.Errorf("text:\n%s\nwant:\n%s", shown.Text, designPreapprove)
	}
}

// TestPreapproveKeyMessage: for a key, the message lists the key, every
// host and the remote user, and the span shows the zone of the time.
func TestPreapproveKeyMessage(t *testing.T) {
	p := preapprovePrompt()
	p.Secrets, p.Key, p.Hosts, p.RemoteUser = nil, "deploy", []string{"web-1", "web-2"}, "deploy"
	p.From = p.From.In(time.FixedZone("EEST", 3*3600))
	tx, kb, err := promptMessage(p)
	if err != nil {
		t.Fatal(err)
	}
	plain := tx.plain.String()
	for _, want := range []string{"✅ key: deploy", "✅ hosts: web-1, web-2", "✅ remote user: deploy",
		"✅ uses: 1", "✅ from: 2026-10-28 06:00:00 EEST"} {
		if !strings.Contains(plain, want) {
			t.Errorf("the message lacks %q:\n%s", want, plain)
		}
	}
	if got := buttonsLine(kb); got != "[ Approve ] [ Deny ]" {
		t.Errorf("the buttons are %s", got)
	}
	end := endingText(p, approval.Ending{Answer: audit.AnswerApproveOnce,
		At: time.Date(2026, 10, 14, 14, 2, 41, 0, time.UTC)})
	if !strings.Contains(end.plain.String(), "👍 approved by you at 14:02:41, for 1 use(s) until 2026-10-28 04:00:00 UTC") {
		t.Errorf("the result line is wrong:\n%s", end.plain.String())
	}
}

// TestPreapprovePromptChecks: a prompt that the core would not make is
// refused, so the message cannot show more or less than it should.
func TestPreapprovePromptChecks(t *testing.T) {
	for name, change := range map[string]func(*approval.Prompt){
		"no uses":             func(p *approval.Prompt) { p.Uses = 0 },
		"no start":            func(p *approval.Prompt) { p.From = time.Time{} },
		"end before start":    func(p *approval.Prompt) { p.Until = p.From },
		"no buttons":          func(p *approval.Prompt) { p.Once = false },
		"a window button":     func(p *approval.Prompt) { p.WindowMinutes = 5 },
		"secrets and a key":   func(p *approval.Prompt) { p.Key = "deploy" },
		"no names":            func(p *approval.Prompt) { p.Secrets = nil },
		"a key without hosts": func(p *approval.Prompt) { p.Secrets, p.Key, p.RemoteUser = nil, "deploy", "deploy" },
		"a bad secret name":   func(p *approval.Prompt) { p.Secrets = []string{"a b"} },
		"a host key":          func(p *approval.Prompt) { p.HostKey = "SHA256:" + strings.Repeat("A", 43) },
		"a via in a message":  func(p *approval.Prompt) { p.Via = audit.ViaScheduled },
		"no expiry":           func(p *approval.Prompt) { p.TimeLeft = 0 },
		"uses in a secrets":   func(p *approval.Prompt) { p.Kind = audit.KindSecrets },
		"a grant end in it":   func(p *approval.Prompt) { p.GrantEnds = p.Until },
		"too many hosts":      func(p *approval.Prompt) { p.Secrets, p.Key, p.RemoteUser, p.Hosts = nil, "k", "u", make([]string, 21) },
	} {
		p := preapprovePrompt()
		change(&p)
		if _, _, err := promptMessage(p); err == nil {
			t.Errorf("%s: the prompt was accepted", name)
		}
	}
	// A notice of a preapprove request does not exist.
	if _, err := noticeText(noticeOf(preapprovePrompt())); err == nil {
		t.Error("a notice of a preapprove request was accepted")
	}
}

// TestScheduledNotice: the notice of a use of a scheduled grant says so,
// and a notice of a "never ask" use does not.
func TestScheduledNotice(t *testing.T) {
	p := approval.Prompt{
		RequestID: testID(4), ShortCode: "k3f9", Kind: audit.KindSecrets, Client: "laptop",
		Secrets: []string{"backup-token"}, Via: audit.ViaScheduled,
	}
	tx, err := noticeText(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := tx.plain.String(); !strings.Contains(got, "\n"+scheduledNoticeLine+"\n") {
		t.Errorf("the notice of a scheduled use:\n%s", got)
	}
	p.Via = ""
	tx, err = noticeText(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := tx.plain.String(); !strings.Contains(got, noticeLine) || strings.Contains(got, "scheduled") {
		t.Errorf("the notice of a never ask use:\n%s", got)
	}
	p.Via = "other"
	if _, err := noticeText(p); err == nil {
		t.Error("a notice with an unknown via was accepted")
	}
}
