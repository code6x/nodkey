package telegram

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
)

// designGrant is the example of an SSH grant in DESIGN.md section 7, as the
// person sees it. It is the message of
//
//	nodkey ssh-grant --key deploy --user deploy --host web-1 --host web-2 \
//	                 --for 15m --reason "apply the nginx fix"
const designGrant = `🔐 SSH grant · request m4k2
✅ machine: laptop
✅ key: deploy
✅ hosts: web-1, web-2
✅ remote user: deploy
✅ grants end: 14:20:00 (15 min)
— claimed by the agent —
reason: apply the nginx fix
expires 14:07:00 (120 s)
[ Approve ] [ Deny ]`

// sshGrantPrompt is the prompt that the core makes for that command:
// nodkey ssh-grant sends no command line, only the reason.
func sshGrantPrompt() approval.Prompt {
	p := grantPrompt()
	p.Claim = approval.Claim{Reason: "apply the nginx fix"}
	return p
}

// TestSSHGrantMessageAsInDesign: the text that the person sees for a
// request of nodkey ssh-grant is exactly the example of DESIGN.md section
// 7, and DESIGN.md still shows it. The verified lines list the key, every
// host, the remote user and the end of the grants. The message has only
// "Approve" and "Deny".
func TestSSHGrantMessageAsInDesign(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "DESIGN.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc), "```\n"+designGrant+"\n```") {
		t.Errorf("DESIGN.md section 7 does not show this message any more:\n%s", designGrant)
	}
	e := newEnv(t)
	shown, err := e.a.Ask(context.Background(), sshGrantPrompt())
	if err != nil {
		t.Fatal(err)
	}
	if shown.Text != designGrant {
		t.Errorf("text:\n%s\nwant:\n%s", shown.Text, designGrant)
	}
}

// TestSSHGrantShowsEveryHost: the message of an SSH grant lists every
// host, also 20 hosts with the longest names, with the longest key name
// and remote user, and a long reason. The reason is cut so that the
// message fits; no verified line is cut, also not after the request
// ended.
func TestSSHGrantShowsEveryHost(t *testing.T) {
	p := sshGrantPrompt()
	p.Key = strings.Repeat("k", 64)
	p.RemoteUser = "u" + strings.Repeat("x", 31)
	p.Hosts = nil
	for i := range approval.MaxGrantHosts {
		p.Hosts = append(p.Hosts, fmt.Sprintf("h%02d-", i)+strings.Repeat("x", 60))
	}
	p.Claim.Reason = strings.Repeat("😀", 3000)
	verified := []string{
		"✅ machine: laptop", "✅ key: " + p.Key, "✅ hosts: " + strings.Join(p.Hosts, ", "),
		"✅ remote user: " + p.RemoteUser, "✅ grants end: 14:20:00 (15 min)",
	}
	asked, kb, err := promptMessage(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := buttonsLine(kb); got != "[ Approve ] [ Deny ]" {
		t.Errorf("the buttons are %s", got)
	}
	approved := endingText(p, approval.Ending{Answer: audit.AnswerApproveWindow, WindowMinutes: 15,
		At: time.Date(2026, 10, 14, 14, 2, 41, 0, time.UTC)})
	for _, tc := range []struct {
		name string
		tx   *text
		last string
	}{
		{"the message", asked, "expires 14:07:00 (120 s)"},
		{"the message after the approval", approved, "👍 approved by you at 14:02:41, until 14:20:00"},
	} {
		plain := tc.tx.plain.String()
		lines := strings.Split(plain, "\n")
		if len(lines) < 9 || !slices.Equal(lines[1:6], verified) {
			t.Errorf("%s: the verified lines are not all there:\n%s", tc.name, plain)
			continue
		}
		if !strings.HasPrefix(lines[7], "reason: 😀") || !strings.HasSuffix(lines[7], "…") || lines[8] != tc.last {
			t.Errorf("%s: the reason is not cut, or the last line is wrong:\n%.300s…%s", tc.name, plain, lines[8])
		}
		if n := utf16Len(plain); n > maxTextUnits {
			t.Errorf("%s: %d UTF-16 code units, more than %d", tc.name, n, maxTextUnits)
		}
	}
}
