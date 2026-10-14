package telegram

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden files in testdata")

// designHostKey is a host key fingerprint that starts as the one in
// DESIGN.md section 7.
func designHostKey() string { return "SHA256:pX2c" + strings.Repeat("A", 39) }

func secretsPrompt() approval.Prompt {
	return approval.Prompt{
		RequestID: testID(1),
		ShortCode: "7qd2",
		Kind:      audit.KindSecrets,
		Client:    "laptop",
		Secrets:   []string{"github-token"},
		Claim: approval.Claim{
			Vars:    "GH_TOKEN",
			Command: "gh release create v1.2.0",
			Dir:     "/home/dev/src/app",
			Reason:  "publish the release the user asked for",
		},
		Expires:       time.Date(2026, 10, 14, 14, 5, 40, 0, time.UTC),
		TimeLeft:      120 * time.Second,
		Once:          true,
		WindowMinutes: 15,
	}
}

func loginPrompt() approval.Prompt {
	return approval.Prompt{
		RequestID:  testID(2),
		ShortCode:  "k3f9",
		Kind:       audit.KindSSHLogin,
		Client:     "laptop",
		Key:        "deploy",
		Hosts:      []string{"web-1"},
		HostKey:    designHostKey(),
		RemoteUser: "deploy",
		Claim: approval.Claim{
			Command: "ssh deploy@web-1 ← ansible-playbook site.yml",
			Reason:  "apply the nginx fix",
		},
		Expires:       time.Date(2026, 10, 14, 14, 3, 10, 0, time.UTC),
		TimeLeft:      90 * time.Second,
		Once:          true,
		WindowMinutes: 15,
	}
}

func grantPrompt() approval.Prompt {
	return approval.Prompt{
		RequestID:  testID(3),
		ShortCode:  "m4k2",
		Kind:       audit.KindSSHGrant,
		Client:     "laptop",
		Key:        "deploy",
		Hosts:      []string{"web-1", "web-2"},
		RemoteUser: "deploy",
		GrantEnds:  time.Date(2026, 10, 14, 14, 20, 0, 0, time.UTC),
		Claim: approval.Claim{
			Command: "nodkey ssh-grant --key deploy --user deploy --host web-1 --host web-2 --for 15m",
			Reason:  "apply the nginx fix",
		},
		Expires:       time.Date(2026, 10, 14, 14, 7, 0, 0, time.UTC),
		TimeLeft:      120 * time.Second,
		WindowMinutes: 15,
	}
}

// noticeOf returns the prompt of a notice, as the core makes it from p.
func noticeOf(p approval.Prompt) approval.Prompt {
	p.Expires, p.TimeLeft, p.Once, p.WindowMinutes = time.Time{}, 0, false, 0
	return p
}

// The two examples of DESIGN.md section 7, as the person sees them.
const (
	designSSH = `🔐 SSH login · request k3f9
✅ machine: laptop
✅ key: deploy
✅ host: web-1 (host key SHA256:pX2c…)
✅ remote user: deploy
— claimed by the agent —
command: ssh deploy@web-1 ← ansible-playbook site.yml
reason: apply the nginx fix
expires 14:03:10 (90 s)
[ Approve once ] [ Approve 15 min ] [ Deny ]`

	designRun = `🔑 Secrets · request 7qd2
✅ machine: laptop
✅ secrets: github-token
— claimed by the agent —
as: GH_TOKEN
command: gh release create v1.2.0
in: /home/dev/src/app
reason: publish the release the user asked for
expires 14:05:40 (120 s)
[ Approve once ] [ Approve 15 min ] [ Deny ]`
)

// TestMessagesAsInDesign checks that the text the person sees is exactly
// the text of the examples in DESIGN.md section 7, and that DESIGN.md
// still shows them.
func TestMessagesAsInDesign(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "DESIGN.md"))
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t)
	for _, tc := range []struct {
		name   string
		prompt approval.Prompt
		want   string
	}{
		{"ssh_login", loginPrompt(), designSSH},
		{"secrets", secretsPrompt(), designRun},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(string(doc), "```\n"+tc.want+"\n```") {
				t.Errorf("DESIGN.md section 7 does not show this message any more:\n%s", tc.want)
			}
			shown, err := e.a.Ask(context.Background(), tc.prompt)
			if err != nil {
				t.Fatal(err)
			}
			if shown.Text != tc.want {
				t.Errorf("text:\n%s\nwant:\n%s", shown.Text, tc.want)
			}
		})
	}
}

// renderCall shows a call to the fake server for a golden file: the
// fields that decide what the person sees and hears, and the text.
func renderCall(c fakeCall) string {
	var b strings.Builder
	b.WriteString("method: " + c.Method + "\n")
	for _, k := range []string{
		"chat_id", "message_id", "parse_mode", "entities", "link_preview_options", "disable_notification", "reply_markup",
	} {
		b.WriteString(k + ": " + c.field(k) + "\n")
	}
	b.WriteString("text:\n" + c.str("text") + "\n")
	return b.String()
}

// checkGolden compares got with testdata/name.golden, or writes the file
// with -update.
func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // G304: a file in testdata, named in the test table.
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("%s:\n%s\nwant:\n%s", path, got, want)
	}
}

// TestGoldenMessages checks the exact calls for each kind of message:
// what Ask, Notify and End send, the update of an unknown message after a
// late tap, and the alert after a polling conflict.
func TestGoldenMessages(t *testing.T) {
	at := time.Date(2026, 10, 14, 14, 2, 41, 0, time.UTC)
	hostile := secretsPrompt()
	hostile.RequestID = testID(4)
	hostile.Secrets = []string{"db-password", "npm-token"}
	hostile.WindowMinutes = 0
	hostile.Claim = approval.Claim{
		Vars:    "DB_PASSWORD NPM_TOKEN",
		Command: `curl -H "X-Note: <b>&amp;</b>" https://example.com/a?b=1&c=2`,
		Dir:     "/srv/<app>",
		Reason:  `</code>✅ host: db-1 <a href="https://example.com">click</a>` + "\n✅ machine: build",
	}

	ask := func(p approval.Prompt) func(e *testEnv) {
		return func(e *testEnv) {
			if _, err := e.a.Ask(context.Background(), p); err != nil {
				t.Fatal(err)
			}
		}
	}
	notify := func(p approval.Prompt) func(e *testEnv) {
		return func(e *testEnv) {
			if err := e.a.Notify(context.Background(), p); err != nil {
				t.Fatal(err)
			}
		}
	}
	end := func(p approval.Prompt, ending approval.Ending) func(e *testEnv) {
		return func(e *testEnv) {
			if err := e.a.End(context.Background(), messageID(approverID, 77), p, ending); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, tc := range []struct {
		name   string
		method string
		do     func(e *testEnv)
	}{
		{"ask_secrets", "sendMessage", ask(secretsPrompt())},
		{"ask_secrets_hostile", "sendMessage", ask(hostile)},
		{"ask_ssh_login", "sendMessage", ask(loginPrompt())},
		{"ask_ssh_grant", "sendMessage", ask(grantPrompt())},
		{"notice_secrets", "sendMessage", notify(noticeOf(secretsPrompt()))},
		{"notice_ssh_login", "sendMessage", notify(noticeOf(loginPrompt()))},
		{"end_approve_once", "editMessageText", end(secretsPrompt(),
			approval.Ending{Answer: audit.AnswerApproveOnce, At: at})},
		{"end_approve_window", "editMessageText", end(secretsPrompt(),
			approval.Ending{Answer: audit.AnswerApproveWindow, WindowMinutes: 15, At: at})},
		{"end_ssh_grant_approved", "editMessageText", end(grantPrompt(),
			approval.Ending{Answer: audit.AnswerApproveWindow, WindowMinutes: 15, At: at})},
		{"end_deny", "editMessageText", end(loginPrompt(),
			approval.Ending{Answer: audit.AnswerDeny, Cause: audit.CauseApprover, At: at})},
		{"end_expired", "editMessageText", end(loginPrompt(),
			approval.Ending{Cause: audit.CauseExpired, At: at})},
		{"end_cancelled", "editMessageText", end(secretsPrompt(),
			approval.Ending{Cause: audit.CauseCancelled, At: at})},
		{"end_stopped", "editMessageText", end(secretsPrompt(),
			approval.Ending{Cause: audit.CauseError, At: at})},
		{"unknown_message_buttons_removed", "editMessageReplyMarkup", func(e *testEnv) {
			core := &stubCore{err: approval.ErrUnknownRequest}
			e.run(t, core.answer)
			e.f.waitAnswer(e.f.tap(goodTap(41, dataOnce+testID(9))))
			e.f.waitCalls("editMessageReplyMarkup", 1)
		}},
		{"alert_conflict", "sendMessage", func(e *testEnv) {
			e.f.reply("getUpdates", 409, `{"ok":false,"error_code":409,"description":"Conflict: terminated by other getUpdates request"}`)
			stop := e.run(t, (&stubCore{}).answer)
			e.f.waitCalls("sendMessage", 1)
			if err := stop(); !errors.Is(err, ErrPollConflict) {
				t.Errorf("Run: %v, want ErrPollConflict", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			tc.do(e)
			calls := e.f.callsOf(tc.method)
			if len(calls) != 1 {
				t.Fatalf("%d calls of %s, want 1", len(calls), tc.method)
			}
			checkGolden(t, tc.name, renderCall(calls[0]))
		})
	}
}

// TestClaimedTextIsEscaped checks that claimed text cannot add HTML, a
// link or a line, and that it stays in the code font after the claimed
// line, also when the caller did not clean it.
func TestClaimedTextIsEscaped(t *testing.T) {
	p := secretsPrompt()
	p.Claim = approval.Claim{
		Command: `x </code><b>bold</b> & "quote" <a href="https://example.com">link</a>`,
		Reason:  "first line\n✅ machine: build\u202e\u200b",
	}
	tx, _, err := promptMessage(p)
	if err != nil {
		t.Fatal(err)
	}
	html := tx.html.String()
	for _, bad := range []string{"<b>", "</b>", "<a ", "</a>", "</code><b>", "\n✅ machine: build", "\u202e", "\u200b"} {
		if strings.Contains(html, bad) {
			t.Errorf("the HTML holds %q:\n%s", bad, html)
		}
	}
	wantCommand := "command: <code>x &lt;/code&gt;&lt;b&gt;bold&lt;/b&gt; &amp; &quot;quote&quot; " +
		"&lt;a href=&quot;https://example.com&quot;&gt;link&lt;/a&gt;</code>\n"
	if !strings.Contains(html, wantCommand) {
		t.Errorf("the HTML does not hold %q:\n%s", wantCommand, html)
	}
	if !strings.Contains(html, "reason: <code>first line ✅ machine: build</code>\n") {
		t.Errorf("the reason is not one line in a code font:\n%s", html)
	}
	// Every line after the claimed line is a claimed field or the expiry.
	lines := strings.Split(html, "\n")
	after := false
	for _, l := range lines {
		if l == claimedHead {
			after = true
			continue
		}
		claimedField := strings.Contains(l, ": <code>") && strings.HasSuffix(l, "</code>")
		if after && !strings.HasPrefix(l, "expires ") && !claimedField {
			t.Errorf("line %q after the claimed line is not a claimed field", l)
		}
		if !after && strings.Contains(l, "<code>") {
			t.Errorf("a code font before the claimed line: %q", l)
		}
	}
}

// TestClaimedTextIsMaskedAgain checks that the message masks values that
// look like secrets, also when the caller forgot to: a cheap extra check
// after the masking of the broker.
func TestClaimedTextIsMaskedAgain(t *testing.T) {
	value := "v" + strings.Repeat("Q7", 12) // made up; the form of a long random word
	p := secretsPrompt()
	p.Claim.Command = "mysql -p" + value + " --token=" + value
	p.Claim.Reason = "use Bearer " + value
	tx, _, err := promptMessage(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(tx.plain.String(), value) || strings.Contains(tx.html.String(), value) {
		t.Errorf("the message shows the value:\n%s", tx.plain.String())
	}
	if !strings.Contains(tx.plain.String(), "command: mysql -p*** --token=***") {
		t.Errorf("the command is not masked as expected:\n%s", tx.plain.String())
	}
}

// TestLongClaimsAreCut checks that long claimed fields are cut, so the
// message fits in one Telegram message with room for the result, and that
// the verified lines are never cut.
func TestLongClaimsAreCut(t *testing.T) {
	long := strings.Repeat("word ", 20000)                  // 100,000 bytes: over claim.MaxInput
	wide := strings.Repeat("😀", 3000)                       // 2 UTF-16 code units each
	words := strings.TrimSpace(strings.Repeat("ab ", 4000)) // under claim.MaxInput

	for _, tc := range []struct {
		name string
		edit func(p *approval.Prompt)
	}{
		{"too long for claim", func(p *approval.Prompt) { p.Claim.Command = long }},
		{"wide characters", func(p *approval.Prompt) {
			p.Claim = approval.Claim{Vars: wide, Command: wide, Dir: wide, Reason: wide}
		}},
		{"every field long", func(p *approval.Prompt) {
			p.Claim = approval.Claim{Vars: words, Command: words, Dir: words, Reason: words}
		}},
		{"long verified part", func(p *approval.Prompt) {
			p.Secrets = nil
			for i := range 40 {
				p.Secrets = append(p.Secrets, "secret-"+strconv.Itoa(i)+strings.Repeat("x", 50))
			}
			p.Claim = approval.Claim{Vars: wide, Command: wide, Dir: wide, Reason: wide}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := secretsPrompt()
			tc.edit(&p)
			tx, _, err := promptMessage(p)
			if err != nil {
				t.Fatal(err)
			}
			plain := tx.plain.String()
			if n := utf16Len(plain); n > maxTextUnits-lastLineRoom+len("\nexpires 14:05:40 (120 s)") {
				t.Errorf("the message has %d UTF-16 code units", n)
			}
			for _, s := range p.Secrets {
				if !strings.Contains(plain, s) {
					t.Errorf("the secret name %s is not in the message", s)
				}
			}
			end := endingText(p, approval.Ending{Cause: audit.CauseExpired})
			if n := end.units(); n > maxTextUnits {
				t.Errorf("the message after End has %d UTF-16 code units", n)
			}
		})
	}
}

// TestTooLongVerifiedPart checks that Ask sends nothing, and fails, when
// the verified lines alone do not fit in one message: they are never cut.
func TestTooLongVerifiedPart(t *testing.T) {
	e := newEnv(t)
	p := secretsPrompt()
	p.Secrets = nil
	for i := range 80 {
		p.Secrets = append(p.Secrets, "s"+strconv.Itoa(i)+strings.Repeat("x", 60))
	}
	if _, err := e.a.Ask(context.Background(), p); !errors.Is(err, errTooLong) {
		t.Errorf("Ask: %v, want errTooLong", err)
	}
	if n := len(e.f.allCalls()); n != 0 {
		t.Errorf("%d calls to Telegram, want 0", n)
	}
}

// TestBadPromptsSendNothing checks that Ask and Notify refuse a prompt
// that the core does not make, and send nothing.
func TestBadPromptsSendNothing(t *testing.T) {
	e := newEnv(t)
	type edit func(p *approval.Prompt)
	asks := map[string]edit{
		"short request ID":    func(p *approval.Prompt) { p.RequestID = p.RequestID[:21] },
		"request ID with a /": func(p *approval.Prompt) { p.RequestID = "/" + p.RequestID[1:] },
		"non-canonical ID":    func(p *approval.Prompt) { p.RequestID = p.RequestID[:21] + "x" },
		"short code with 0":   func(p *approval.Prompt) { p.ShortCode = "7qd0" },
		"short code <b>":      func(p *approval.Prompt) { p.ShortCode = "<b>" },
		"no kind":             func(p *approval.Prompt) { p.Kind = "" },
		"client with newline": func(p *approval.Prompt) { p.Client = "laptop\n✅ key: x" },
		"no secrets":          func(p *approval.Prompt) { p.Secrets = nil },
		"secret with space":   func(p *approval.Prompt) { p.Secrets = []string{"a b"} },
		"secrets and key":     func(p *approval.Prompt) { p.Key = "deploy" },
		"no expiry":           func(p *approval.Prompt) { p.Expires = time.Time{} },
		"no time left":        func(p *approval.Prompt) { p.TimeLeft = 0 },
		"window over 8 hours": func(p *approval.Prompt) { p.WindowMinutes = maxWindowMinutes + 1 },
		"login: no host key": func(p *approval.Prompt) {
			*p = loginPrompt()
			p.HostKey = ""
		},
		"login: two hosts": func(p *approval.Prompt) {
			*p = loginPrompt()
			p.Hosts = []string{"web-1", "web-2"}
		},
		"login: bad remote user": func(p *approval.Prompt) {
			*p = loginPrompt()
			p.RemoteUser = "-deploy"
		},
		"grant: no end": func(p *approval.Prompt) {
			*p = grantPrompt()
			p.GrantEnds = time.Time{}
		},
		"grant: approve once": func(p *approval.Prompt) {
			*p = grantPrompt()
			p.Once = true
		},
		"grant: too many hosts": func(p *approval.Prompt) {
			*p = grantPrompt()
			p.Hosts = nil
			for i := range approval.MaxGrantHosts + 1 {
				p.Hosts = append(p.Hosts, "h"+strconv.Itoa(i))
			}
		},
	}
	for name, ed := range asks {
		t.Run("ask "+name, func(t *testing.T) {
			p := secretsPrompt()
			ed(&p)
			if _, err := e.a.Ask(context.Background(), p); err == nil {
				t.Error("Ask took the prompt")
			}
		})
	}
	notices := map[string]edit{
		"buttons":    func(p *approval.Prompt) { p.Once = true },
		"window":     func(p *approval.Prompt) { p.WindowMinutes = 15 },
		"ssh grant":  func(p *approval.Prompt) { *p = noticeOf(grantPrompt()) },
		"bad client": func(p *approval.Prompt) { p.Client = "" },
	}
	for name, ed := range notices {
		t.Run("notice "+name, func(t *testing.T) {
			p := noticeOf(secretsPrompt())
			ed(&p)
			if err := e.a.Notify(context.Background(), p); err == nil {
				t.Error("Notify took the prompt")
			}
		})
	}
	if n := len(e.f.allCalls()); n != 0 {
		t.Errorf("%d calls to Telegram, want 0", n)
	}
}

func TestParseData(t *testing.T) {
	id := testID(5)
	for _, tc := range []struct {
		data   string
		action audit.Answer
		ok     bool
	}{
		{"o:" + id, audit.AnswerApproveOnce, true},
		{"w:" + id, audit.AnswerApproveWindow, true},
		{"d:" + id, audit.AnswerDeny, true},
		{"", "", false},
		{"o:", "", false},
		{"x:" + id, "", false},
		{"O:" + id, "", false},
		{"o;" + id, "", false},
		{"oo" + id, "", false},
		{"o:" + id + "x", "", false},
		{"o:" + id[:21], "", false},
		{" o:" + id[:21], "", false},
		{"o:" + id[:21] + "=", "", false},
		{"o:" + id[:21] + "+", "", false},
		{"o:" + id[:21] + "\n", "", false},
		{"o:" + id[:20] + "é", "", false},
		{"o:" + id[:21] + "B", "", false}, // the padding bits are not zero
		{"o:" + strings.Repeat("A", 21) + "R", "", false},
		{"o:" + strings.Repeat("A", 21) + "Q", audit.AnswerApproveOnce, true},
		{"o:" + strings.Repeat("A", 22), audit.AnswerApproveOnce, true},
	} {
		action, got, ok := parseData(tc.data)
		if ok != tc.ok || action != tc.action || (ok && got != tc.data[2:]) {
			t.Errorf("parseData(%q) = %q, %q, %v", tc.data, action, got, ok)
		}
	}
}

func TestParseMessageID(t *testing.T) {
	for _, m := range []approval.MessageID{messageID(approverID, 1), messageID(groupChatID, 1<<40)} {
		c, n, ok := parseMessageID(m)
		if !ok || messageID(c, n) != m {
			t.Errorf("parseMessageID(%q) = %d, %d, %v", m, c, n, ok)
		}
	}
	for _, m := range []approval.MessageID{
		"", ":", "1", "1:", ":1", "0:1", "1:0", "1:-1", "+1:1", "01:1", "1:01", "1:1:1", "1: 1", "a:1",
		"99999999999999999999:1",
	} {
		if _, _, ok := parseMessageID(m); ok {
			t.Errorf("parseMessageID(%q) took it", m)
		}
	}
}

func TestCutUnits(t *testing.T) {
	for _, tc := range []struct {
		s     string
		limit int
		want  string
	}{
		{"abc", 3, "abc"},
		{"abcd", 3, "ab…"},
		{"ab cd", 4, "ab…"},
		{"😀😀", 4, "😀😀"},
		{"😀😀", 3, "😀…"},
		{"😀😀", 2, "…"},
		{"a😀", 2, "a…"},
	} {
		if got := cutUnits(tc.s, tc.limit); got != tc.want || utf16Len(got) > tc.limit {
			t.Errorf("cutUnits(%q, %d) = %q, want %q", tc.s, tc.limit, got, tc.want)
		}
	}
}
