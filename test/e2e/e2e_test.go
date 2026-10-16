//go:build e2e

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestEndToEnd is the end-to-end test of version 1 (issue #15, DESIGN.md
// section 17): the real nodkey broker, nodkey run, nodkey ssh-agent and
// nodkey ssh-grant, the real ssh and git, sshd in a container, and the
// person's taps at a fake Telegram server. Each case also checks the
// entries that it adds to the audit log. At the end, nodkey audit verify
// checks the whole log with every anchor of the broker's journal, and
// the canary search looks at every log and every output.
//
// The cases run in this order on purpose. A Deny pauses the key for 60
// seconds and ends its grants (DESIGN.md section 8), so the denied login
// comes last, and the grants of ssh-grant and of "Approve 15 min" cover
// hosts that the later cases do not expect to be covered.
func TestEndToEnd(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, c := range []struct {
		name string
		run  func(*testing.T)
	}{
		{"nodkey run passes the secret into the command", e.runApproved},
		{"nodkey run denied", e.runDenied},
		{"ssh login approved", e.loginApproved},
		{"unknown host key refused", e.unknownHostKey},
		{"ssh-grant covers exactly the listed hosts", e.sshGrant},
		{"git over SSH", e.gitOverSSH},
		{"ssh login denied, and the Deny ends the grants", e.loginDenied},
	} {
		t.Run(c.name, func(t *testing.T) {
			e.audit.unchecked(t)
			c.run(t)
		})
	}
	t.Run("the clients and the broker stop", e.stop)
	t.Run("nodkey audit verify passes with every anchor", e.verifyAudit)
	t.Run("only the messages of requests and the audit log hold claimed text", e.searchClaimed)
	t.Run("the canaries and the tokens are nowhere", e.searchCanaries)
}

// TestAgentRefusesAnotherRealUserInDocker runs the root-only test of
// internal/client (issue #13) as root in a container, where it can switch
// a child process to another user: that process connects to the socket of
// nodkey ssh-agent, and the agent refuses it (SO_PEERCRED). The test must
// pass there, not skip.
func TestAgentRefusesAnotherRealUserInDocker(t *testing.T) {
	t.Parallel()
	img := sshdImage(t)
	bin := buildClientTest(t, subdirectory(t, "root-"))
	out, code := runAsRoot(t, img, bin,
		"-test.run=^TestAgentRefusesAnotherRealUser$", "-test.v", "-test.count=1", "-test.timeout=2m")
	switch {
	case code != 0:
		t.Fatalf("the test of internal/client failed in the container (exit %d):\n%s", code, out)
	case !strings.Contains(out, "--- PASS: TestAgentRefusesAnotherRealUser "):
		t.Fatalf("the test of internal/client did not pass in the container:\n%s", out)
	case strings.Contains(out, "--- SKIP"):
		t.Fatalf("the test of internal/client skipped in the container:\n%s", out)
	}
	t.Logf("in the container, as root:\n%s", out)
}

// Patterns of the lines of a message (DESIGN.md section 7).
const (
	codePattern   = `[2-9a-hjkmnp-z]{4}` // a short code
	clockPattern  = `\d\d:\d\d:\d\d`
	expiryPattern = `^expires ` + clockPattern + ` \(\d+ s\)$`
	// wrapperShown is how the command line of the wrapper shows in a
	// message: both forms of the second canary masked.
	wrapperShown = wrapperArg + " --api-token=*** *** -- "
)

// lit returns a pattern that matches exactly s.
func lit(s string) string { return "^" + regexp.QuoteMeta(s) + "$" }

// checkLines fails unless text has one line for each pattern, and each
// line matches its pattern.
func checkLines(t *testing.T, what, text string, patterns ...string) {
	t.Helper()
	lines := strings.Split(text, "\n")
	if len(lines) != len(patterns) {
		t.Errorf("%s has %d lines, want %d:\n%s", what, len(lines), len(patterns), redact(text))
		return
	}
	for i, p := range patterns {
		if !regexp.MustCompile(p).MatchString(lines[i]) {
			t.Errorf("%s: line %d is %q, want it to match %q", what, i+1, redact(lines[i]), p)
		}
	}
}

// shortCode returns the short code in the first line of a message.
func shortCode(t *testing.T, m tgMessage) string {
	t.Helper()
	first, _, _ := strings.Cut(m.text, "\n")
	code := first[strings.LastIndexByte(first, ' ')+1:]
	if !regexp.MustCompile("^" + codePattern + "$").MatchString(code) {
		t.Fatalf("the first line of the message has no short code: %q", redact(first))
	}
	return code
}

// checkMessageEntry checks the message of the request entry en: the exact
// text that the person saw, and the buttons as its last line (DESIGN.md
// section 9).
func checkMessageEntry(t *testing.T, en entry, m tgMessage, buttons string) {
	t.Helper()
	if got, want := en.field("message"), m.text+"\n"+buttons; got != want {
		t.Errorf("the request entry has the message\n%s\nwant the message that the person saw\n%s",
			redact(got), redact(want))
	}
}

// checkResult waits until the broker shows the end of the request on its
// message, and checks that line.
func (e *env) checkResult(t *testing.T, m tgMessage, pattern string) {
	t.Helper()
	if got := e.tg.waitResult(t, m); !regexp.MustCompile(pattern).MatchString(got) {
		t.Errorf("the message shows the result %q, want it to match %q", redact(got), pattern)
	}
}

// tapAndCheck taps the button prefix on m, and checks the text that the
// phone shows.
func (e *env) tapAndCheck(t *testing.T, m tgMessage, prefix, want string) {
	t.Helper()
	if got := e.tg.tap(t, m, prefix); got != want {
		t.Errorf("the phone shows %q after the tap, want %q", redact(got), want)
	}
}

// checkMessages fails unless want messages went out since there were n:
// with buttons or without. An alert or a notice counts too.
func (e *env) checkMessages(t *testing.T, n, want int) {
	t.Helper()
	if got := e.tg.sent() - n; got != want {
		t.Errorf("%d messages went out, want %d", got, want)
	}
}

// nodkeyRun starts nodkey run as the client ci, with the secret of the
// broker in secretVar, and the command argv.
func (e *env) nodkeyRun(t *testing.T, reason string, argv ...string) *proc {
	t.Helper()
	args := append([]string{e.bin, "run", "--secret", secretVar + "=" + secretName, "--reason", reason, "--"}, argv...)
	return e.procs.start(t, "nodkey run", filepath.Join(e.ci.home, "work"), e.ci.env(), nil, args...)
}

// lookIn returns the path of the program name in the directories of path,
// as nodkey run finds it.
func lookIn(t *testing.T, path, name string) string {
	t.Helper()
	for dir := range strings.SplitSeq(path, ":") {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p
		}
	}
	t.Fatalf("no %s in %s", name, path)
	return ""
}

// secretsSubject returns the fields of every audit entry of a request of
// nodkey run by ci.
func secretsSubject(command, reason string) map[string]string {
	return map[string]string{
		"client": "ci", "kind": "secrets", "secrets": secretName, "key": "", "hosts": "", "host_key": "",
		"remote_user": "", "command": command, "reason": reason,
	}
}

// runApproved: nodkey run asks, the person taps "Approve once", and the
// command gets the value of the secret in its environment. It proves this
// by the SHA-256 of the value, and prints nothing else; nodkey prints only
// the short code (DESIGN.md section 5).
func (e *env) runApproved(t *testing.T) {
	reason := e.reason("e2e: give the command the canary secret")
	script := `printf %s "$` + secretVar + `" | sha256sum`
	n := e.tg.sent()
	p := e.nodkeyRun(t, reason, "sh", "-c", script)
	m := e.tg.waitMessage(t, n+1, p)
	code := shortCode(t, m)
	command := lookIn(t, clientPath, "sh") + " -c '" + script + "'"
	checkLines(t, "the message", m.text,
		lit("🔑 Secrets · request "+code),
		lit("✅ machine: ci"),
		lit("✅ secrets: "+secretName),
		lit("— claimed by the agent —"),
		lit("as: "+secretVar),
		lit("command: "+command),
		`^in: \S+/ci/work$`,
		lit("reason: "+reason),
		expiryPattern)
	if want := []string{tapOnce + m.requestID, tapDeny + m.requestID}; !slices.Equal(m.buttons, want) {
		t.Errorf("the buttons %q, want %q: the rule is always", m.buttons, want)
	}
	e.tapAndCheck(t, m, tapOnce, "Approved.")
	p.mustExit(t, 0)

	sum := sha256.Sum256([]byte(e.canary1))
	if got, want := p.stdout.all(), []string{hex.EncodeToString(sum[:]) + "  -"}; !slices.Equal(got, want) {
		t.Errorf("the command printed %q, want the SHA-256 of the secret: %q", redact(strings.Join(got, "\n")), want)
	}
	if got, want := p.stderr.all(), []string{"nodkey: waiting for approval (request " + code + ")"}; !slices.Equal(got, want) {
		t.Errorf("nodkey run wrote %q to stderr, want %q", redact(strings.Join(got, "\n")), want)
	}
	entries := e.audit.next(t, secretsSubject(command, reason), "request", "decision:approve_once", "secret_sent")
	checkMessageEntry(t, entries[0], m, "[ Approve once ] [ Deny ]")
	if id := entries[1].field("user_id"); id != strconv.FormatInt(approverID, 10) {
		t.Errorf("the decision entry has the user ID %q, want the approver's", id)
	}
	e.checkResult(t, m, `^👍 approved once by you at `+clockPattern+`$`)
	e.checkMessages(t, n, 1)
}

// runDenied: the person taps Deny. nodkey run exits with 77, and the
// command does not run.
func (e *env) runDenied(t *testing.T) {
	reason := e.reason("e2e: a command that must not run")
	const file = "the-command-ran" // in the working directory of nodkey run
	marker := filepath.Join(e.ci.home, "work", file)
	n := e.tg.sent()
	p := e.nodkeyRun(t, reason, "touch", file)
	m := e.tg.waitMessage(t, n+1, p)
	e.tapAndCheck(t, m, tapDeny, "Denied.")
	p.mustExit(t, 77)
	if last := p.stderr.last(); last != "nodkey: denied (exit 77)" {
		t.Errorf("the last line of nodkey run is %q, want %q", redact(last), "nodkey: denied (exit 77)")
	}
	if fileExists(marker) {
		t.Error("the command ran after a Deny")
	}
	command := lookIn(t, clientPath, "touch") + " " + file
	e.audit.next(t, secretsSubject(command, reason), "request", "decision:deny", "denied:approver")
	e.checkResult(t, m, `^⛔ denied by you at `+clockPattern+`$`)
	e.checkMessages(t, n, 1)
}

// loginSubject returns the fields of every audit entry of an SSH login by
// laptop as user to host, which the broker checked.
func (e *env) loginSubject(user, host, reason string) map[string]string {
	return map[string]string{
		"client": "laptop", "kind": "ssh_login", "key": keyName, "secrets": "", "hosts": host,
		"host_key": ssh.FingerprintSHA256(e.hostKeys[host]), "remote_user": user, "reason": reason,
	}
}

// checkLoginMessage checks the message of an SSH login as user to host
// that ssh made through the wrapper (DESIGN.md section 7): the verified
// lines, and the claimed command lines of ssh and its parents, with the
// second canary masked in the command line of the wrapper.
func (e *env) checkLoginMessage(t *testing.T, m tgMessage, user, host, reason string) {
	t.Helper()
	fp := ssh.FingerprintSHA256(e.hostKeys[host])
	checkLines(t, "the message", m.text,
		`^🔐 SSH login · request `+codePattern+`$`,
		lit("✅ machine: laptop"),
		lit("✅ key: "+keyName),
		lit("✅ host: "+host+" (host key "+fp[:len("SHA256:")+4]+"…)"),
		lit("✅ remote user: "+user),
		lit("— claimed by the agent —"),
		"^command: "+regexp.QuoteMeta(e.sshPath+" -F ")+`\S+`+regexp.QuoteMeta(" "+user+"@"+host+" echo e2e-ok ← ")+
			`\S+`+regexp.QuoteMeta(" "+wrapperShown+e.sshPath+" -F "),
		lit("reason: "+reason),
		expiryPattern)
	if want := []string{tapOnce + m.requestID, tapWindow + m.requestID, tapDeny + m.requestID}; !slices.Equal(m.buttons, want) {
		t.Errorf("the buttons %q, want %q: the rule is window", m.buttons, want)
	}
}

// login logs in with ssh as user to host, and checks what the message
// shows. It taps the button prefix, and checks that ssh logs in. It
// returns the audit entries of the login.
func (e *env) login(t *testing.T, user, host, prefix string) []entry {
	t.Helper()
	reason := e.reason("e2e: log in to " + host + " as " + user)
	n, agentLines := e.tg.sent(), e.agent.stderr.count()
	p := e.ssh(t, user, host, reason)
	m := e.tg.waitMessage(t, n+1, p)
	code := shortCode(t, m)
	e.checkLoginMessage(t, m, user, host, reason)
	e.tapAndCheck(t, m, prefix, "Approved.")
	p.mustExit(t, 0)
	if got := p.stdout.all(); !slices.Equal(got, []string{"e2e-ok"}) {
		t.Errorf("ssh printed %q, want the output of the command", redact(strings.Join(got, "\n")))
	}
	want := []string{"nodkey: waiting for approval (request " + code + ")"}
	if got := e.agent.stderr.next(agentLines, len(want)); !slices.Equal(got, want) {
		t.Errorf("nodkey ssh-agent wrote %q, want %q", redact(strings.Join(got, "\n")), want)
	}
	answer := map[string]string{tapOnce: "decision:approve_once", tapWindow: "decision:approve_window"}[prefix]
	entries := e.audit.next(t, e.loginSubject(user, host, reason), "request", answer, "signed")
	checkMessageEntry(t, entries[0], m, "[ Approve once ] [ Approve 15 min ] [ Deny ]")
	if command := entries[0].field("command"); !strings.Contains(command, wrapperShown) {
		t.Errorf("the request entry has the command %q, want the masked command line of the wrapper", redact(command))
	}
	result := `^👍 approved once by you at ` + clockPattern + `$`
	if prefix == tapWindow {
		result = `^👍 approved for 15 min by you at ` + clockPattern + `$`
		if w := entries[1].field("window_minutes"); w != "15" {
			t.Errorf("the decision entry has window_minutes %q, want 15", w)
		}
	}
	e.checkResult(t, m, result)
	e.checkMessages(t, n, 1)
	return entries
}

// loginByGrant logs in with ssh as user to host, and checks that a grant
// let it in, without a message.
func (e *env) loginByGrant(t *testing.T, user, host string) {
	t.Helper()
	reason := e.reason("e2e: log in to " + host + " as " + user)
	n := e.tg.sent()
	p := e.ssh(t, user, host, reason)
	p.mustExit(t, 0)
	if e.tg.sent() != n {
		t.Errorf("a message went out for the login to %s; a grant should cover it, without a message", host)
	}
	subject := e.loginSubject(user, host, reason)
	subject["message"] = "" // no message
	e.audit.next(t, subject, "request", "grant_used:grant", "signed")
}

// loginApproved: ssh logs in to web-1 after the person taps "Approve
// once". The message names the host from the broker's own known_hosts,
// and shows the claimed command lines, masked.
func (e *env) loginApproved(t *testing.T) {
	e.login(t, "deploy", "web-1", tapOnce)
}

// unknownHostKey: web-3's host key is not in the broker's known_hosts. The
// broker refuses the login before any message, and its log says why.
func (e *env) unknownHostKey(t *testing.T) {
	reason := e.reason("e2e: log in to web-3")
	n, agentLines := e.tg.sent(), e.agent.stderr.count()
	p := e.ssh(t, "deploy", unknownTarget, reason)
	p.mustExit(t, 255)
	if !p.stderr.has("Permission denied (publickey)") {
		t.Errorf("ssh does not say that the login was refused:\n%s", p.output())
	}
	if e.tg.sent() != n {
		t.Error("a message went out about a host that is not in the broker's known_hosts")
	}
	want := []string{"nodkey: no signature: denied"}
	if got := e.agent.stderr.next(agentLines, len(want)); !slices.Equal(got, want) {
		t.Errorf("nodkey ssh-agent wrote %q, want %q", redact(strings.Join(got, "\n")), want)
	}
	e.broker.stderr.settled(t, "nodkey broker", "the host key is not in the broker's known_hosts")
	// The entries name the key, and no host: the check of the host failed.
	e.audit.next(t, map[string]string{
		"client": "laptop", "kind": "ssh_login", "key": keyName, "hosts": "", "host_key": "", "remote_user": "",
		"reason": reason, "message": "",
	}, "request", "denied:not_allowed")
}

// sshGrant: one tap on the message of nodkey ssh-grant lets ssh log in to
// the listed hosts, web-1 and web-2, as deploy, without another tap. A
// host that is not listed, db-1, still asks, and so does another remote
// user, ops, on a listed host (DESIGN.md section 13).
func (e *env) sshGrant(t *testing.T) {
	reason := e.reason("e2e: apply the nginx fix")
	n := e.tg.sent()
	p := e.procs.start(t, "nodkey ssh-grant", filepath.Join(e.laptop.home, "work"), e.laptop.env(), nil,
		e.bin, "ssh-grant", "--key", keyName, "--user", "deploy", "--host", "web-1", "--host", "web-2",
		"--for", "15m", "--reason", reason)
	m := e.tg.waitMessage(t, n+1, p)
	code := shortCode(t, m)
	checkLines(t, "the message", m.text,
		lit("🔐 SSH grant · request "+code),
		lit("✅ machine: laptop"),
		lit("✅ key: "+keyName),
		lit("✅ hosts: web-1, web-2"),
		lit("✅ remote user: deploy"),
		`^✅ grants end: `+clockPattern+` \(15 min\)$`,
		lit("— claimed by the agent —"),
		lit("reason: "+reason),
		expiryPattern)
	if want := []string{tapWindow + m.requestID, tapDeny + m.requestID}; !slices.Equal(m.buttons, want) {
		t.Errorf("the buttons %q, want %q: Approve and Deny", m.buttons, want)
	}
	e.tapAndCheck(t, m, tapWindow, "Approved.")
	p.mustExit(t, 0)
	if lines := p.stderr.all(); len(lines) != 2 || lines[0] != "nodkey: waiting for approval (request "+code+")" ||
		!regexp.MustCompile(`^nodkey: SSH logins as deploy to 2 hosts allowed until \d\d:\d\d \(exit 0\)$`).MatchString(lines[1]) {
		t.Errorf("nodkey ssh-grant wrote %q", redact(strings.Join(lines, "\n")))
	}
	if out := p.stdout.text(); out != "" {
		t.Errorf("nodkey ssh-grant printed %q on stdout", redact(out))
	}
	entries := e.audit.next(t, map[string]string{
		"client": "laptop", "kind": "ssh_grant", "key": keyName, "hosts": "web-1,web-2", "host_key": "",
		"remote_user": "deploy", "reason": reason, "command": "",
	}, "request", "decision:approve_window")
	checkMessageEntry(t, entries[0], m, "[ Approve ] [ Deny ]")
	if w := entries[1].field("window_minutes"); w != "15" {
		t.Errorf("the decision entry has window_minutes %q, want 15", w)
	}
	e.checkResult(t, m, `^👍 approved by you at `+clockPattern+`, until `+clockPattern+`$`)
	e.checkMessages(t, n, 1)

	// The listed hosts: no tap.
	e.loginByGrant(t, "deploy", "web-1")
	e.loginByGrant(t, "deploy", "web-2")
	// A host that is not listed still asks, and so does another remote
	// user on a listed host.
	e.login(t, "deploy", "db-1", tapOnce)
	e.login(t, "ops", "web-1", tapOnce)
}

// gitOverSSH: git clones the bare repository on db-1, pushes a commit to
// it, and clones it again, with ssh through nodkey ssh-agent. The first
// login asks, and the person taps "Approve 15 min"; that grant covers the
// two logins after it (DESIGN.md section 8).
func (e *env) gitOverSSH(t *testing.T) {
	work := filepath.Join(e.laptop.home, "git")
	mkdirs(t, work)
	reason := e.reason("e2e: git over SSH")
	n := e.tg.sent()
	clone := e.git(t, work, reason, "clone", "deploy@db-1:repo.git", "one")
	m := e.tg.waitMessage(t, n+1, clone)
	code := shortCode(t, m)
	if !strings.Contains(m.text, "✅ host: db-1 (host key ") || !strings.Contains(m.text, "git-upload-pack") {
		t.Errorf("the message of git clone:\n%s", redact(m.text))
	}
	e.tapAndCheck(t, m, tapWindow, "Approved.")
	clone.mustExit(t, 0)
	e.agent.stderr.settled(t, "nodkey ssh-agent", "nodkey: waiting for approval (request "+code+")")
	entries := e.audit.next(t, e.loginSubject("deploy", "db-1", reason), "request", "decision:approve_window", "signed")
	checkMessageEntry(t, entries[0], m, "[ Approve once ] [ Approve 15 min ] [ Deny ]")
	e.checkResult(t, m, `^👍 approved for 15 min by you at `+clockPattern+`$`)

	// A commit, and a push: the grant covers the login of git push.
	one := filepath.Join(work, "one")
	writeFile(t, filepath.Join(one, "README"), []byte("nodkey end-to-end test\n"))
	e.git(t, one, reason, "add", "README").mustExit(t, 0)
	e.git(t, one, reason, "commit", "--quiet", "--message", "e2e: a commit over SSH").mustExit(t, 0)
	e.git(t, one, reason, "push", "--quiet", "origin", "HEAD:refs/heads/main").mustExit(t, 0)
	subject := e.loginSubject("deploy", "db-1", reason)
	subject["message"] = ""
	e.audit.next(t, subject, "request", "grant_used:grant", "signed")

	// A new clone has the commit.
	e.git(t, work, reason, "clone", "--quiet", "deploy@db-1:repo.git", "two").mustExit(t, 0)
	e.audit.next(t, subject, "request", "grant_used:grant", "signed")
	if e.tg.sent() != n+1 {
		t.Errorf("%d messages went out for git, want 1: the grant covers the push and the second clone", e.tg.sent()-n)
	}
	head := func(dir string) string {
		p := e.git(t, dir, reason, "rev-parse", "HEAD")
		p.mustExit(t, 0)
		return p.stdout.text()
	}
	if h1, h2 := head(one), head(filepath.Join(work, "two")); h1 != h2 || len(h1) < 40 {
		t.Errorf("the second clone has the commit %q, want %q", h2, h1)
	}
	if got := string(readFile(t, filepath.Join(work, "two", "README"))); got != "nodkey end-to-end test\n" {
		t.Errorf("the second clone has README %q", got)
	}
}

// loginDenied: the person taps Deny, and ssh does not log in. The Deny
// also ends every grant of the key at once, and new requests for the key
// are denied without a message for 60 seconds (DESIGN.md section 8): a
// grant is checked before that pause, so the login to web-1, which the
// grant of ssh-grant allowed before, is denied now.
func (e *env) loginDenied(t *testing.T) {
	reason := e.reason("e2e: log in to db-1 as ops")
	n, agentLines := e.tg.sent(), e.agent.stderr.count()
	p := e.ssh(t, "ops", "db-1", reason)
	m := e.tg.waitMessage(t, n+1, p)
	code := shortCode(t, m)
	e.checkLoginMessage(t, m, "ops", "db-1", reason)
	e.tapAndCheck(t, m, tapDeny, "Denied.")
	p.mustExit(t, 255)
	if !p.stderr.has("Permission denied (publickey)") {
		t.Errorf("ssh does not say that the login was refused:\n%s", p.output())
	}
	want := []string{"nodkey: waiting for approval (request " + code + ")", "nodkey: no signature (request " + code + "): denied"}
	if got := e.agent.stderr.next(agentLines, len(want)); !slices.Equal(got, want) {
		t.Errorf("nodkey ssh-agent wrote %q, want %q", redact(strings.Join(got, "\n")), want)
	}
	entries := e.audit.next(t, e.loginSubject("ops", "db-1", reason), "request", "decision:deny", "denied:approver")
	checkMessageEntry(t, entries[0], m, "[ Approve once ] [ Approve 15 min ] [ Deny ]")
	e.checkResult(t, m, `^⛔ denied by you at `+clockPattern+`$`)

	// The grant of ssh-grant for web-1 has ended.
	reason = e.reason("e2e: log in to web-1 as deploy")
	agentLines = e.agent.stderr.count()
	p = e.ssh(t, "deploy", "web-1", reason)
	p.mustExit(t, 255)
	if e.tg.sent() != n+1 {
		t.Error("a message went out during the pause after a Deny")
	}
	want = []string{"nodkey: no signature: denied by a limit of the broker"}
	if got := e.agent.stderr.next(agentLines, len(want)); !slices.Equal(got, want) {
		t.Errorf("nodkey ssh-agent wrote %q, want %q", redact(strings.Join(got, "\n")), want)
	}
	subject := e.loginSubject("deploy", "web-1", reason)
	subject["message"] = ""
	e.audit.next(t, subject, "request", "denied:limit")
}

// stop stops nodkey ssh-agent and nodkey broker with SIGTERM, as systemd
// does, and checks that each ends as DESIGN.md section 15 says.
func (e *env) stop(t *testing.T) {
	e.agent.signal(t, syscall.SIGTERM)
	if code := e.agent.wait(t); code != 128+int(syscall.SIGTERM) {
		t.Errorf("nodkey ssh-agent ended with %d, want to die of SIGTERM", code)
	}
	if last := e.agent.stderr.last(); last != "nodkey: stopped by SIGTERM (exit 143)" {
		t.Errorf("the last line of nodkey ssh-agent is %q", redact(last))
	}
	if fileExists(e.socket) {
		t.Error("nodkey ssh-agent left its socket")
	}
	if !fileExists(e.socket + ".lock") {
		t.Error("the lock file of nodkey ssh-agent is gone; it stays after the agent ends")
	}
	e.broker.signal(t, syscall.SIGTERM)
	e.broker.mustExit(t, 0)
	e.broker.stderr.inOrder(t, "nodkey broker", "nodkey broker: stopping, as a signal asked",
		"nodkey broker: the audit log is closed", lineStopped+`" exit_code=0`)
	e.audit.next(t, map[string]string{}, "broker_stopped")
	e.audit.unchecked(t)
	if entries := e.audit.entries(t); len(entries) == 0 || entries[0].name() != "broker_started" {
		t.Errorf("the audit log does not start with broker_started: %q", eventNames(entries))
	}
	for _, p := range e.procs.all() {
		if p.stderr.has("DATA RACE") {
			t.Errorf("the race detector found a data race in %s", p.name)
		}
	}
	for _, c := range e.tg.proxied() {
		if c != "CONNECT "+telegramHost+":443" {
			t.Errorf("the fake proxy was asked for %q", c)
		}
	}
}

// verifyAudit: nodkey audit verify checks the whole audit log with every
// anchor that the broker wrote to its journal (stderr), as DESIGN.md
// section 9 says: journalctl -u nodkey -o cat | nodkey audit verify FILE
// --anchors -. Every entry has its anchor. A copy of the log with one
// changed entry fails.
func (e *env) verifyAudit(t *testing.T) {
	data := readFile(t, e.auditPath)
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	n := len(lines)
	journal := e.broker.stderr.text()
	if got := strings.Count("\n"+journal, "\naudit anchor "); got != n {
		t.Errorf("the journal has %d anchors, want one for each of the %d entries", got, n)
	}
	verify := func(name, path string) *proc {
		return e.procs.start(t, name, "", append([]string{"PATH=" + clientPath}, quickExit()...),
			strings.NewReader(journal), e.bin, "audit", "verify", path, "--anchors", "-")
	}
	p := verify("nodkey audit verify", e.auditPath)
	p.mustExit(t, 0)
	last := sha256.Sum256([]byte(lines[n-1]))
	checkLines(t, "the output of nodkey audit verify", strings.TrimSuffix(p.stdout.text(), "\n"),
		lit("ok: "+strconv.Itoa(n)+" entries (torn lines: 0)"),
		lit("anchors: "+strconv.Itoa(n)+" checked, all match; the newest is entry "+strconv.Itoa(n)),
		lit("last entry: "+strconv.Itoa(n)+":"+hex.EncodeToString(last[:])))

	// A copy with one changed field: the client of the first request.
	i := slices.IndexFunc(lines, func(l string) bool { return strings.Contains(l, `"client":"`) })
	if i < 0 {
		t.Fatal("no entry of the audit log names a client")
	}
	lines[i] = strings.Replace(lines[i], `"client":"`, `"client":"x`, 1)
	changed := filepath.Join(e.dir, "state", "changed.jsonl")
	writeFile(t, changed, []byte(strings.Join(lines, "\n")+"\n"))
	p = verify("nodkey audit verify (a changed entry)", changed)
	p.mustExit(t, 65)
	// The changed line fails its anchor, or the line after it fails its
	// link to it, whichever the check finds first.
	if !p.stderr.has(": line "+strconv.Itoa(i+1)+": ") && !p.stderr.has(": line "+strconv.Itoa(i+2)+": ") {
		t.Errorf("nodkey audit verify does not name the changed line %d:\n%s", i+1, p.output())
	}
}

// claimedTexts returns parts of the claimed text that the cases sent:
// each reason, and words of the command lines, of the working directory
// and of the variable name.
func (e *env) claimedTexts() []string {
	return append(slices.Clone(e.reasons), wrapperArg, "--api-token", "echo e2e-ok", "sha256sum", "the-command-ran",
		"git-upload-pack", "git-receive-pack", secretVar, "/ci/work")
}

// firstOf returns the first of parts that text holds, or "".
func firstOf(text string, parts []string) string {
	for _, p := range parts {
		if strings.Contains(text, p) {
			return p
		}
	}
	return ""
}

// searchClaimed checks where the claimed text of the cases went. DESIGN.md
// section 7 shows claimed text only in the message of a request, and
// section 9 keeps it in the audit log. So no other call to Telegram holds
// it, such as an alert, a notice or the answer to a tap, and no output of
// nodkey: not the broker's journal, not nodkey ssh-agent, and not the
// lines of nodkey run, nodkey ssh-grant, nodkey keygen and nodkey audit
// verify. The config of the test has no "never ask" rule, so no notice
// goes out, and nothing in the test makes an alert. The client and the
// broker are the same build from the source, so no notice about a version
// goes out either (DESIGN.md section 10): every message must have
// buttons. It runs after the broker has stopped, when its alerts in the
// background have gone out too.
func (e *env) searchClaimed(t *testing.T) {
	for _, text := range e.tg.unasked(t) {
		t.Errorf("a message without buttons went out, an alert or a notice:\n%s", redact(text))
	}
	if len(e.reasons) == 0 {
		t.Fatal("no case sent claimed text; the search does not test")
	}
	claimed := e.claimedTexts()
	for i, call := range e.tg.otherCalls() {
		if c := firstOf(call, claimed); c != "" {
			t.Errorf("call %d to Telegram, which is not the message of a request, holds the claimed text %q: %s",
				i, c, redact(call))
		}
	}
	for _, p := range e.procs.all() {
		if !strings.HasPrefix(p.name, "nodkey ") {
			continue // ssh and git print what the person ran
		}
		outputs := map[string]string{"stderr": p.stderr.text()}
		if p.name != "nodkey run" { // its stdout is the command's
			outputs["stdout"] = p.stdout.text()
		}
		for which, text := range outputs {
			if c := firstOf(text, claimed); c != "" {
				t.Errorf("the %s of %s holds the claimed text %q", which, p.name, c)
			}
		}
	}
}

// searchCanaries is the canary search of DESIGN.md section 17. It looks
// at every log (the broker's journal, nodkey ssh-agent, the sshd of the
// targets), the audit log, every call to the fake Telegram server, and
// every output of a client: nodkey run, nodkey ssh-grant, ssh, git,
// nodkey keygen and nodkey audit verify.
//
// The first canary, the secret value, must be nowhere, in no form, not
// even a part of it. Neither may the made-up bot token or the token of
// the store. The second canary sat in the command line of the wrapper, a
// parent of ssh. That is claimed text: DESIGN.md section 7 shows it only
// in the message and in the audit log (the command and message fields),
// always masked. So it must be nowhere either, and its masked form must
// be in each message and audit entry of a login through the wrapper.
// searchClaimed checks that the logs hold no claimed text at all.
//
// The search finds nothing only if there was something to find: a guard
// checks that the broker handed out the secret, and that SSH logins went
// through the wrapper, so that a -run filter cannot make it pass empty.
func (e *env) searchCanaries(t *testing.T) {
	entries := e.audit.entries(t)
	if !slices.ContainsFunc(entries, func(en entry) bool {
		return en.field("event") == "secret_sent" && en.field("secrets") == secretName
	}) {
		t.Error("the broker handed out no secret (no secret_sent entry); the search of the first canary does not test")
	}
	texts := map[string]string{
		"the audit log":              string(readFile(t, e.auditPath)),
		"the log of the SSH targets": e.targets.logs(t),
	}
	for i, p := range e.procs.all() {
		texts["stdout of "+p.name+" #"+strconv.Itoa(i)] = p.stdout.text()
		texts["stderr of "+p.name+" #"+strconv.Itoa(i)] = p.stderr.text()
	}
	for i, b := range e.tg.bodies() {
		texts["call "+strconv.Itoa(i)+" to Telegram"] = b
	}
	for i, s := range e.tg.shownTexts(t) {
		texts["message text "+strconv.Itoa(i)] = s
	}
	_, botSecret, _ := strings.Cut(e.tg.token, ":")
	forms := secretForms(e.canary1)
	forms = append(forms, formsOf("the bot token", e.tg.token)...)
	forms = append(forms, formsOf("the secret part of the bot token", botSecret)...)
	forms = append(forms, formsOf("the token of the store", e.bwsToken)...)
	for where, text := range texts {
		if names := found(text, forms); len(names) > 0 {
			t.Errorf("%s holds %q", where, names)
		}
		if strings.Contains(asciiLower(text), asciiLower(e.canary2)) {
			t.Errorf("%s holds the second canary (from the command line of a parent of ssh)", where)
		}
	}

	// Where the masked second canary is. Every SSH login of the test went
	// through the wrapper.
	logins := 0
	for _, s := range e.tg.shownTexts(t) {
		if strings.HasPrefix(s, "🔐 SSH login") {
			logins++
			if !strings.Contains(s, wrapperShown) {
				t.Errorf("a message of an SSH login does not show the masked command line of the wrapper:\n%s", redact(s))
			}
		}
	}
	if logins == 0 {
		t.Error("no message of an SSH login; the search of the second canary does not test")
	}
	for _, en := range entries {
		if en.field("kind") == "ssh_login" && !strings.Contains(en.field("command"), wrapperShown) {
			t.Errorf("the %s entry of the request %s does not have the masked command line of the wrapper",
				en.name(), en.field("request_id"))
		}
	}
}
