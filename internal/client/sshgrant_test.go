package client

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/sshauth"
	"github.com/code6x/nodkey/internal/transport"
)

// grantApproved is the last line of nodkey ssh-grant after the approval
// of grantArgs, with the clock of testGranter.
const grantApproved = "nodkey: SSH logins as deploy to 2 hosts allowed until 12:15 (exit 0)"

// TestSSHGrantApproves: the person approves. nodkey ssh-grant prints the
// short code of the message once, then its last line, and exits with 0.
// The message lists the key, the remote user, every host and the end of
// the grants, and only the reason as claimed text. Then the broker signs
// logins with that key as that user to each host key of each listed host
// without a tap, until the end shown in the message. A host that is not in
// the list, another user, another key and another client still ask.
func TestSSHGrantApproves(t *testing.T) {
	t.Parallel()
	gb := newGrantBroker(t)
	gb.approver.Auto(audit.AnswerApproveWindow)
	laptop := gb.client(t, "laptop")
	code, stderr := grantIn(t.Context(), testGranter(laptop, []string{"NODKEY_REASON=from the environment"}),
		grantArgs("--reason", "apply the nginx fix")...)
	p := gb.waitAsked(t, 1)[0].Prompt
	if want := "nodkey: waiting for approval (request " + p.ShortCode + ")\n" + grantApproved + "\n"; code != exitOK ||
		stderr != want {
		t.Fatalf("exit code %d, stderr %q; want 0 and %q", code, stderr, want)
	}
	ends := noon.Add(grantWindow)
	if p.Kind != audit.KindSSHGrant || p.Client != "laptop" || p.Key != "deploy" ||
		!slices.Equal(p.Hosts, []string{"web-1", "web-2"}) || p.RemoteUser != "deploy" || p.HostKey != "" ||
		len(p.Secrets) != 0 || !p.GrantEnds.Equal(ends) {
		t.Errorf("the message shows %+v; want the key deploy, the user deploy, web-1 and web-2, until %v", p, ends)
	}
	if p.Once || p.WindowMinutes != 15 || p.TimeLeft != secretsTimeout {
		t.Errorf("approve once %v, window %d, time left %v; want only Approve and Deny, and %v to answer",
			p.Once, p.WindowMinutes, p.TimeLeft, secretsTimeout)
	}
	if p.Claim != (approval.Claim{Reason: "apply the nginx fix"}) {
		t.Errorf("the claimed part is %+v; want only the reason of --reason", p.Claim)
	}
	if got := gb.lastEvents(); got != "request decision:approve_window" {
		t.Errorf("audit entries: %s", got)
	}

	gb.approver.Auto("")
	// Each host key of each listed host, as deploy, with the key deploy.
	for _, h := range []struct {
		host string
		key  int
	}{{"web-1", 0}, {"web-1", 1}, {"web-2", 0}} {
		if err := gb.sign(t, laptop, "deploy", gb.signRequest(t, "deploy", h.host, h.key, "deploy")); err != nil {
			t.Fatalf("a login to %s with its host key %d: %v", h.host, h.key, err)
		}
		if got := gb.lastEvents(); got != "request grant_used:grant signed" {
			t.Errorf("a login to %s with its host key %d: audit entries %s", h.host, h.key, got)
		}
	}
	if n := len(gb.approver.Asked()); n != 1 {
		t.Errorf("%d messages, want 1: the grants cover these logins", n)
	}
	n := 1
	for _, tt := range []struct {
		name                    string
		client, key, host, user string
	}{
		{"a host that is not in the list", "laptop", "deploy", "db-1", "deploy"},
		{"another remote user", "laptop", "deploy", "web-1", "root"},
		{"another key", "laptop", "web", "web-1", "deploy"},
		{"another client", "ci", "deploy", "web-1", "deploy"},
	} {
		n++
		p := gb.mustAsk(t, gb.client(t, tt.client), gb.signRequest(t, tt.key, tt.host, 0, tt.user), n)
		if p.Kind != audit.KindSSHLogin || p.Client != tt.client || p.Key != tt.key ||
			!slices.Equal(p.Hosts, []string{tt.host}) || p.RemoteUser != tt.user {
			t.Errorf("%s: the message shows %+v", tt.name, p)
		}
	}
	// The grants end at the time in the message.
	gb.clock.Advance(grantWindow - time.Second)
	if err := gb.sign(t, laptop, "deploy", gb.signRequest(t, "deploy", "web-2", 0, "deploy")); err != nil {
		t.Fatalf("a login one second before the grants end: %v", err)
	}
	gb.clock.Advance(time.Second)
	gb.mustAsk(t, laptop, gb.signRequest(t, "deploy", "web-2", 0, "deploy"), n+1)
}

// TestSSHGrantDenied: the person taps Deny. nodkey ssh-grant exits with 77
// after its waiting line, and no grant starts. In the pause after the
// Deny, a second ssh-grant gets 429 from the broker (77 too, without a
// waiting line), and a login with the key is denied without a message.
// After the pause, a login asks.
func TestSSHGrantDenied(t *testing.T) {
	t.Parallel()
	gb := newGrantBroker(t)
	gb.approver.Auto(audit.AnswerDeny)
	laptop := gb.client(t, "laptop")
	g := testGranter(laptop, nil)
	code, stderr := grantIn(t.Context(), g, grantArgs()...)
	if code != exitDenied || lastLine(stderr) != "nodkey: denied (exit 77)" || len(waitingCodes(stderr)) != 1 {
		t.Errorf("exit code %d, stderr %q; want 77, one waiting line, and the last line %q", code, stderr,
			"nodkey: denied (exit 77)")
	}
	if got := gb.lastEvents(); got != "request decision:deny denied:approver" {
		t.Errorf("audit entries: %s", got)
	}
	code, stderr = grantIn(t.Context(), g, grantArgs()...)
	if want := "nodkey: denied by a limit of the broker (exit 77)\n"; code != exitDenied || stderr != want {
		t.Errorf("in the pause after a Deny: exit code %d, stderr %q; want 77 and only %q", code, stderr, want)
	}
	gb.approver.Auto("")
	var e *Error
	if err := gb.sign(t, laptop, "deploy", gb.signRequest(t, "deploy", "web-1", 0, "deploy")); !errors.As(err, &e) ||
		e.Status != http.StatusTooManyRequests {
		t.Errorf("a login in the pause after the Deny: %v; want 429", err)
	}
	gb.clock.Advance(approval.DenyPause)
	gb.mustAsk(t, laptop, gb.signRequest(t, "deploy", "web-1", 0, "deploy"), 2)
}

// TestSSHGrantExpired: nobody answers in time. nodkey ssh-grant exits with
// 77, and no grant starts. A request for grants waits as long as a request
// for secrets, but never past the end of its grants: with --for 1m, one
// minute.
func TestSSHGrantExpired(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		forText string
		wait    time.Duration
	}{
		{"15m", secretsTimeout},
		{"1m", time.Minute},
	} {
		t.Run(tt.forText, func(t *testing.T) {
			t.Parallel()
			gb := newGrantBroker(t)
			laptop := gb.client(t, "laptop")
			type result struct {
				code   int
				stderr string
			}
			done := make(chan result, 1)
			go func() {
				code, stderr := grantIn(t.Context(), testGranter(laptop, nil),
					"--key", "deploy", "--user", "deploy", "--host", "web-1", "--for", tt.forText)
				done <- result{code, stderr}
			}()
			p := gb.waitAsked(t, 1)[0].Prompt
			if p.TimeLeft != tt.wait || !p.GrantEnds.Equal(noon.Add(mustDuration(t, tt.forText))) {
				t.Errorf("time left %v, grants end %v; want %v and %s after noon", p.TimeLeft, p.GrantEnds, tt.wait,
					tt.forText)
			}
			gb.clock.Advance(tt.wait)
			var res result
			select {
			case res = <-done:
			case <-time.After(waitLimit):
				t.Fatal("nodkey ssh-grant did not end")
			}
			if res.code != exitDenied || lastLine(res.stderr) != "nodkey: denied (exit 77)" {
				t.Errorf("exit code %d, stderr %q; want 77", res.code, res.stderr)
			}
			if got := gb.lastEvents(); got != "request denied:expired" {
				t.Errorf("audit entries: %s", got)
			}
			gb.mustAsk(t, laptop, gb.signRequest(t, "deploy", "web-1", 0, "deploy"), 2)
		})
	}
}

// mustDuration parses a duration of a test.
func mustDuration(t testing.TB, s string) time.Duration {
	t.Helper()
	d, err := time.ParseDuration(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestSSHGrantRefusedByTheBroker: the broker refuses, before any message,
// the SSH grants that the client cannot check itself (DESIGN.md section
// 13): a key whose rule is not "window", a time longer than the key's
// window, a host that is not in the broker's known_hosts or not in the
// key's hosts, an unknown key, and a key of another client. nodkey
// ssh-grant exits with 77, without a waiting line, and no grant starts.
func TestSSHGrantRefusedByTheBroker(t *testing.T) {
	t.Parallel()
	gb := newGrantBroker(t)
	gb.approver.Auto(audit.AnswerApproveWindow) // a message would be approved at once
	grant := func(key, forText string, hosts ...string) []string {
		args := []string{"--key", key, "--user", "deploy", "--for", forText}
		for _, h := range hosts {
			args = append(args, "--host", h)
		}
		return args
	}
	for _, tt := range []struct {
		name   string
		client string
		args   []string
	}{
		{"a key whose rule is always", "laptop", grant("admin", "15m", "web-1")},
		{"a key whose rule is never", "ci", grant("backup", "15m", "web-1")},
		{"longer than the key's window", "laptop", grant("deploy", "16m", "web-1")},
		{"a host that is not in known_hosts", "laptop", grant("deploy", "15m", "web-1", "web-9")},
		{"a host that is not in the key's hosts", "laptop", grant("web", "15m", "web-1", "db-1")},
		{"an unknown key", "laptop", grant("nope", "15m", "web-1")},
		{"a key of another client", "ci", grant("web", "15m", "web-1")},
	} {
		code, stderr := grantIn(t.Context(), testGranter(gb.client(t, tt.client), nil), tt.args...)
		if code != exitDenied || stderr != "nodkey: denied (exit 77)\n" {
			t.Errorf("%s: exit code %d, stderr %q; want 77 without a waiting line", tt.name, code, stderr)
		}
		if got := gb.lastEvents(); got != "request denied:not_allowed" {
			t.Errorf("%s: audit entries %s", tt.name, got)
		}
	}
	if n := len(gb.approver.Asked()); n != 0 {
		t.Fatalf("%d messages; the broker must refuse these grants before any message", n)
	}
	gb.approver.Auto("")
	gb.mustAsk(t, gb.client(t, "laptop"), gb.signRequest(t, "deploy", "web-1", 0, "deploy"), 1)
}

// TestSSHGrantBrokerChecksItself: the broker does not rely on the checks of
// nodkey ssh-grant. A hostile client can send any request; these are ones
// that nodkey ssh-grant never sends. The broker refuses each before any
// message: with 403, or with 400 for more than 20 hosts, which is over a
// cap of the API.
func TestSSHGrantBrokerChecksItself(t *testing.T) {
	t.Parallel()
	gb := newGrantBroker(t)
	gb.approver.Auto(audit.AnswerApproveWindow) // a message would be approved at once
	laptop := gb.client(t, "laptop")
	many := make([]string, api.MaxGrantHosts+1)
	for i := range many {
		many[i] = "web-1"
	}
	for _, tt := range []struct {
		name   string
		edit   func(*api.GrantRequest)
		status int
	}{
		{"a remote user with @", func(r *api.GrantRequest) { r.User = "deploy@web-1" }, http.StatusForbidden},
		{"a remote user that starts with -", func(r *api.GrantRequest) { r.User = "-oProxyCommand=x" },
			http.StatusForbidden},
		{"a remote user with 33 characters", func(r *api.GrantRequest) { r.User = "u" + strings.Repeat("x", 32) },
			http.StatusForbidden},
		{"a remote user with a line break", func(r *api.GrantRequest) { r.User = "deploy\nroot" },
			http.StatusForbidden},
		{"no remote user", func(r *api.GrantRequest) { r.User = "" }, http.StatusForbidden},
		{"no host", func(r *api.GrantRequest) { r.Hosts = nil }, http.StatusForbidden},
		{"more than 20 hosts", func(r *api.GrantRequest) { r.Hosts = many }, http.StatusBadRequest},
		{"a host with a port", func(r *api.GrantRequest) { r.Hosts = []string{"web-1:22"} }, http.StatusForbidden},
		{"a host with a wildcard", func(r *api.GrantRequest) { r.Hosts = []string{"web-*"} }, http.StatusForbidden},
		{"a host in another case", func(r *api.GrantRequest) { r.Hosts = []string{"WEB-1"} }, http.StatusForbidden},
		{"under one minute", func(r *api.GrantRequest) { r.Seconds = 59 }, http.StatusForbidden},
		{"no time", func(r *api.GrantRequest) { r.Seconds = 0 }, http.StatusForbidden},
		{"a time below 0", func(r *api.GrantRequest) { r.Seconds = -900 }, http.StatusForbidden},
		{"one second over the window", func(r *api.GrantRequest) { r.Seconds = 15*60 + 1 }, http.StatusForbidden},
		{"a huge time", func(r *api.GrantRequest) { r.Seconds = 1 << 62 }, http.StatusForbidden},
	} {
		req := api.GrantRequest{Key: "deploy", User: "deploy", Hosts: []string{"web-1"}, Seconds: 15 * 60, Reason: "r"}
		tt.edit(&req)
		_, err := Post[api.GrantAnswer](t.Context(), laptop, api.PathSSHGrant, mustJSON(t, req), nil)
		var e *Error
		if !errors.As(err, &e) || e.Status != tt.status {
			t.Errorf("%s: %v; want status %d", tt.name, err, tt.status)
		}
		if got := gb.lastEvents(); got != "request denied:not_allowed" {
			t.Errorf("%s: audit entries %s", tt.name, got)
		}
	}
	if n := len(gb.approver.Asked()); n != 0 {
		t.Errorf("%d messages; the broker must refuse these grants before any message", n)
	}
}

// TestSSHGrantUsage: wrong usage exits with 64, prints the usage, and asks
// no one. The client checks what it can, to give a clear error: the key
// name, the remote user, 1 to 20 hosts that are plain names and each there
// once, and a time in whole minutes of at most 8 hours.
func TestSSHGrantUsage(t *testing.T) {
	t.Parallel()
	base := func(drop string, extra ...string) []string {
		var args []string
		for _, kv := range [][2]string{{"--key", "deploy"}, {"--user", "deploy"}, {"--host", "web-1"}, {"--for", "15m"}} {
			if kv[0] != drop {
				args = append(args, kv[0], kv[1])
			}
		}
		return append(args, extra...)
	}
	var many []string
	for i := range api.MaxGrantHosts + 1 {
		many = append(many, "--host", "web-"+itoa(i))
	}
	tests := []struct {
		name string
		args []string
		want string // a part of the last line
	}{
		{"nothing", nil, "give the key with --key NAME"},
		{"no key", base("--key"), "give the key with --key NAME"},
		{"no user", base("--user"), "give the remote user with --user USER"},
		{"no host", base("--host"), "give at least one host with --host NAME"},
		{"no time", base("--for"), "give the time of the grants with --for DURATION"},
		{"no value", []string{"--key"}, "--key needs a value"},
		{"no value at the end", base("", "--host"), "--host needs a value"},
		{"an empty key", base("--key", "--key="), `--key: the key name "" must be 1 to 64 letters`},
		{"a key with a space", base("--key", "--key", "de ploy"), `the key name "de ploy" must be`},
		{"a key that starts with .", base("--key", "--key", ".deploy"), `the key name ".deploy" must be`},
		{"a key with 65 characters", base("--key", "--key", strings.Repeat("k", 65)), "must be 1 to 64 letters"},
		{"a user with @", base("--user", "--user", "deploy@web-1"),
			`--user: the remote user name "deploy@web-1" must match [A-Za-z0-9._][A-Za-z0-9._-]{0,31}`},
		{"a user that starts with -", base("--user", "--user", "-oProxyCommand=x"), "must match"},
		{"an empty user", base("--user", "--user="), `the remote user name "" must match`},
		{"a user with 33 characters", base("--user", "--user", "u"+strings.Repeat("x", 32)), "must match"},
		{"a user with a line break", base("--user", "--user", "deploy\nroot"), `"deploy\nroot" must match`},
		{"a host with a user", base("", "--host", "deploy@web-2"), `--host: "deploy@web-2" is not a host name`},
		{"a host with a port", base("", "--host", "web-2:22"), `"web-2:22" is not a host name`},
		{"a host in brackets", base("", "--host", "[web-2]:22"), "is not a host name"},
		{"two hosts in one", base("", "--host", "web-2,web-3"), "give each host with its own --host"},
		{"a wildcard", base("", "--host", "*.example.com"), "is not a host name"},
		{"an empty host", base("", "--host="), `"" is not a host name`},
		{"a host that starts with -", base("", "--host", "-web-2"), `"-web-2" is not a host name`},
		{"a host with 65 characters", base("", "--host", strings.Repeat("h", 65)), "is not a host name"},
		{"a host twice", base("", "--host", "web-1"), "--host: the host web-1 is given twice"},
		{"21 hosts", append(base("--host"), many...), "at most 20 --host options"},
		{"0 minutes", base("--for", "--for", "0m"), `--for "0m": give a time in whole minutes, such as 15m or 1h`},
		{"a time below 0", base("--for", "--for", "-15m"), "give a time in whole minutes"},
		{"seconds", base("--for", "--for", "90s"), "give a time in whole minutes"},
		{"part of a minute", base("--for", "--for", "1m30s"), "give a time in whole minutes"},
		{"no unit", base("--for", "--for", "15"), "give a time in whole minutes"},
		{"not a time", base("--for", "--for", "soon"), "give a time in whole minutes"},
		{"too large to read", base("--for", "--for", "9999999999h"), "give a time in whole minutes"},
		{"over 8 hours", base("--for", "--for", "8h1m"),
			`--for "8h1m": the grants can last at most 8 hours, the longest window of a key`},
		{"a key twice", base("", "--key", "web"), "--key is given twice"},
		{"a user twice", base("", "--user", "root"), "--user is given twice"},
		{"a time twice", base("", "--for=15m"), "--for is given twice"},
		{"a reason twice", base("", "--reason", "a", "-reason=b"), "--reason is given twice"},
		{"an unknown option", base("", "--bogus"), `unknown option "--bogus"`},
		{"one dash", base("", "-"), `unknown option "-"`},
		{"two dashes", base("", "--"), `unknown option "--"`},
		{"a host without --host", base("", "web-2"), `unexpected argument "web-2"; put each host after its own --host`},
		{"help with other arguments", base("", "--help"), "--help must be the only argument"},
		{"help with a value", []string{"-h=1"}, "--help must be the only argument"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			code, stderr := grantIn(t.Context(), testGranter(nil, nil), tt.args...)
			if !strings.HasPrefix(stderr, grantUsage) {
				t.Errorf("stderr = %q; want the usage first", stderr)
			}
			if last := lastLine(stderr); code != exitUsage || !strings.HasPrefix(last, "nodkey: ") ||
				!strings.Contains(last, tt.want) || !strings.HasSuffix(last, " (exit 64)") {
				t.Errorf("exit code %d, last line %q; want 64 and %q", code, last, tt.want)
			}
		})
	}
}

// TestSSHGrantHelp: -h and --help print the usage and exit with 0, but only
// as the only argument.
func TestSSHGrantHelp(t *testing.T) {
	t.Parallel()
	for _, arg := range []string{"-h", "--help", "-help", "--h"} {
		code, stderr := grantIn(t.Context(), testGranter(nil, nil), arg)
		if code != exitOK || stderr != grantUsage {
			t.Errorf("nodkey ssh-grant %s: exit code %d, stderr %q; want 0 and only the usage", arg, code, stderr)
		}
	}
}

// TestParseGrantArgs: the forms of the options, as the flag package reads
// them, and the good edges: 20 hosts, the longest names, and the times of
// 1 minute and 8 hours.
func TestParseGrantArgs(t *testing.T) {
	t.Parallel()
	o, err := parseGrantArgs([]string{"-key", "deploy", "--user=deploy", "-host=web-1", "--host", "web-2",
		"-for=1h30m", "-reason=why"})
	if err != nil {
		t.Fatal(err)
	}
	if o.key != "deploy" || o.user != "deploy" || !slices.Equal(o.hosts, []string{"web-1", "web-2"}) ||
		o.duration != 90*time.Minute || o.reason != "why" || !o.reasonSet {
		t.Errorf("parseGrantArgs = %+v", o)
	}
	o, err = parseGrantArgs([]string{"--reason", "--", "--key", "a", "--user", "a", "--host", "a", "--for", "1m"})
	if err != nil || o.reason != "--" || !o.reasonSet || o.duration != time.Minute {
		t.Errorf("a reason that is \"--\" and a time of 1 minute: %+v, %v", o, err)
	}
	if o, err := parseGrantArgs(grantArgs()); err != nil || o.reasonSet {
		t.Errorf("without --reason: %+v, %v", o, err)
	}
	long := func(c string, n int) string { return strings.Repeat(c, n) }
	args := []string{"--key", long("k", 64), "--user", "." + long("u", 31), "--for", "8h"}
	var hosts []string
	for i := range api.MaxGrantHosts {
		h := "h" + itoa(i) + "-" + long("x", 64)
		hosts = append(hosts, h[:64])
		args = append(args, "--host", h[:64])
	}
	o, err = parseGrantArgs(args)
	if err != nil {
		t.Fatalf("20 hosts with the longest names: %v", err)
	}
	if !slices.Equal(o.hosts, hosts) || o.duration != config.MaxWindow {
		t.Errorf("parseGrantArgs = %+v", o)
	}
	req := newGrantRequest(o, long("\x01", api.MaxText))
	if req.Seconds != 8*60*60 {
		t.Errorf("--for 8h is %d seconds", req.Seconds)
	}
	body, err := encodeGrantRequest(req)
	if err != nil || len(body) > transport.MaxRequestBody {
		t.Errorf("the largest request: %d bytes, %v", len(body), err)
	}
	if _, err := encodeGrantRequest(api.GrantRequest{Hosts: append(hosts, "one-more")}); err == nil {
		t.Errorf("encodeGrantRequest took %d hosts", api.MaxGrantHosts+1)
	}
	if one, twenty := grantHostCount(1), grantHostCount(20); one != "1 host" || twenty != "20 hosts" {
		t.Errorf("grantHostCount: %q and %q", one, twenty)
	}
}

// TestGrantNameRule: a key name or a host name passes the client's check
// exactly when it follows the name rule of the broker config, as the
// broker's known_hosts reads it.
func TestGrantNameRule(t *testing.T) {
	t.Parallel()
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(newGrantHostKey(t, false).PublicKey())))
	for _, name := range []string{
		"web-1", "a", "Z", "0", "x.y_z-1", strings.Repeat("a", 64), strings.Repeat("a", 65), ".web", "_web",
		"-web", "web 1", "web-1:22", "web-1,web-2", "*", "web?", "é", "web/1", "deploy@web-1",
	} {
		_, err := config.ParseKnownHosts([]byte(name + " " + key + "\n"))
		if got, want := grantNamePattern.MatchString(name), err == nil; got != want {
			t.Errorf("%q: the client says %v, known_hosts says %v (%v)", name, got, want, err)
		}
	}
	if !sshauth.ValidUser("deploy") || sshauth.ValidUser("deploy@web-1") {
		t.Error("sshauth.ValidUser does not check the remote user")
	}
}

// TestSSHGrantAnswers: only a final 200 whose body passes api.ReadAnswer,
// with 1 to 15 minutes for --for 15m, counts. 403 and 429 exit with 77;
// every other answer, also a redirect, a body that api.ReadAnswer refuses,
// and minutes out of range, with 69. nodkey ssh-grant sends the request
// once, and never prints an answer body, a header, or the number of an
// answer that it refused.
func TestSSHGrantAnswers(t *testing.T) {
	t.Parallel()
	value := madeUp("value")
	const notValid = "the answer of the broker is not valid"
	const outOfRange = "the answer of the broker is not valid: its time is not 1 to 15 minutes"
	tests := []struct {
		name    string
		handler http.HandlerFunc
		code    int
		want    string // the last line, without "nodkey: " and " (exit N)"
	}{
		{"403 with text in the body and a header", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-Note", value)
			_ = transport.WriteJSONBody(w, http.StatusForbidden, []byte(`{"error":"`+value+`"}`))
		}, exitDenied, "denied"},
		{"429", answer(http.StatusTooManyRequests, `{"error":"Too Many Requests"}`), exitDenied,
			"denied by a limit of the broker"},
		{"400", answer(http.StatusBadRequest, `{"error":"Bad Request"}`), exitUnavailable,
			"the broker answered 400 Bad Request"},
		{"404", answer(http.StatusNotFound, `{"error":"Not Found"}`), exitUnavailable,
			"the broker answered 404 Not Found"},
		{"500 with minutes in the body", answer(http.StatusInternalServerError, `{"minutes":15}`), exitUnavailable,
			"the broker answered 500 Internal Server Error"},
		{"503", answer(http.StatusServiceUnavailable, `{"error":"Service Unavailable"}`), exitUnavailable,
			"the broker answered 503 Service Unavailable"},
		{"201 with a valid answer", answer(http.StatusCreated, `{"minutes":15}`), exitUnavailable,
			"the broker answered 201 Created"},
		{"a redirect", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "https://192.0.2.10:7743/v1/ssh-grant")
			w.WriteHeader(http.StatusTemporaryRedirect)
		}, exitUnavailable, "the broker answered 307 Temporary Redirect"},
		{"not JSON", answer(http.StatusOK, "not json "+value), exitUnavailable, notValid},
		{"null", answer(http.StatusOK, "null"), exitUnavailable, notValid},
		{"no minutes", answer(http.StatusOK, `{}`), exitUnavailable, notValid},
		{"minutes null", answer(http.StatusOK, `{"minutes":null}`), exitUnavailable, notValid},
		{"minutes as text", answer(http.StatusOK, `{"minutes":"15"}`), exitUnavailable, notValid},
		{"minutes with a fraction", answer(http.StatusOK, `{"minutes":14.5}`), exitUnavailable, notValid},
		{"minutes with an exponent", answer(http.StatusOK, `{"minutes":1e1}`), exitUnavailable, notValid},
		{"minutes twice", answer(http.StatusOK, `{"minutes":15,"minutes":15}`), exitUnavailable, notValid},
		{"an unknown field", answer(http.StatusOK, `{"minutes":15,"note":"`+value+`"}`), exitUnavailable, notValid},
		{"a field in another case", answer(http.StatusOK, `{"Minutes":15}`), exitUnavailable, notValid},
		{"data after the answer", answer(http.StatusOK, `{"minutes":15}{}`), exitUnavailable, notValid},
		{"larger than api.MaxAnswer", answer(http.StatusOK, `{"minutes":15}`+strings.Repeat(" ", api.MaxAnswer)),
			exitUnavailable, notValid},
		{"0 minutes", answer(http.StatusOK, `{"minutes":0}`), exitUnavailable, outOfRange},
		{"minutes below 0", answer(http.StatusOK, `{"minutes":-15}`), exitUnavailable, outOfRange},
		{"more minutes than --for", answer(http.StatusOK, `{"minutes":16}`), exitUnavailable, outOfRange},
		{"a huge number of minutes", answer(http.StatusOK, `{"minutes":1099511627776}`), exitUnavailable, notValid},
		{"a body shorter than its length", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"minutes":`)
			_ = http.NewResponseController(w).Flush()
			panic(http.ErrAbortHandler) // drop the connection
		}, exitUnavailable, notValid},
		{"a dropped connection", func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) },
			exitUnavailable, "broke before the answer"},
		{"too many informational answers", func(w http.ResponseWriter, _ *http.Request) {
			for range maxInformational + 1 {
				if err := transport.WriteProcessing(w, http.Header{api.ShortCodeHeader: {"7qd2"}}); err != nil {
					return
				}
			}
			_ = transport.WriteJSONBody(w, http.StatusOK, []byte(`{"minutes":15}`))
		}, exitUnavailable, "the broker sent more than 4 informational answers"},
		{"1 minute", answer(http.StatusOK, `{"minutes":1}`), exitOK,
			"SSH logins as deploy to 2 hosts allowed until 12:01"},
		{"15 minutes", answer(http.StatusOK, `{"minutes":15}`), exitOK,
			"SSH logins as deploy to 2 hosts allowed until 12:15"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fb := newFakeBroker(t, tt.handler)
			code, stderr := grantIn(t.Context(), testGranter(fb.b, nil), grantArgs()...)
			last := lastLine(stderr)
			if code != tt.code || !strings.HasPrefix(last, "nodkey: ") || !strings.Contains(last, tt.want) ||
				!strings.HasSuffix(last, " (exit "+itoa(tt.code)+")") {
				t.Errorf("exit code %d, stderr %q; want %d and %q in the last line", code, safe(stderr), tt.code, tt.want)
			}
			if fb.requests.Load() != 1 {
				t.Errorf("the broker got %d requests, want 1", fb.requests.Load())
			}
			mustNotLeak(t, value, stderr)
			if strings.Contains(stderr, "1099511627776") {
				t.Errorf("stderr shows the number of the answer: %q", stderr)
			}
		})
	}
}

// TestSSHGrantShortCode: nodkey ssh-grant prints the short code of the
// first 102 Processing once, and only a code that has the form of a short
// code. It never prints another header, or a code from another status.
func TestSSHGrantShortCode(t *testing.T) {
	t.Parallel()
	value := madeUp("value")
	informational := func(status int, code string) func(http.ResponseWriter) {
		return func(w http.ResponseWriter) {
			w.Header().Set(api.ShortCodeHeader, code)
			w.Header().Set("X-Note", value)
			w.WriteHeader(status)
			w.Header().Del(api.ShortCodeHeader)
			w.Header().Del("X-Note")
		}
	}
	tests := []struct {
		name  string
		first []func(http.ResponseWriter)
		final string // the short code header of the final answer
		want  string
	}{
		{"one", []func(http.ResponseWriter){informational(http.StatusProcessing, "m4k2")}, "", "m4k2"},
		{"two", []func(http.ResponseWriter){
			informational(http.StatusProcessing, "m4k2"), informational(http.StatusProcessing, "k3f9"),
		}, "", "m4k2"},
		{"not a short code first", []func(http.ResponseWriter){
			informational(http.StatusProcessing, "M4K2"), informational(http.StatusProcessing, "k3f9"),
		}, "", "k3f9"},
		{"not a short code", []func(http.ResponseWriter){informational(http.StatusProcessing, value)}, "", ""},
		{"not 102", []func(http.ResponseWriter){informational(http.StatusEarlyHints, "m4k2")}, "", ""},
		{"in the final answer", nil, "m4k2", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fb := newFakeBroker(t, func(w http.ResponseWriter, _ *http.Request) {
				for _, f := range tt.first {
					f(w)
				}
				if tt.final != "" {
					w.Header().Set(api.ShortCodeHeader, tt.final)
				}
				_ = transport.WriteJSONBody(w, http.StatusOK, []byte(`{"minutes":15}`))
			})
			code, stderr := grantIn(t.Context(), testGranter(fb.b, nil), grantArgs()...)
			want := grantApproved + "\n"
			if tt.want != "" {
				want = "nodkey: waiting for approval (request " + tt.want + ")\n" + want
			}
			if code != exitOK || stderr != want {
				t.Errorf("exit code %d, stderr %q; want 0 and %q", code, safe(stderr), want)
			}
			mustNotLeak(t, value, stderr)
		})
	}
}

// TestSSHGrantOutputAsInDesign: the output of nodkey ssh-grant after an
// approval is exactly the example of DESIGN.md section 13: the waiting
// line, and the last line with the end of the grants, the time when the
// request went out plus the minutes of the answer, without the seconds.
func TestSSHGrantOutputAsInDesign(t *testing.T) {
	t.Parallel()
	doc, err := os.ReadFile(filepath.Join("..", "..", "DESIGN.md"))
	if err != nil {
		t.Fatal(err)
	}
	fb := newFakeBroker(t, func(w http.ResponseWriter, _ *http.Request) {
		if err := transport.WriteProcessing(w, http.Header{api.ShortCodeHeader: {"m4k2"}}); err != nil {
			return
		}
		_ = transport.WriteJSONBody(w, http.StatusOK, []byte(`{"minutes":15}`))
	})
	g := testGranter(fb.b, nil)
	g.now = func() time.Time { return time.Date(2026, 10, 14, 14, 5, 12, 0, time.UTC) }
	code, stderr := grantIn(t.Context(), g, grantArgs("--reason", "apply the nginx fix")...)
	if code != exitOK || !strings.Contains(string(doc), "```\n"+stderr+"```") {
		t.Errorf("exit code %d; DESIGN.md section 13 does not show this output:\n%s", code, stderr)
	}
}

// TestSSHGrantRequest: the request is one POST of JSON to /v1/ssh-grant,
// which the broker can read (transport.ReadJSON), with the header
// "Connection: close", so no other request goes on its connection. It has
// the key, the remote user, the hosts in the order of the arguments, --for
// in seconds, and the reason: from --reason, else from NODKEY_REASON. A
// reason over 64 KiB becomes "[hidden: too long]".
func TestSSHGrantRequest(t *testing.T) {
	t.Parallel()
	full := strings.Repeat("r", api.MaxText)
	tests := []struct {
		name   string
		args   []string
		env    []string
		reason string
	}{
		{"option", []string{"--reason", "from the option"}, []string{"NODKEY_REASON=from the environment"},
			"from the option"},
		{"environment", nil, []string{"A=1", "NODKEY_REASON=from the environment", "NODKEY_REASON=second"},
			"from the environment"},
		{"empty option", []string{"--reason="}, []string{"NODKEY_REASON=from the environment"}, ""},
		{"none", nil, nil, ""},
		{"at the limit", []string{"--reason", full}, nil, full},
		{"too long", []string{"--reason", full + "r"}, nil, tooLong},
		{"too long in the environment", nil, []string{"NODKEY_REASON=" + full + "r"}, tooLong},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got *api.GrantRequest
			var header http.Header
			var method string
			fb := newFakeBroker(t, func(w http.ResponseWriter, r *http.Request) {
				method, header = r.Method+" "+r.RequestURI, r.Header.Clone()
				req, err := transport.ReadJSON[api.GrantRequest](w, r)
				if err != nil {
					return
				}
				got = req
				transport.WriteError(w, http.StatusForbidden)
			})
			args := append([]string{"--key", "deploy", "--user", "deploy", "--host", "web-2", "--host", "web-1",
				"--for", "1h"}, tt.args...)
			code, _ := grantIn(t.Context(), testGranter(fb.b, tt.env), args...)
			if code != exitDenied || got == nil {
				t.Fatalf("exit code %d; the broker could not read the request", code)
			}
			want := api.GrantRequest{Key: "deploy", User: "deploy", Hosts: []string{"web-2", "web-1"}, Seconds: 3600,
				Reason: tt.reason}
			if a, b := mustJSON(t, *got), mustJSON(t, want); string(a) != string(b) {
				t.Errorf("the request is %.300s\nwant %.300s", a, b)
			}
			if method != "POST "+api.PathSSHGrant || header.Get("Content-Type") != api.ContentType ||
				header.Get("Connection") != "close" {
				t.Errorf("the request is %s with the headers %v", method, header)
			}
		})
	}
}

// TestSSHGrantCancel: the person stops nodkey ssh-grant while it waits
// (SIGINT or SIGTERM end ctx). The connection closes, the broker cancels
// the request, and run returns 130, the status of a command that SIGINT
// ended; main then ends nodkey with SIGINT (TestSSHGrantInterrupted). No
// grant starts.
func TestSSHGrantCancel(t *testing.T) {
	t.Parallel()
	gb := newGrantBroker(t)
	laptop := gb.client(t, "laptop")
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	done := make(chan int, 1)
	var stderr string
	go func() {
		var code int
		code, stderr = grantIn(ctx, testGranter(laptop, nil), grantArgs()...)
		done <- code
	}()
	p := gb.waitAsked(t, 1)[0].Prompt
	cancel(interrupted{sig: syscall.SIGINT})
	if code := <-done; code != 130 || lastLine(stderr) != "nodkey: cancelled by SIGINT (exit 130)" {
		t.Errorf("exit code %d, stderr %q; want 130", code, stderr)
	}
	ended, err := gb.approver.WaitEnded(1, waitLimit)
	if err != nil || ended[0].Ending.Cause != audit.CauseCancelled {
		t.Errorf("the broker did not cancel the request: %+v, %v", ended, err)
	}
	gb.waitEvents(t, p.RequestID, "request denied:cancelled")
	gb.mustAsk(t, laptop, gb.signRequest(t, "deploy", "web-1", 0, "deploy"), 2)
}

// TestSSHGrantUnreachable: nodkey ssh-grant exits with 69 when it cannot
// read its config, cannot reach the broker, or when the other side is not
// the broker of broker_pin. It never asks again.
func TestSSHGrantUnreachable(t *testing.T) {
	t.Parallel()
	gb := newGrantBroker(t)
	closed := func(t *testing.T) string {
		ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}
		return addr
	}
	granterFor := func(t *testing.T, addr string, key tlsKey, pin config.Pin) granter {
		b, err := newBroker(addr, key.cert, pin)
		if err != nil {
			t.Fatal(err)
		}
		return testGranter(b, nil)
	}
	tests := []struct {
		name string
		g    func(t *testing.T) granter
		want string // a part of the last line
	}{
		{"no config", func(*testing.T) granter {
			g := testGranter(nil, nil)
			g.load = func(path string) (*Broker, error) {
				return nil, errors.New("config " + path + ": made-up error")
			}
			return g
		}, "config /nonexistent/client.toml: made-up error"},
		{"no home", func(*testing.T) granter {
			g := testGranter(nil, nil)
			g.configPath = func() (string, error) { return "", errors.New("the home directory is not known") }
			return g
		}, "the home directory is not known"},
		{"broker down", func(t *testing.T) granter {
			return granterFor(t, closed(t), gb.clients["laptop"], gb.key.pin)
		}, "cannot connect to the broker at 127.0.0.1:"},
		{"another broker key", func(t *testing.T) granter {
			return granterFor(t, gb.addr, gb.clients["laptop"], newTLSKey(t).pin)
		}, "the broker's TLS key is not the pinned key"},
		{"a client key the broker does not pin", func(t *testing.T) granter {
			return granterFor(t, gb.addr, newTLSKey(t), gb.key.pin)
		}, "refused the TLS connection"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			code, stderr := grantIn(t.Context(), tt.g(t), grantArgs()...)
			if code != exitUnavailable || !strings.Contains(lastLine(stderr), tt.want) ||
				!strings.HasSuffix(stderr, "(exit 69)\n") {
				t.Errorf("exit code %d, stderr %q; want 69 and %q", code, stderr, tt.want)
			}
		})
	}
	if n := len(gb.audit.all()); n != 0 {
		t.Errorf("the broker has %d audit entries; no request should reach it", n)
	}
}

// TestSSHGrantDeadline: a broker that does not answer in time. nodkey
// ssh-grant closes the connection at the deadline, and exits with 69.
func TestSSHGrantDeadline(t *testing.T) {
	t.Parallel()
	fb := newFakeBroker(t, func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	})
	fb.b.timeout = 500 * time.Millisecond
	code, stderr := grantIn(t.Context(), testGranter(fb.b, nil), grantArgs()...)
	if want := "nodkey: no answer from the broker within 500ms (exit 69)"; code != exitUnavailable ||
		lastLine(stderr) != want {
		t.Errorf("exit code %d, stderr %q; want the last line %q", code, stderr, want)
	}
	if n := fb.requests.Load(); n > 1 {
		t.Errorf("%d requests, want at most 1", n)
	}
}
