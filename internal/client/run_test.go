package client

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/claim"
)

// waitingLine matches the line that nodkey run prints while it waits.
var waitingLine = regexp.MustCompile(`^nodkey: waiting for approval \(request ([2-9a-hjkmnp-z]{4})\)$`)

// waitingCodes returns the short codes of the waiting lines in stderr.
func waitingCodes(stderr string) []string {
	var codes []string
	for line := range strings.Lines(stderr) {
		if m := waitingLine.FindStringSubmatch(strings.TrimSuffix(line, "\n")); m != nil {
			codes = append(codes, m[1])
		}
	}
	return codes
}

// TestRunApproves: the person approves. nodkey run prints the short code
// of the message once, and nothing else, and starts the command with the
// values in its environment, in place of old variables of the same names.
// The claimed part of the message has the variables, the command line,
// the directory and the reason.
func TestRunApproves(t *testing.T) {
	t.Parallel()
	tb := newTestBroker(t)
	tb.approver.Auto(audit.AnswerApproveOnce)
	fx := &fakeExec{}
	cmd := self(t)
	env := []string{"HOME=/home/dev", "GH_TOKEN=old", "PATH=/usr/bin", "NPM_TOKEN=old", "GH_TOKEN=older",
		"NODKEY_REASON=from the environment"}
	code, stderr := runIn(t.Context(), testRunner(tb.client(t), env, fx),
		"--secret", "GH_TOKEN=github-token", "--secret=NPM_TOKEN=npm-token", "--reason", "publish the release",
		"--", cmd, "release", "create", "v1.2.0")
	if code != exitOK {
		t.Fatalf("exit code %d, want %d; stderr %q", code, exitOK, safe(stderr))
	}
	mustNotLeak(t, tb.values["github-token"], stderr)
	mustNotLeak(t, tb.values["npm-token"], stderr)
	asked := tb.approver.Asked()
	if len(asked) != 1 {
		t.Fatalf("%d messages, want 1", len(asked))
	}
	p := asked[0].Prompt
	if stderr != "nodkey: waiting for approval (request "+p.ShortCode+")\n" {
		t.Errorf("stderr = %q; want only the waiting line with the short code %s", safe(stderr), p.ShortCode)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// The broker masks the directory, which can hide a random-looking part
	// of the path of the checkout, and keeps at most 1000 characters of it
	// (DESIGN.md section 7).
	if p.Claim.Vars != "GH_TOKEN, NPM_TOKEN" || !strings.HasSuffix(p.Claim.Command, " release create v1.2.0") ||
		p.Claim.Dir != claim.Line(claim.Mask(wd), 1000) || p.Claim.Reason != "publish the release" {
		t.Errorf("the claimed part is %+v", p.Claim)
	}
	if !slices.Equal(p.Secrets, []string{"github-token", "npm-token"}) {
		t.Errorf("the message shows the secrets %q", p.Secrets)
	}
	calls := fx.ran()
	if len(calls) != 1 {
		t.Fatalf("%d commands started, want 1", len(calls))
	}
	if calls[0].path != cmd || !slices.Equal(calls[0].argv, []string{cmd, "release", "create", "v1.2.0"}) {
		t.Errorf("started %q with %q", calls[0].path, calls[0].argv)
	}
	want := []string{"HOME=/home/dev", "PATH=/usr/bin", "NODKEY_REASON=from the environment",
		"GH_TOKEN=" + tb.values["github-token"], "NPM_TOKEN=" + tb.values["npm-token"]}
	if !slices.Equal(calls[0].envv, want) {
		// The environment holds the values: show only the names.
		t.Errorf("the command's environment has the variables %q, want %q", names(calls[0].envv), names(want))
	}
	if got := eventNames(tb.audit.all()); got != "request decision:approve_once secret_sent" {
		t.Errorf("audit entries: %s", got)
	}
}

// names returns the names of the variables in env.
func names(env []string) []string {
	out := make([]string, len(env))
	for i, kv := range env {
		out[i], _, _ = strings.Cut(kv, "=")
	}
	return out
}

// TestRunReason: the reason comes from --reason, else from NODKEY_REASON.
// An empty --reason counts too.
func TestRunReason(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
		env  []string
		want string
	}{
		{"option", []string{"--reason", "from the option"}, []string{"NODKEY_REASON=from the environment"},
			"from the option"},
		{"environment", nil, []string{"NODKEY_REASON=from the environment"}, "from the environment"},
		{"empty option", []string{"--reason="}, []string{"NODKEY_REASON=from the environment"}, ""},
		{"none", nil, nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tb := newTestBroker(t)
			tb.approver.Auto(audit.AnswerApproveOnce)
			args := append(slices.Clone(tt.args), "--secret", "GH_TOKEN=github-token", "--", self(t))
			if code, stderr := runIn(t.Context(), testRunner(tb.client(t), tt.env, &fakeExec{}), args...); code != exitOK {
				t.Fatalf("exit code %d; stderr %q", code, safe(stderr))
			}
			if got := tb.waitAsked(t, 1)[0].Prompt.Claim.Reason; got != tt.want {
				t.Errorf("the reason is %q, want %q", got, tt.want)
			}
		})
	}
}

// TestRunDenied: the person taps Deny, so the broker answers 403. nodkey
// run exits with 77 and starts nothing. A new request in the pause after
// the Deny gets 429 from the broker: 77 too, without a waiting line.
func TestRunDenied(t *testing.T) {
	t.Parallel()
	tb := newTestBroker(t)
	tb.approver.Auto(audit.AnswerDeny)
	fx := &fakeExec{}
	r := testRunner(tb.client(t), nil, fx)
	code, stderr := runIn(t.Context(), r, "--secret", "GH_TOKEN=github-token", "--", self(t))
	if code != exitDenied || lastLine(stderr) != "nodkey: denied (exit 77)" {
		t.Errorf("exit code %d, stderr %q; want 77 and the last line %q", code, safe(stderr), "nodkey: denied (exit 77)")
	}
	if len(waitingCodes(stderr)) != 1 {
		t.Errorf("stderr = %q; want one waiting line", safe(stderr))
	}
	code, stderr = runIn(t.Context(), r, "--secret", "GH_TOKEN=github-token", "--", self(t))
	if want := "nodkey: denied by a limit of the broker (exit 77)"; code != exitDenied || stderr != want+"\n" {
		t.Errorf("in the pause after a Deny: exit code %d, stderr %q; want 77 and only %q", code, safe(stderr), want)
	}
	if len(fx.ran()) != 0 || tb.store.fetched() != 0 {
		t.Error("a denied request fetched a value or started the command")
	}
	mustNotLeak(t, tb.values["github-token"], stderr)
}

// TestRunExpired: nobody answers in time. nodkey run exits with 77.
func TestRunExpired(t *testing.T) {
	t.Parallel()
	tb := newTestBroker(t)
	fx := &fakeExec{}
	type result struct {
		code   int
		stderr string
	}
	done := make(chan result, 1)
	go func() {
		code, stderr := runIn(t.Context(), testRunner(tb.client(t), nil, fx),
			"--secret", "GH_TOKEN=github-token", "--", self(t))
		done <- result{code, stderr}
	}()
	tb.waitAsked(t, 1)
	tb.clock.Advance(secretsTimeout)
	res := <-done
	if res.code != exitDenied || lastLine(res.stderr) != "nodkey: denied (exit 77)" {
		t.Errorf("exit code %d, stderr %q", res.code, safe(res.stderr))
	}
	if got := eventNames(tb.audit.waitFor(t, 2)); got != "request denied:expired" {
		t.Errorf("audit entries: %s", got)
	}
	if len(fx.ran()) != 0 {
		t.Error("the command started after the request expired")
	}
}

// TestRunCancel: the person stops nodkey run while it waits (SIGINT or
// SIGTERM end ctx). The connection closes, the broker cancels the
// request, and run returns the status of a command that SIGINT ended,
// 130; main then ends nodkey with SIGINT (TestRunInterrupted).
func TestRunCancel(t *testing.T) {
	t.Parallel()
	tb := newTestBroker(t)
	fx := &fakeExec{}
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	done := make(chan int, 1)
	var stderr string
	go func() {
		var code int
		code, stderr = runIn(ctx, testRunner(tb.client(t), nil, fx), "--secret", "GH_TOKEN=github-token", "--",
			self(t))
		done <- code
	}()
	tb.waitAsked(t, 1)
	cancel(interrupted{sig: syscall.SIGINT})
	if code := <-done; code != 130 || lastLine(stderr) != "nodkey: cancelled by SIGINT (exit 130)" {
		t.Errorf("exit code %d, stderr %q", code, safe(stderr))
	}
	ended, err := tb.approver.WaitEnded(1, waitLimit)
	if err != nil || ended[0].Ending.Cause != audit.CauseCancelled {
		t.Errorf("the broker did not cancel the request: %+v, %v", ended, err)
	}
	if got := eventNames(tb.audit.waitFor(t, 2)); got != "request denied:cancelled" {
		t.Errorf("audit entries: %s", got)
	}
	if len(fx.ran()) != 0 || tb.store.fetched() != 0 {
		t.Error("a cancelled request fetched a value or started the command")
	}
}

// TestRunCancelBeforeExec: a SIGINT that comes with the answer still
// stops the command: nodkey run looks at ctx once more after it stops
// catching signals.
func TestRunCancelBeforeExec(t *testing.T) {
	t.Parallel()
	tb := newTestBroker(t)
	tb.approver.Auto(audit.AnswerApproveOnce)
	fx := &fakeExec{}
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	var stderr strings.Builder
	code := testRunner(tb.client(t), nil, fx).run(ctx, []string{"--secret", "GH_TOKEN=github-token", "--", self(t)},
		&stderr, func() { cancel(interrupted{sig: syscall.SIGTERM}) })
	if code != 143 || lastLine(stderr.String()) != "nodkey: cancelled by SIGTERM (exit 143)" {
		t.Errorf("exit code %d, stderr %q", code, safe(stderr.String()))
	}
	if len(fx.ran()) != 0 {
		t.Error("the command started after a cancel")
	}
	mustNotLeak(t, tb.values["github-token"], stderr.String())
}

// TestRunStoreFails: the broker cannot fetch the value and answers 503.
// nodkey run exits with 69.
func TestRunStoreFails(t *testing.T) {
	t.Parallel()
	tb := newTestBroker(t)
	tb.approver.Auto(audit.AnswerApproveOnce)
	tb.store.fail(errors.New("mem store: a made-up failure"))
	fx := &fakeExec{}
	code, stderr := runIn(t.Context(), testRunner(tb.client(t), nil, fx), "--secret", "GH_TOKEN=github-token", "--",
		self(t))
	if want := "nodkey: the broker answered 503 Service Unavailable; the broker could not finish the request; its journal says why (journalctl -u nodkey) (exit 69)"; code != exitUnavailable ||
		lastLine(stderr) != want {
		t.Errorf("exit code %d, stderr %q; want 69 and the last line %q", code, safe(stderr), want)
	}
	if len(fx.ran()) != 0 {
		t.Error("the command started without its value")
	}
}

// TestRunUnreachable: nodkey run exits with 69 when it cannot reach the
// broker, or when the other side is not the broker of broker_pin. It
// never asks again.
func TestRunUnreachable(t *testing.T) {
	t.Parallel()
	tb := newTestBroker(t)
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
	tests := []struct {
		name string
		b    func(t *testing.T) *Broker
		want string // a part of the last line
	}{
		{"broker down", func(t *testing.T) *Broker {
			addr := closed(t)
			b, err := newBroker(addr, tb.laptop.cert, tb.key.pin)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}, "cannot connect to the broker at 127.0.0.1:"},
		{"another broker key", func(t *testing.T) *Broker {
			b, err := newBroker(tb.addr, tb.laptop.cert, newTLSKey(t).pin)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}, "the broker's TLS key is not the pinned key"},
		{"a client key the broker does not pin", func(t *testing.T) *Broker {
			b, err := newBroker(tb.addr, newTLSKey(t).cert, tb.key.pin)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}, "refused the TLS connection"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fx := &fakeExec{}
			code, stderr := runIn(t.Context(), testRunner(tt.b(t), nil, fx), "--secret", "GH_TOKEN=github-token",
				"--", self(t))
			if code != exitUnavailable || !strings.Contains(lastLine(stderr), tt.want) ||
				!strings.HasSuffix(stderr, "(exit 69)\n") {
				t.Errorf("exit code %d, stderr %q; want 69 and %q", code, safe(stderr), tt.want)
			}
			if len(fx.ran()) != 0 {
				t.Error("the command started")
			}
		})
	}
	if n := len(tb.audit.all()); n != 0 {
		t.Errorf("the broker has %d audit entries; no request should reach it", n)
	}
}

// TestRunDeadline: a broker that does not answer in time. nodkey run
// closes the connection at the deadline, and exits with 69.
func TestRunDeadline(t *testing.T) {
	t.Parallel()
	got, hungUp := make(chan struct{}), make(chan struct{})
	fb := newFakeBroker(t, func(_ http.ResponseWriter, r *http.Request) {
		// net/http sees a hang-up only after the body was read, as the
		// broker reads it.
		_, _ = io.Copy(io.Discard, r.Body)
		close(got)
		<-r.Context().Done()
		close(hungUp)
	})
	fb.b.timeout = 500 * time.Millisecond
	fx := &fakeExec{}
	code, stderr := runIn(t.Context(), testRunner(fb.b, nil, fx), "--secret", "GH_TOKEN=github-token", "--",
		self(t))
	if want := "nodkey: no answer from the broker within 500ms (exit 69)"; code != exitUnavailable ||
		lastLine(stderr) != want {
		t.Errorf("exit code %d, stderr %q; want the last line %q", code, safe(stderr), want)
	}
	// On a busy machine, the request may not reach the broker before the
	// deadline. When it did, the broker sees the connection close.
	select {
	case <-got:
		select {
		case <-hungUp:
		case <-time.After(waitLimit):
			t.Error("the broker did not see the connection close")
		}
	default:
		t.Log("the request did not reach the broker before the deadline")
	}
	if n := fb.requests.Load(); n > 1 || len(fx.ran()) != 0 {
		t.Errorf("%d requests and %d commands; want at most 1 request and no command", n, len(fx.ran()))
	}
}

// TestRunCommandNotFound: nodkey run looks for the command before it asks
// anyone. A command that is not there exits with 127, and one that cannot
// be run with 126, with no request.
func TestRunCommandNotFound(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain-file")
	if err := os.WriteFile(plain, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		command string
		code    int
		want    string // the last line
	}{
		{"nodkey-test-no-such-command-" + strings.ToLower(rand8()), exitNotFound, "not found"},
		{filepath.Join(dir, "missing"), exitNotFound, "not found"},
		{"", exitNotFound, "not found"},
		{plain, exitCannotRun, "permission denied"},
		{dir, exitCannotRun, "is a directory"},
		{filepath.Join(plain, "below"), exitCannotRun, "not a directory"},
	}
	for _, tt := range tests {
		fb := newFakeBroker(t, func(http.ResponseWriter, *http.Request) {
			t.Error("a request reached the broker")
		})
		fx := &fakeExec{}
		code, stderr := runIn(t.Context(), testRunner(fb.b, nil, fx), "--secret", "GH_TOKEN=github-token", "--",
			tt.command)
		last := lastLine(stderr)
		if code != tt.code || !strings.Contains(last, tt.want) || !strings.HasPrefix(last, "nodkey: ") {
			t.Errorf("command %q: exit code %d, stderr %q; want %d and %q", tt.command, code, safe(stderr), tt.code, tt.want)
		}
		if fb.requests.Load() != 0 || len(fx.ran()) != 0 {
			t.Errorf("command %q: a request was sent or a command started", tt.command)
		}
	}
}

// rand8 returns 8 random letters, for names that must not exist.
func rand8() string { return madeUp("x")[len("made-up-x-") : len("made-up-x-")+8] }

// TestRunExecFails: the command cannot start after the approval, such as
// a file that is not a program. nodkey run exits with 126.
func TestRunExecFails(t *testing.T) {
	t.Parallel()
	tb := newTestBroker(t)
	tb.approver.Auto(audit.AnswerApproveOnce)
	fx := &fakeExec{err: syscall.ENOEXEC}
	code, stderr := runIn(t.Context(), testRunner(tb.client(t), nil, fx), "--secret", "GH_TOKEN=github-token", "--",
		self(t))
	if want := "exec format error (exit 126)"; code != exitCannotRun || !strings.HasSuffix(lastLine(stderr), want) {
		t.Errorf("exit code %d, stderr %q; want 126 and %q", code, safe(stderr), want)
	}
	mustNotLeak(t, tb.values["github-token"], stderr)
}

// TestRunLongCommandLine: a command line of 1.9 MiB is replaced with
// "[hidden: too long]" in the request, so the request fits the broker's
// cap of 2 MiB (no 413), and the person decides as usual: a Deny exits
// with 77, an approval starts the whole command line.
func TestRunLongCommandLine(t *testing.T) {
	t.Parallel()
	cmd := self(t)
	argv := []string{cmd}
	for range 19 {
		argv = append(argv, strings.Repeat("a", 100<<10))
	}
	for _, action := range []audit.Answer{audit.AnswerDeny, audit.AnswerApproveOnce} {
		tb := newTestBroker(t)
		tb.approver.Auto(action)
		fx := &fakeExec{}
		args := append([]string{"--secret", "GH_TOKEN=github-token", "--"}, argv...)
		code, stderr := runIn(t.Context(), testRunner(tb.client(t), nil, fx), args...)
		prompt := tb.waitAsked(t, 1)[0].Prompt
		if !strings.Contains(prompt.Claim.Command, tooLong) {
			t.Errorf("%s: the message shows the command %.80q, want %q", action, prompt.Claim.Command, tooLong)
		}
		switch action {
		case audit.AnswerDeny:
			if code != exitDenied || lastLine(stderr) != "nodkey: denied (exit 77)" {
				t.Errorf("deny: exit code %d, stderr %.200q", code, safe(stderr))
			}
		default:
			calls := fx.ran()
			if code != exitOK || len(calls) != 1 || !slices.Equal(calls[0].argv, argv) {
				t.Errorf("approve: exit code %d, stderr %.200q; the command did not start with its whole command line",
					code, safe(stderr))
			}
		}
	}
}

// TestRunShowsTheProgram: the message shows the program as the file that
// nodkey run starts: the absolute path that PATH found. Here that is a
// "gh" in a directory early in PATH, such as node_modules/.bin of a
// package script. The command gets its arguments as they were typed.
func TestRunShowsTheProgram(t *testing.T) { // not parallel: it changes PATH
	bin := filepath.Join(t.TempDir(), "node_modules", ".bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	gh := filepath.Join(bin, "gh")
	if err := os.WriteFile(gh, []byte("#!/bin/sh\n"), 0o700); err != nil { //nolint:gosec // G306: the file must look like a program.
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	tb := newTestBroker(t)
	tb.approver.Auto(audit.AnswerApproveOnce)
	fx := &fakeExec{}
	code, stderr := runIn(t.Context(), testRunner(tb.client(t), nil, fx), "--secret", "GH_TOKEN=github-token",
		"--", "gh", "release", "create", "v1.2.0")
	calls := fx.ran()
	if code != exitOK || len(calls) != 1 {
		t.Fatalf("exit code %d, stderr %q", code, safe(stderr))
	}
	if calls[0].path != gh || !slices.Equal(calls[0].argv, []string{"gh", "release", "create", "v1.2.0"}) {
		t.Errorf("started %q with %q; want %q with the arguments as typed", calls[0].path, calls[0].argv, gh)
	}
	// The broker masks the claimed text, so a random-looking part of the
	// temporary directory may be hidden, but not the end of the path.
	if got := tb.waitAsked(t, 1)[0].Prompt.Claim.Command; !strings.HasPrefix(got, "/") ||
		!strings.HasSuffix(got, "/node_modules/.bin/gh release create v1.2.0") {
		t.Errorf("the message shows the command %q; want the path of the file that runs, %s", got, gh)
	}
}

// TestRunHelp: -h and --help print the usage and exit with 0 only as the
// only argument. With other arguments they are wrong usage, with the last
// line of nodkey: an exit with 0 that runs nothing would look like a
// command that ran.
func TestRunHelp(t *testing.T) {
	t.Parallel()
	for _, arg := range []string{"-h", "--help", "-help", "--h"} {
		code, stderr := runIn(t.Context(), testRunner(nil, nil, &fakeExec{}), arg)
		if code != exitOK || stderr != runUsage {
			t.Errorf("nodkey run %s: exit code %d, stderr %q; want 0 and only the usage", arg, code, safe(stderr))
		}
	}
	for _, args := range [][]string{
		{"--secret", "GH_TOKEN=github-token", "-h", "--", "false"},
		{"-h", "--secret", "GH_TOKEN=github-token", "--", "false"},
		{"--help", "--"},
		{"-h=1"},
	} {
		fx := &fakeExec{}
		code, stderr := runIn(t.Context(), testRunner(nil, nil, fx), args...)
		if last := lastLine(stderr); code != exitUsage || last != `nodkey run: --help must be the only argument; see "nodkey run --help" (exit 64)` {
			t.Errorf("nodkey run %q: exit code %d, last line %q; want 64", args, code, safe(last))
		}
		if len(fx.ran()) != 0 {
			t.Errorf("nodkey run %q: the command started", args)
		}
	}
}

// TestRunNotDumpableFails: when nodkey cannot mark itself as not
// dumpable, it does not ask for the values (69).
func TestRunNotDumpableFails(t *testing.T) {
	t.Parallel()
	fb := newFakeBroker(t, func(http.ResponseWriter, *http.Request) {
		t.Error("a request reached the broker")
	})
	fx := &fakeExec{}
	r := testRunner(fb.b, nil, fx)
	r.notDumpable = func() error { return syscall.EPERM }
	code, stderr := runIn(t.Context(), r, "--secret", "GH_TOKEN=github-token", "--", self(t))
	if want := "nodkey: cannot mark nodkey as not dumpable: operation not permitted (exit 69)"; code != exitUnavailable ||
		lastLine(stderr) != want {
		t.Errorf("exit code %d, stderr %q; want the last line %q", code, safe(stderr), want)
	}
	if fb.requests.Load() != 0 || len(fx.ran()) != 0 {
		t.Error("a request was sent or the command started")
	}
}
