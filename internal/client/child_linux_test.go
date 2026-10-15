package client

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/transport"
)

// These tests run nodkey run in a child process, with the real execve and
// the real signals. The child is the test binary again: with the
// variables childAddr, childPin and childKey it runs as nodkey run, with
// the broker of the test, and with childAgent too, as nodkey ssh-agent
// (childSSHAgent). The command that it starts is the test binary too,
// with the first argument helperArg (see helper), or a program such as
// cat.

// The variables of a child that runs as nodkey run.
const (
	childAddr = "NODKEY_TEST_CHILD_BROKER"     // the broker's address
	childPin  = "NODKEY_TEST_CHILD_BROKER_PIN" // the pin of the broker's key
	childKey  = "NODKEY_TEST_CHILD_KEY"        // the client's key file
)

// helperArg is the first argument of the test binary when it runs as the
// command that nodkey run starts.
const helperArg = "nodkey-test-helper"

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == helperArg {
		os.Exit(helper(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == agentClientArg {
		os.Exit(agentClient(os.Args[2:]))
	}
	if os.Getenv(childAgent) != "" {
		os.Exit(childSSHAgent(os.Args[1:]))
	}
	if os.Getenv(childAddr) != "" {
		os.Exit(childRun(os.Args[1:]))
	}
	os.Exit(m.Run())
}

// childLoad takes the place of Load in a child: it reads the key file and
// the broker of the test. Load would refuse the system temporary
// directory, which everyone can write to.
func childLoad(string) (*Broker, error) {
	pin, err := config.ParsePin(os.Getenv(childPin))
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(os.Getenv(childKey)) //nolint:gosec // G703: the test wrote this key file, and passes its path.
	if err != nil {
		return nil, err
	}
	key, err := transport.ParseKeyFile(data)
	if err != nil {
		return nil, err
	}
	return newBroker(os.Getenv(childAddr), key, pin)
}

// childRun runs nodkey run as Run does, with the real signals and the real
// execve, but with the key file and the broker of the test (childLoad).
func childRun(args []string) int {
	r := runner{
		load:        childLoad,
		configPath:  func() (string, error) { return "test", nil },
		environ:     os.Environ,
		exec:        checkedExec,
		notDumpable: notDumpable,
	}
	return r.main(args, os.Stderr) //nolint:forbidigo // the child is nodkey run, which writes to stderr.
}

// checkedExec is syscall.Exec, after it checked that nodkey holds the
// values as a process that is not dumpable (TestRunNotDumpable). If it is
// dumpable, the command does not start, and nodkey run exits with 126.
func checkedExec(path string, argv, envv []string) error {
	if d := dumpable(); d != 0 {
		return fmt.Errorf("test: nodkey is dumpable (%d) before execve", d)
	}
	return syscall.Exec(path, argv, envv) //nolint:gosec // G204: the command that nodkey run would start.
}

// dumpable returns the dumpable flag of the process (prctl
// PR_GET_DUMPABLE): 0, 1 or 2.
func dumpable() int {
	d, _, _ := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0)
	return int(d)
}

// helper is the command that nodkey run starts in these tests. Its
// arguments are steps:
//
//   - "env VAR SUM": VAR is in the environment exactly once, and the
//     SHA-256 of its value in hex is SUM. It prints "env ok VAR", or "env
//     wrong VAR", never the value.
//   - "dumpable": print "dumpable N", the dumpable flag of the command.
//   - "exit N": exit with N, when every step before passed.
func helper(args []string) int {
	stdout := os.Stdout //nolint:forbidigo // the helper is the command, which writes to stdout.
	code := 0
	for len(args) > 0 {
		switch {
		case args[0] == "env" && len(args) >= 3:
			name, sum := args[1], args[2]
			var values []string
			for _, kv := range os.Environ() {
				if k, v, ok := strings.Cut(kv, "="); ok && k == name {
					values = append(values, v)
				}
			}
			result := "ok"
			if len(values) != 1 || fmt.Sprintf("%x", sha256.Sum256([]byte(values[0]))) != sum {
				result, code = "wrong", 1
			}
			_, _ = fmt.Fprintf(stdout, "env %s %s\n", result, name)
			args = args[3:]
		case args[0] == "dumpable":
			_, _ = fmt.Fprintf(stdout, "dumpable %d\n", dumpable())
			args = args[1:]
		case args[0] == "exit" && len(args) >= 2:
			n, err := strconv.Atoi(args[1])
			if err != nil {
				return 2
			}
			if code == 0 {
				code = n
			}
			args = args[2:]
		default:
			_, _ = fmt.Fprintf(stdout, "helper: unknown step %q\n", args[0])
			return 2
		}
	}
	return code
}

// child returns the command that runs nodkey run with args in a child
// process, with the broker tb as the client laptop. env is added to the
// environment of the test, without the variables of the same names.
func (tb *testBroker) child(t *testing.T, env []string, args ...string) *exec.Cmd {
	t.Helper()
	keyFile := filepath.Join(t.TempDir(), "client.key")
	if err := os.WriteFile(keyFile, tb.laptop.file, 0o600); err != nil {
		t.Fatal(err)
	}
	env = append(env, childAddr+"="+tb.addr, childPin+"="+tb.key.pin.String(), childKey+"="+keyFile)
	cmd := exec.CommandContext(t.Context(), self(t), args...) //nolint:gosec // G204: the test runs its own binary again.
	cmd.Env = withEnv(os.Environ(), env)
	return cmd
}

// withEnv returns base without the variables of extra and without
// NODKEY_REASON, and then extra.
func withEnv(base, extra []string) []string {
	drop := map[string]bool{reasonVar: true}
	for _, kv := range extra {
		name, _, _ := strings.Cut(kv, "=")
		drop[name] = true
	}
	var out []string
	for _, kv := range base {
		if name, _, _ := strings.Cut(kv, "="); !drop[name] {
			out = append(out, kv)
		}
	}
	return append(out, extra...)
}

// diedOf reports whether err, from exec.Cmd.Wait, says that the process
// ended because of sig.
func diedOf(err error, sig syscall.Signal) bool {
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return false
	}
	ws, ok := exit.Sys().(syscall.WaitStatus)
	return ok && ws.Signaled() && ws.Signal() == sig
}

// runChild runs cmd and returns its stdout, its stderr and its exit code.
func runChild(t *testing.T, cmd *exec.Cmd) (stdout, stderr string, code int) {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		code = exit.ExitCode()
	default:
		t.Fatalf("the child did not run: %v", err)
	}
	return out.String(), errOut.String(), code
}

// TestRunInAChild: the person approves, the command replaces nodkey run
// with the value in its environment, in place of an old variable of the
// same name, and nodkey run exits with the command's exit code. nodkey
// prints only the short code, and nothing after the command started. The
// value never reaches nodkey's output.
func TestRunInAChild(t *testing.T) {
	t.Parallel()
	tb := newTestBroker(t)
	tb.approver.Auto(audit.AnswerApproveOnce)
	value := tb.values["github-token"]
	cmd := tb.child(t, []string{"GH_TOKEN=old", "NODKEY_REASON=publish the release"},
		"--secret", "GH_TOKEN=github-token", "--", self(t), helperArg, "env", "GH_TOKEN", sha256Hex(value),
		"exit", "7")
	stdout, stderr, code := runChild(t, cmd)
	mustNotLeak(t, value, stdout, stderr)
	if code != 7 || stdout != "env ok GH_TOKEN\n" {
		t.Errorf("exit code %d, stdout %q; want 7 and the value in the environment (stderr %q)", code, safe(stdout), safe(stderr))
	}
	prompt := tb.waitAsked(t, 1)[0].Prompt
	if stderr != "nodkey: waiting for approval (request "+prompt.ShortCode+")\n" {
		t.Errorf("stderr = %q; want only the waiting line with the short code %s", safe(stderr), prompt.ShortCode)
	}
	if prompt.Claim.Reason != "publish the release" {
		t.Errorf("the reason is %q", prompt.Claim.Reason)
	}
	if got := eventNames(tb.audit.all()); got != "request decision:approve_once secret_sent" {
		t.Errorf("audit entries: %s", got)
	}
}

// TestRunKeepsSIGPIPE: the command starts with the default handling of
// SIGPIPE: not ignored, not blocked. An ignored signal stays ignored
// after execve, so nodkey run must never ignore it. cat shows the
// signals of its own process (/proc/self/status); a Go program would
// install its own handler first.
func TestRunKeepsSIGPIPE(t *testing.T) {
	t.Parallel()
	cat := needProgram(t, "cat")
	tb := newTestBroker(t)
	tb.approver.Auto(audit.AnswerApproveOnce)
	stdout, stderr, code := runChild(t, tb.child(t, nil, "--secret", "GH_TOKEN=github-token", "--", cat,
		"/proc/self/status"))
	mustNotLeak(t, tb.values["github-token"], stdout, stderr)
	if code != 0 {
		t.Fatalf("exit code %d; stderr %q", code, safe(stderr))
	}
	pipe := uint64(1) << (uint(syscall.SIGPIPE) - 1)
	for _, field := range []string{"SigIgn", "SigBlk"} {
		mask, ok := statusMask(stdout, field)
		if !ok {
			t.Fatalf("no %s line in /proc/self/status", field)
		}
		if mask&pipe != 0 {
			t.Errorf("%s of the command has SIGPIPE (%s: %016x)", field, field, mask)
		}
	}
}

// needProgram returns the path of the program name. Without it, the test
// is skipped, or fails when CI is set: CI must have it.
func needProgram(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("%s is not installed", name)
		}
		t.Skipf("%s is not installed", name)
	}
	return path
}

// needSIGINT skips the test, or fails it when CI is set, when the test
// runs with SIGINT ignored: a child keeps it ignored, as a job in the
// background of a shell does, and nodkey run then ignores it too.
func needSIGINT(t *testing.T) {
	t.Helper()
	if signal.Ignored(syscall.SIGINT) {
		if os.Getenv("CI") != "" {
			t.Fatal("the test runs with SIGINT ignored")
		}
		t.Skip("the test runs with SIGINT ignored")
	}
}

// TestRunInheritedSIGPIPE: the shell of the agent ignores SIGPIPE
// (trap ” PIPE) before it starts nodkey run. The command still starts
// with the default handling of SIGPIPE: Go installs its own handler in
// nodkey, which execve resets, and nodkey never ignores SIGPIPE. (From
// the security review of issue #12.)
func TestRunInheritedSIGPIPE(t *testing.T) {
	t.Parallel()
	cat, sh := needProgram(t, "cat"), needProgram(t, "sh")
	pipe := uint64(1) << (uint(syscall.SIGPIPE) - 1)
	// The trap works: without nodkey, cat starts with SIGPIPE ignored.
	plain := exec.CommandContext(t.Context(), sh, "-c", `trap '' PIPE; exec "$0" "$@"`, cat, "/proc/self/status") //nolint:gosec // G204: cat through sh, as the shell of an agent would start it.
	if stdout, _, code := runChild(t, plain); code != 0 {
		t.Fatalf("sh: exit code %d", code)
	} else if mask, ok := statusMask(stdout, "SigIgn"); !ok || mask&pipe == 0 {
		t.Fatalf("the trap does not ignore SIGPIPE (SigIgn %016x)", mask)
	}
	tb := newTestBroker(t)
	tb.approver.Auto(audit.AnswerApproveOnce)
	inner := tb.child(t, nil, "--secret", "GH_TOKEN=github-token", "--", cat, "/proc/self/status")
	cmd := exec.CommandContext(t.Context(), sh, append([]string{"-c", `trap '' PIPE; exec "$0" "$@"`}, inner.Args...)...) //nolint:gosec // G204: the test runs its own binary again, through sh.
	cmd.Env = inner.Env
	stdout, stderr, code := runChild(t, cmd)
	mustNotLeak(t, tb.values["github-token"], stdout, stderr)
	if code != 0 {
		t.Fatalf("exit code %d, stderr %q", code, safe(stderr))
	}
	mask, ok := statusMask(stdout, "SigIgn")
	if !ok || mask&pipe != 0 {
		t.Errorf("the command starts with SIGPIPE ignored (SigIgn %016x)", mask)
	}
}

// statusMask returns a signal mask of /proc/PID/status, such as SigIgn.
func statusMask(status, field string) (uint64, bool) {
	for line := range strings.Lines(status) {
		if v, ok := strings.CutPrefix(line, field+":"); ok {
			mask, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			return mask, err == nil
		}
	}
	return 0, false
}

// TestRunInterrupted: SIGINT or SIGTERM while nodkey run waits. It closes
// the connection, so the broker cancels the request, prints its last line
// with the status that a shell shows (130 or 143), and then ends with the
// same signal. The command does not start.
func TestRunInterrupted(t *testing.T) {
	t.Parallel()
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			t.Parallel()
			if sig == syscall.SIGINT {
				needSIGINT(t)
			}
			tb := newTestBroker(t)
			cmd := tb.child(t, nil, "--secret", "GH_TOKEN=github-token", "--", self(t), helperArg, "exit", "0")
			var stdout bytes.Buffer
			cmd.Stdout = &stdout
			pipe, err := cmd.StderrPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			lines := make(chan string, 16)
			go func() {
				defer close(lines)
				r := bufio.NewReader(pipe)
				for {
					line, err := r.ReadString('\n')
					if line != "" {
						lines <- line
					}
					if err != nil {
						return
					}
				}
			}()
			var stderr strings.Builder
			select {
			case line := <-lines:
				stderr.WriteString(line)
				if len(waitingCodes(line)) != 1 {
					t.Fatalf("the first line is %q, want the waiting line", safe(line))
				}
			case <-time.After(waitLimit):
				t.Fatal("no waiting line")
			}
			// The broker sends the short code just before the message. A
			// signal before the message would end the request without one,
			// and then no message is updated.
			tb.waitAsked(t, 1)
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			for line := range lines {
				stderr.WriteString(line)
			}
			err = cmd.Wait()
			name := map[syscall.Signal]string{syscall.SIGINT: "SIGINT", syscall.SIGTERM: "SIGTERM"}[sig]
			want := fmt.Sprintf("nodkey: cancelled by %s (exit %d)", name, 128+int(sig))
			if !diedOf(err, sig) || lastLine(stderr.String()) != want {
				t.Errorf("%v; stderr %q; want an end by %s and the last line %q", err, safe(stderr.String()), sig, want)
			}
			if stdout.Len() != 0 {
				t.Errorf("the command started: %q", safe(stdout.String()))
			}
			ended, err := tb.approver.WaitEnded(1, waitLimit)
			if err != nil || ended[0].Ending.Cause != audit.CauseCancelled {
				t.Errorf("the broker did not cancel the request: %+v, %v", ended, err)
			}
			if got := eventNames(tb.audit.waitFor(t, 2)); got != "request denied:cancelled" {
				t.Errorf("audit entries: %s", got)
			}
		})
	}
}

// TestRunCannotStart: a file that is not a program, which the person
// approved. execve fails, and nodkey run exits with 126, without the
// value in its output.
func TestRunCannotStart(t *testing.T) {
	t.Parallel()
	bad := filepath.Join(t.TempDir(), "not-a-program")
	if err := os.WriteFile(bad, []byte("this is not a program\n"), 0o700); err != nil { //nolint:gosec // G306: the file must look like a program.
		t.Fatal(err)
	}
	tb := newTestBroker(t)
	tb.approver.Auto(audit.AnswerApproveOnce)
	stdout, stderr, code := runChild(t, tb.child(t, nil, "--secret", "GH_TOKEN=github-token", "--", bad))
	mustNotLeak(t, tb.values["github-token"], stdout, stderr)
	last := lastLine(stderr)
	if code != exitCannotRun || !strings.HasPrefix(last, "nodkey: cannot run ") || !strings.HasSuffix(last, "(exit 126)") {
		t.Errorf("exit code %d, stderr %q; want 126", code, safe(stderr))
	}
	if len(tb.approver.Asked()) == 1 && !strings.Contains(last, "exec format error") {
		// The file system may not let anything run (noexec); then
		// nodkey run stops before it asks.
		t.Errorf("after the approval, the last line is %q; want an exec format error", safe(last))
	}
}

// TestRunInterruptStopsAShellLoop: a bash script runs nodkey run in a
// loop, and the person presses Ctrl-C (SIGINT to the process group) while
// the first request waits. nodkey run ends itself with SIGINT, so bash
// stops the loop too: no second request reaches the phone. (From the
// security review of issue #12: with exit code 77, bash went on.)
func TestRunInterruptStopsAShellLoop(t *testing.T) {
	t.Parallel()
	needSIGINT(t)
	bash := needProgram(t, "bash")
	tb := newTestBroker(t)
	inner := tb.child(t, nil, "--secret", "GH_TOKEN=github-token", "--", self(t), helperArg, "exit", "0")
	script := `for i in 1 2 3; do "$@"; echo "loop $i: exit $?" >&2; done`
	cmd := exec.CommandContext(t.Context(), bash, append([]string{"-c", script, "bash"}, inner.Args...)...) //nolint:gosec // G204: the test runs its own binary again, through bash.
	cmd.Env = inner.Env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) })
	tb.waitAsked(t, 1)
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	second := make(chan struct{})
	go func() {
		if _, err := tb.approver.WaitAsked(2, waitLimit); err == nil {
			close(second)
		}
	}()
	select {
	case err := <-done:
		// bash saw that nodkey died of SIGINT, so it ends with SIGINT too.
		var exit *exec.ExitError
		if !diedOf(err, syscall.SIGINT) && (!errors.As(err, &exit) || exit.ExitCode() != 130) {
			t.Errorf("bash: %v; want an end by SIGINT", err)
		}
	case <-second:
		t.Fatal("after one Ctrl-C, the loop sent a second request to the phone")
	case <-time.After(waitLimit):
		t.Fatal("bash did not end after Ctrl-C")
	}
	if strings.Contains(stderr.String(), "loop 1") || !strings.Contains(stderr.String(),
		"nodkey: cancelled by SIGINT (exit 130)\n") {
		t.Errorf("stderr %q; want nodkey's last line, and no next round of the loop", safe(stderr.String()))
	}
	if n := len(tb.approver.Asked()); n != 1 {
		t.Errorf("%d messages, want 1", n)
	}
}

// TestRunNotDumpable: nodkey run marks itself as not dumpable before it
// asks for the values (prctl PR_SET_DUMPABLE 0). While the request waits,
// another process of the same user cannot read its /proc files. Right
// before execve it is still not dumpable (checkedExec makes it exit with
// 126 otherwise), and execve makes the command dumpable again.
func TestRunNotDumpable(t *testing.T) {
	t.Parallel()
	tb := newTestBroker(t)
	// The helper exits with 5: the race detector pauses for a second when
	// a program exits with 0.
	cmd := tb.child(t, nil, "--secret", "GH_TOKEN=github-token", "--", self(t), helperArg, "dumpable", "exit", "5")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	id := tb.waitAsked(t, 1)[0].Prompt.RequestID
	// nodkey waits for the person now. Only root may read the /proc files
	// of a process that is not dumpable.
	if os.Getuid() != 0 {
		environ := "/proc/" + strconv.Itoa(cmd.Process.Pid) + "/environ"
		if _, err := os.ReadFile(environ); !errors.Is(err, fs.ErrPermission) { //nolint:gosec // G304: the file of the child process.
			t.Errorf("reading %s while nodkey waits: %v; want permission denied", environ, err)
		}
	}
	if err := tb.approver.Tap(id, audit.AnswerApproveOnce); err != nil {
		t.Fatal(err)
	}
	err := cmd.Wait()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 5 {
		t.Fatalf("%v; stderr %q; want the exit code 5 of the command", err, safe(stderr.String()))
	}
	if stdout.String() != "dumpable 1\n" {
		t.Errorf("the command prints %q, want \"dumpable 1\"", safe(stdout.String()))
	}
	mustNotLeak(t, tb.values["github-token"], stdout.String(), stderr.String())
}

// TestRunProgramLinkChanges shows a behaviour that DESIGN.md accepts
// (section 5, step 1): the program is a symbolic link, and the message
// shows the link. The kernel follows the link at execve, so when the link
// changes while the request waits, its new target runs. Whoever can change
// the link, its directory or the file already controls that program.
// (From the second security review of issue #12.)
func TestRunProgramLinkChanges(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	for path, text := range map[string]string{a: "A", b: "B"} {
		if err := os.WriteFile(path, []byte("#!/bin/sh\necho "+text+"\n"), 0o700); err != nil { //nolint:gosec // G306: the file must look like a program.
			t.Fatal(err)
		}
	}
	gh := filepath.Join(dir, "gh")
	if err := os.Symlink(a, gh); err != nil {
		t.Fatal(err)
	}
	tb := newTestBroker(t)
	cmd := tb.child(t, nil, "--secret", "GH_TOKEN=github-token", "--", gh)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := tb.waitAsked(t, 1)[0].Prompt
	if !strings.HasSuffix(p.Claim.Command, "/gh") {
		t.Errorf("the message shows the command %q; want the link %s", p.Claim.Command, gh)
	}
	if err := os.Symlink(b, gh+".new"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(gh+".new", gh); err != nil {
		t.Fatal(err)
	}
	if err := tb.approver.Tap(p.RequestID, audit.AnswerApproveOnce); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("%v; stderr %q", err, safe(stderr.String()))
	}
	if got := strings.TrimSpace(stdout.String()); got != "B" {
		t.Errorf("the command printed %q; want B, from the new target of the link", got)
	}
}
