//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// waitLimit bounds every wait of the test for one step: a line of a log, a
// message at the fake Telegram, the end of a command.
const waitLimit = 60 * time.Second

// settleLimit bounds a wait for what a program wrote before it answered
// its client: a line of its log, or an audit entry. When the client has
// its answer, it is there, or on its way through a pipe.
const settleLimit = 10 * time.Second

// proc is a program that the test started, such as nodkey broker, nodkey
// ssh-agent, ssh or git, with its output.
type proc struct {
	name   string
	cmd    *exec.Cmd
	stdout *lineLog
	stderr *lineLog
	done   chan struct{} // closed when the program ended and its output is read
	err    error         // the error of Wait; set before done is closed
}

// procs are the programs of one test, for the canary search: every log and
// every output of a client.
type procs struct {
	mu   sync.Mutex
	list []*proc
}

// start starts argv in the directory dir ("" for the directory of the
// test), with exactly the environment env, and its stdin from stdin (nil
// for none). The program gets a process group of its own: when the test
// ends and it still runs, the test kills it with every process that it
// started, such as ssh under the wrapper. When the test process dies
// without its cleanups, such as after the -timeout of go test or Ctrl-C,
// the kernel kills the program (Pdeathsig).
func (ps *procs) start(t *testing.T, name, dir string, env []string, stdin io.Reader, argv ...string) *proc {
	t.Helper()
	// Not exec.CommandContext with the test's context: that context ends
	// before the cleanups run, and the test stops its long-running
	// programs itself (nodkey broker and nodkey ssh-agent with SIGTERM).
	cmd := exec.CommandContext(context.Background(), argv[0], argv[1:]...) //nolint:gosec // G204: the test runs its own programs.
	p := &proc{name: name, cmd: cmd, stdout: newLineLog(), stderr: newLineLog(), done: make(chan struct{})}
	cmd.Dir, cmd.Env, cmd.Stdin = dir, env, stdin
	cmd.Stdout, cmd.Stderr = p.stdout, p.stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	// A process that the program leaves behind may keep its output open.
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Start(); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	go func() {
		p.err = cmd.Wait()
		p.stdout.close()
		p.stderr.close()
		close(p.done)
	}()
	ps.mu.Lock()
	ps.list = append(ps.list, p)
	ps.mu.Unlock()
	t.Cleanup(func() {
		select {
		case <-p.done:
		default:
			p.kill()
			<-p.done
		}
	})
	return p
}

// kill kills the process group of the program.
func (p *proc) kill() {
	_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
}

// all returns every program so far.
func (ps *procs) all() []*proc {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return slices.Clone(ps.list)
}

// wait waits until the program ends, and returns its exit code, or 128
// and the number of the signal that ended it.
func (p *proc) wait(t *testing.T) int {
	t.Helper()
	select {
	case <-p.done:
	case <-time.After(waitLimit):
		p.kill()
		<-p.done
		t.Fatalf("%s did not end within %s; its output:\n%s", p.name, waitLimit, p.output())
	}
	var exit *exec.ExitError
	switch {
	case p.err == nil:
		return 0
	case errors.As(p.err, &exit):
		if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return exit.ExitCode()
	}
	t.Fatalf("%s: %v", p.name, p.err)
	return -1
}

// mustExit waits until the program ends, and fails unless it exited with
// code.
func (p *proc) mustExit(t *testing.T, code int) {
	t.Helper()
	if got := p.wait(t); got != code {
		t.Fatalf("%s exited with %d, want %d; its output:\n%s", p.name, got, code, p.output())
	}
}

// signal sends sig to the program.
func (p *proc) signal(t *testing.T, sig os.Signal) {
	t.Helper()
	if err := p.cmd.Process.Signal(sig); err != nil {
		t.Fatalf("%s: %v", p.name, err)
	}
}

// output returns what the program wrote so far, for a failure message.
func (p *proc) output() string {
	return redact(fmt.Sprintf("--- stdout of %s:\n%s--- stderr of %s:\n%s", p.name, p.stdout.text(), p.name,
		p.stderr.text()))
}

// lineLog holds the lines of an output as they come. It is the stdout
// or the stderr of a program.
type lineLog struct {
	mu      sync.Mutex
	lines   []string
	partial []byte        // the start of the next line
	done    bool          // the output is closed
	changed chan struct{} // closed and made new on each change
}

func newLineLog() *lineLog { return &lineLog{changed: make(chan struct{})} }

// Write adds the lines of p. The end of p without a newline waits for the
// rest of its line.
func (l *lineLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.partial = append(l.partial, p...)
	for {
		i := bytes.IndexByte(l.partial, '\n')
		if i < 0 {
			break
		}
		l.lines = append(l.lines, string(l.partial[:i]))
		l.partial = l.partial[i+1:]
	}
	l.notifyLocked()
	return len(p), nil
}

// close ends the output. A last line without a newline counts as a line.
func (l *lineLog) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.partial) > 0 {
		l.lines = append(l.lines, string(l.partial))
		l.partial = nil
	}
	l.done = true
	l.notifyLocked()
}

func (l *lineLog) notifyLocked() {
	close(l.changed)
	l.changed = make(chan struct{})
}

// all returns the lines so far.
func (l *lineLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.lines)
}

// text returns the lines so far, each with a newline.
func (l *lineLog) text() string {
	var b strings.Builder
	for _, line := range l.all() {
		b.WriteString(line + "\n")
	}
	return b.String()
}

// has reports whether a line holds s.
func (l *lineLog) has(s string) bool {
	return slices.ContainsFunc(l.all(), func(line string) bool { return strings.Contains(line, s) })
}

// last returns the last line, or "".
func (l *lineLog) last() string {
	lines := l.all()
	if len(lines) == 0 {
		return ""
	}
	return lines[len(lines)-1]
}

// next waits until there are count lines after the first n, and returns
// the lines after the first n. A program writes a line before it answers
// its client, but the line reaches the test through a pipe, so the test
// waits for it. After settleLimit, it returns the lines that came.
func (l *lineLog) next(n, count int) []string {
	deadline := time.NewTimer(settleLimit)
	defer deadline.Stop()
	for {
		l.mu.Lock()
		lines := slices.Clone(l.lines[min(n, len(l.lines)):])
		done, changed := l.done, l.changed
		l.mu.Unlock()
		if len(lines) >= count || done {
			return lines
		}
		select {
		case <-changed:
		case <-deadline.C:
			return lines
		}
	}
}

// count returns the number of lines so far.
func (l *lineLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.lines)
}

// waitOrEnd waits until a line holds s, and reports true, or until the
// output ends without such a line, and reports false. It waits at most
// waitLimit.
func (l *lineLog) waitOrEnd(t *testing.T, what, s string) bool {
	t.Helper()
	return l.waitOrEndWithin(t, what, s, waitLimit)
}

// waitOrEndWithin is waitOrEnd, with the limit limit.
func (l *lineLog) waitOrEndWithin(t *testing.T, what, s string, limit time.Duration) bool {
	t.Helper()
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	for {
		l.mu.Lock()
		found := slices.ContainsFunc(l.lines, func(line string) bool { return strings.Contains(line, s) })
		done, changed := l.done, l.changed
		l.mu.Unlock()
		switch {
		case found:
			return true
		case done:
			return false
		}
		select {
		case <-changed:
		case <-deadline.C:
			t.Fatalf("no line of %s holds %q after %s; it wrote:\n%s", what, s, limit, redact(l.text()))
		}
	}
}

// wait waits until a line holds s. It fails when the output ends without
// such a line.
func (l *lineLog) wait(t *testing.T, what, s string) {
	t.Helper()
	if !l.waitOrEnd(t, what, s) {
		t.Fatalf("%s ended, and no line holds %q; it wrote:\n%s", what, s, redact(l.text()))
	}
}

// settled waits until a line holds s, a line that the program wrote before
// it answered its client. It fails when none comes within settleLimit.
func (l *lineLog) settled(t *testing.T, what, s string) {
	t.Helper()
	if !l.waitOrEndWithin(t, what, s, settleLimit) {
		t.Fatalf("%s ended, and no line holds %q; it wrote:\n%s", what, s, redact(l.text()))
	}
}

// inOrder fails unless lines hold each of parts, in this order.
func (l *lineLog) inOrder(t *testing.T, what string, parts ...string) {
	t.Helper()
	lines := l.all()
	i := 0
	for _, p := range parts {
		for i < len(lines) && !strings.Contains(lines[i], p) {
			i++
		}
		if i == len(lines) {
			t.Errorf("no line of %s holds %q after the lines of %q; it wrote:\n%s", what, p, parts,
				redact(strings.Join(lines, "\n")))
			return
		}
		i++
	}
}
