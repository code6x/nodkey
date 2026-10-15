package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// childAgent makes the test binary run as nodkey ssh-agent, with the
// broker of childAddr, childPin and childKey. With the value "stuck", the
// agent's check of each connection writes stuckLine and never returns,
// and the agent waits for its connections a minute when it stops.
const childAgent = "NODKEY_TEST_CHILD_AGENT"

// stuckLine is the line of a "stuck" child when its check of a connection
// starts: then the agent has taken that connection.
const stuckLine = "test: the check of a connection is stuck"

// childSSHAgent runs nodkey ssh-agent as SSHAgent does, with the real
// signals and /proc, but with the key file and the broker of the test
// (childLoad), and without the checks of the directories on the way to
// the socket, which refuse the system temporary directory.
func childSSHAgent(args []string) int {
	stderr := os.Stderr //nolint:forbidigo // the child is nodkey ssh-agent, which writes to stderr.
	r := agentRunner{
		load:       childLoad,
		configPath: func() (string, error) { return "test", nil },
		getenv:     os.Getenv,
		checkDirs:  noDirCheck,
		proc:       procFS{root: procDir},
		peer:       peerCredentials,
	}
	if os.Getenv(childAgent) == "stuck" {
		r.peer = func(*net.UnixConn) (peer, error) {
			_, _ = fmt.Fprintln(stderr, stuckLine)
			select {}
		}
		r.tune = func(a *sshAgent) { a.stopWait = time.Minute }
	}
	return r.main(args, stderr)
}

// agentClientArg is the first argument of the test binary when it runs as
// a client of an agent socket (agentClient).
const agentClientArg = "nodkey-test-agent-client"

// agentClient connects to the agent socket args[0], asks for the keys,
// and prints what came: "keys N", "closed" when the agent closed the
// connection without an answer, or "error: ..." when the client could
// not connect.
func agentClient(args []string) int {
	stdout := os.Stdout //nolint:forbidigo // the helper reports on stdout.
	if len(args) != 1 {
		return 2
	}
	c, err := (&net.Dialer{}).DialContext(context.Background(), "unix", args[0])
	if err != nil {
		_, _ = fmt.Fprintln(stdout, "error: cannot connect:", err)
		return 1
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(waitLimit))
	if err := writeAgentMessage(c, []byte{agentListRequest}); err != nil {
		_, _ = fmt.Fprintln(stdout, "closed")
		return 0
	}
	answer, err := readAgentMessage(c)
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, syscall.ECONNRESET):
		_, _ = fmt.Fprintln(stdout, "closed")
	case err != nil:
		_, _ = fmt.Fprintln(stdout, "error: no answer:", err)
	case answer[0] == agentListAnswer && len(answer) >= 5:
		_, _ = fmt.Fprintf(stdout, "keys %d\n", binary.BigEndian.Uint32(answer[1:5]))
	default:
		_, _ = fmt.Fprintf(stdout, "answer %d\n", answer[0])
	}
	return 0
}

// agentChild returns the command that runs nodkey ssh-agent with args in
// a child process, with the broker sb as the client laptop.
func (sb *sshBroker) agentChild(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	keyFile := filepath.Join(t.TempDir(), "client.key")
	if err := os.WriteFile(keyFile, sb.laptop.file, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), self(t), args...) //nolint:gosec // G204: the test runs its own binary again.
	cmd.Env = withEnv(os.Environ(), []string{childAgent + "=1", childAddr + "=" + sb.addr,
		childPin + "=" + sb.key.pin.String(), childKey + "=" + keyFile})
	return cmd
}

// TestSSHAgentInAChild runs nodkey ssh-agent in a child process, with the
// real signals. It serves ssh until SIGINT or SIGTERM. Then it removes its
// socket, prints its last line with the status that a shell shows, and
// ends with the same signal, as nodkey run does.
func TestSSHAgentInAChild(t *testing.T) {
	t.Parallel()
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			t.Parallel()
			if sig == syscall.SIGINT {
				needSIGINT(t)
			}
			host, _ := newSSHKey(t)
			sb := newSSHBroker(t, map[string]ssh.PublicKey{"web-1": host.PublicKey()})
			path := filepath.Join(shortTempDir(t), "nodkey", socketName)
			cmd := sb.agentChild(t, "--socket", path)
			var stderr syncBuffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				if !waited {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			}()
			waitFor(t, "the agent to listen", func() bool { return strings.Contains(stderr.String(), "listens on") })
			keys, err := listKeys(t, path)
			if err != nil || len(keys) != 1 || keys[0].Comment != "deploy" {
				t.Fatalf("the agent lists %v, %v; stderr %q", keys, err, stderr.String())
			}
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case err = <-done:
				waited = true
			case <-time.After(waitLimit):
				t.Fatal("the agent did not stop")
			}
			if !diedOf(err, sig) {
				t.Errorf("the agent ended with %v; want it to die of %v", err, sig)
			}
			want := "nodkey: stopped by " + map[syscall.Signal]string{syscall.SIGINT: "SIGINT",
				syscall.SIGTERM: "SIGTERM"}[sig] + " (exit " + strconv.Itoa(128+int(sig)) + ")"
			if last := lastLine(stderr.String()); last != want {
				t.Errorf("the last line is %q, want %q", last, want)
			}
			if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the socket is still there: %v", err)
			}
		})
	}
}

// TestSSHAgentSecondSignal: after the first SIGTERM, nodkey ssh-agent no
// longer catches the signal. When it cannot stop, here because a
// connection is stuck and it waits for it, a second SIGTERM ends it at
// once.
func TestSSHAgentSecondSignal(t *testing.T) {
	t.Parallel()
	host, _ := newSSHKey(t)
	sb := newSSHBroker(t, map[string]ssh.PublicKey{"web-1": host.PublicKey()})
	path := filepath.Join(shortTempDir(t), "nodkey", socketName)
	cmd := sb.agentChild(t, "--socket", path)
	cmd.Env = withEnv(cmd.Env, []string{childAgent + "=stuck"})
	var stderr syncBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var waitErr error
	exited := make(chan struct{})
	go func() {
		waitErr = cmd.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-exited
	})
	waitFor(t, "the agent to listen", func() bool { return strings.Contains(stderr.String(), "listens on") })
	// A connection that the agent's check holds. A dial ends when the
	// connection waits in the socket's queue; the agent may not have taken
	// it yet, and a SIGTERM then would drop it. So wait until the agent's
	// check of it has started.
	c, err := (&net.Dialer{}).DialContext(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	waitFor(t, "the agent to take the connection", func() bool { return strings.Contains(stderr.String(), stuckLine) })
	start := time.Now()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	// The first SIGTERM closes the socket: new connections are refused.
	waitFor(t, "the socket to close", func() bool {
		c, err := (&net.Dialer{}).DialContext(t.Context(), "unix", path)
		if err == nil {
			_ = c.Close()
		}
		return err != nil
	})
	// It waits for the stuck connection.
	select {
	case <-exited:
		t.Fatalf("the first SIGTERM ended the agent at once (%v); stderr %q", waitErr, stderr.String())
	case <-time.After(300 * time.Millisecond):
	}
	ended := false
	for !ended && time.Since(start) < waitLimit {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
			ended = true
		case <-time.After(200 * time.Millisecond):
		}
	}
	if !ended {
		t.Fatalf("a second SIGTERM did not end the agent; stderr %q", stderr.String())
	}
	if !diedOf(waitErr, syscall.SIGTERM) {
		t.Errorf("the agent ended with %v; want it to die of SIGTERM", waitErr)
	}
}

// TestSSHAgentSignalWhileStarting: SIGTERM while the agent starts, also
// while it checks a socket that is already there, stops it as a signal
// does: the last line, and the status that a shell shows. (From the
// security review of issue #13: it exited with 1.)
func TestSSHAgentSignalWhileStarting(t *testing.T) {
	t.Parallel()
	for _, stale := range []bool{false, true} {
		path := filepath.Join(shortTempDir(t), "nodkey", socketName)
		if stale {
			if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", path)
			if err != nil {
				t.Fatal(err)
			}
			ul, ok := ln.(*net.UnixListener)
			if !ok {
				t.Fatal("not a Unix listener")
			}
			ul.SetUnlinkOnClose(false)
			_ = ul.Close()
		}
		ctx, cancel := context.WithCancelCause(context.Background())
		cancel(interrupted{sig: syscall.SIGTERM})
		var stderr syncBuffer
		fb := newFakeSSHBroker(t, nil, nil)
		code := testAgentRunner(fb.b, "").run(ctx, []string{"--socket", path}, &stderr)
		if last := lastLine(stderr.String()); code != 128+int(syscall.SIGTERM) ||
			last != "nodkey: stopped by SIGTERM (exit 143)" {
			t.Errorf("a stale socket %v: exit code %d, stderr %q", stale, code, stderr.String())
		}
	}
}

// connectAs runs the test binary as a client of the agent socket
// (agentClient), as the user of cred, or as the user of the test when cred
// is nil, and returns what it printed. For another user, the binary is
// copied to a directory that everyone can read, and the socket and its
// directories are opened to everyone, so that only the agent's own check
// of the user (SO_PEERCRED) can refuse the connection.
func connectAs(t *testing.T, socket string, cred *syscall.Credential) string {
	t.Helper()
	bin := self(t)
	if cred != nil {
		dir, err := os.MkdirTemp("", "nodkey-bin-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		data, err := os.ReadFile(bin) //nolint:gosec // G304: the test binary itself, to copy it.
		if err != nil {
			t.Fatal(err)
		}
		bin = filepath.Join(dir, "client.test")
		if err := os.WriteFile(bin, data, 0o755); err != nil { //nolint:gosec // G306: another user runs this copy of the test binary.
			t.Fatal(err)
		}
		for _, p := range []struct {
			path string
			mode os.FileMode
		}{{dir, 0o755}, {bin, 0o755}, {filepath.Dir(filepath.Dir(socket)), 0o711}, {filepath.Dir(socket), 0o711},
			{socket, 0o666}} {
			if err := os.Chmod(p.path, p.mode); err != nil {
				t.Fatal(err)
			}
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), waitLimit)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, agentClientArg, socket) //nolint:gosec // G204: the test runs its own binary again.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	if cred != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("the client: %v; it printed %q", err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestAgentServesAChildOfTheUser: a process of the same user, in a child
// process, connects and gets the keys. (The check of connectAs for
// TestAgentRefusesAnotherRealUser.)
func TestAgentServesAChildOfTheUser(t *testing.T) {
	t.Parallel()
	deploy, _ := newSSHKey(t)
	fb := newFakeSSHBroker(t, map[string]ssh.PublicKey{"deploy": deploy.PublicKey()}, nil)
	au := startAgent(t, fb.b, agentOptions{})
	if got := connectAs(t, au.socket, nil); got != "keys 1" {
		t.Errorf("the child got %q", got)
	}
}

// TestAgentRefusesAnotherRealUser runs only as root: a child switches to
// another user and connects. The kernel tells the agent who connected
// (SO_PEERCRED), and the agent closes the connection without an answer.
// The socket is open to everyone here, so the check of the user is the
// only thing that refuses. Run it as root, such as in the end-to-end job
// (issue #15).
func TestAgentRefusesAnotherRealUser(t *testing.T) {
	t.Parallel()
	if os.Geteuid() != 0 {
		t.Skip("needs root, to run a child as another user; the end-to-end test runs it")
	}
	deploy, _ := newSSHKey(t)
	fb := newFakeSSHBroker(t, map[string]ssh.PublicKey{"deploy": deploy.PublicKey()}, nil)
	au := startAgent(t, fb.b, agentOptions{})
	const nobody = 65534
	if got := connectAs(t, au.socket, &syscall.Credential{Uid: nobody, Gid: nobody}); got != "closed" {
		t.Errorf("the other user got %q; want the connection closed", got)
	}
	want := fmt.Sprintf("nodkey: refused a connection of user ID %d: only user ID 0 may use this agent", nobody)
	waitFor(t, "the agent's line", func() bool { return strings.Contains(au.log.String(), want) })
	if n := fb.requests.Load(); n != 0 {
		t.Errorf("the broker got %d requests", n)
	}
	// Root itself is served.
	if got := connectAs(t, au.socket, nil); got != "keys 1" {
		t.Errorf("root got %q", got)
	}
}
