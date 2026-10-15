package client

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// testAgentRunner returns a runner of nodkey ssh-agent whose broker is b.
// It reads no config file, and its environment has only xdg as
// XDG_RUNTIME_DIR.
func testAgentRunner(b *Broker, xdg string) agentRunner {
	return agentRunner{
		load: func(string) (*Broker, error) {
			if b == nil {
				return nil, errors.New("this test must not connect to a broker")
			}
			return b, nil
		},
		configPath: func() (string, error) { return "/nonexistent/client.toml", nil },
		getenv: func(name string) string {
			if name == "XDG_RUNTIME_DIR" {
				return xdg
			}
			return ""
		},
		checkDirs: noDirCheck,
		proc:      procFS{root: "/nonexistent"},
		peer:      peerCredentials,
	}
}

// TestSSHAgentUsage: wrong usage exits with 64, prints the usage, and
// connects to no broker; -h and --help alone print the usage and exit
// with 0.
func TestSSHAgentUsage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
		xdg  string
		want string // the last line, without "nodkey: " and " (exit 64)"; "" for help
	}{
		{"-h", []string{"-h"}, "", ""},
		{"--help", []string{"--help"}, "", ""},
		{"help with more", []string{"--socket", "/run/a/agent.sock", "-h"}, "", "--help must be the only argument"},
		{"no value", []string{"--socket"}, "", "--socket needs a value"},
		{"an empty value", []string{"--socket="}, "", "--socket needs a path"},
		{"twice", []string{"--socket", "/run/a/b.sock", "-socket=/run/a/c.sock"}, "", "--socket is given twice"},
		{"an unknown option", []string{"--bogus"}, "", `unknown option "--bogus"`},
		{"an argument", []string{"extra"}, "", `unexpected argument "extra"`},
		{"a relative path", []string{"--socket", "agent.sock"}, "", "the socket path must be absolute"},
		{"a path with ..", []string{"--socket", "/run/a/../agent.sock"}, "", "the socket path must be clean"},
		{"a path that is too long", []string{"--socket", "/" + strings.Repeat("a", maxSocketPath) + "/s"}, "",
			"the socket path is longer than 107 bytes"},
		{"no XDG_RUNTIME_DIR", nil, "", "XDG_RUNTIME_DIR is not set, or not an absolute path; give the socket with --socket PATH"},
		{"a relative XDG_RUNTIME_DIR", nil, "run/user/1000", "XDG_RUNTIME_DIR is not set"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stderr syncBuffer
			code := testAgentRunner(nil, tt.xdg).run(t.Context(), tt.args, &stderr)
			out := stderr.String()
			if tt.want == "" {
				if code != exitOK || out != agentUsage {
					t.Errorf("exit code %d, stderr %q; want 0 and the usage", code, out)
				}
				return
			}
			if last := lastLine(out); code != exitUsage || !strings.HasPrefix(out, agentUsage) ||
				!strings.HasPrefix(last, "nodkey: "+tt.want) || !strings.HasSuffix(last, " (exit 64)") {
				t.Errorf("exit code %d, stderr %q; want 64 and %q", code, out, tt.want)
			}
		})
	}
}

// TestSSHAgentStartFails: the agent exits with 69 when the client config
// or the TLS key cannot be read, as nodkey run does, and with 1 when it
// cannot make its socket.
func TestSSHAgentStartFails(t *testing.T) {
	t.Parallel()
	path := filepath.Join(shortTempDir(t), "nodkey", socketName)
	r := testAgentRunner(nil, "")
	r.configPath = func() (string, error) { return "", errors.New("the home directory is not known") }
	var stderr syncBuffer
	if code := r.run(t.Context(), []string{"--socket", path}, &stderr); code != exitUnavailable ||
		stderr.String() != "nodkey: the home directory is not known (exit 69)\n" {
		t.Errorf("without a config path: exit code %d, stderr %q", code, stderr.String())
	}
	r = testAgentRunner(nil, "")
	stderr = syncBuffer{}
	if code := r.run(t.Context(), []string{"--socket", path}, &stderr); code != exitUnavailable ||
		stderr.String() != "nodkey: this test must not connect to a broker (exit 69)\n" {
		t.Errorf("a config that cannot be read: exit code %d, stderr %q", code, stderr.String())
	}
	fb := newFakeSSHBroker(t, nil, nil)
	open := filepath.Join(shortTempDir(t), "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o755); err != nil { //nolint:gosec // G302: the test needs a directory that others can read.
		t.Fatal(err)
	}
	stderr = syncBuffer{}
	code := testAgentRunner(fb.b, "").run(t.Context(), []string{"--socket", filepath.Join(open, socketName)}, &stderr)
	if last := lastLine(stderr.String()); code != exitAgentFailed || !strings.Contains(last, "must have mode 0700") ||
		!strings.HasSuffix(last, "(exit 1)") {
		t.Errorf("a directory with mode 0755: exit code %d, stderr %q", code, stderr.String())
	}
	if fb.requests.Load() != 0 {
		t.Error("the agent asked the broker")
	}
}

// TestSSHAgentRun runs nodkey ssh-agent as SSHAgent does, on the default
// socket: it says where it listens, serves ssh, and on SIGTERM removes the
// socket and prints its last line with the status that a shell shows.
func TestSSHAgentRun(t *testing.T) {
	t.Parallel()
	host, _ := newSSHKey(t)
	sb := newSSHBroker(t, map[string]ssh.PublicKey{"web-1": host.PublicKey()})
	xdg := shortTempDir(t)
	path := filepath.Join(xdg, "nodkey", socketName)
	r := testAgentRunner(sb.client(t), xdg)
	ready := make(chan string, 1)
	r.ready = func(p string) { ready <- p }
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	var stderr syncBuffer
	codes := make(chan int, 1)
	go func() { codes <- r.run(ctx, nil, &stderr) }()
	select {
	case got := <-ready:
		if got != path {
			t.Fatalf("the agent listens on %s, want %s", got, path)
		}
	case <-time.After(waitLimit):
		t.Fatal("the agent does not listen")
	}
	mustMode(t, filepath.Dir(path), fs.ModeDir, 0o700)
	mustMode(t, path, fs.ModeSocket, 0o600)
	au := &agentUnderTest{socket: path, log: &stderr}
	keys, err := au.client(t).List()
	if err != nil || len(keys) != 1 || keys[0].Comment != "deploy" ||
		!slices.Equal(keys[0].Blob, sb.user.PublicKey().Marshal()) {
		t.Fatalf("the agent lists %v, %v", keys, err)
	}
	cancel(interrupted{sig: syscall.SIGTERM})
	select {
	case code := <-codes:
		if code != 128+int(syscall.SIGTERM) {
			t.Errorf("exit code %d, want 143", code)
		}
	case <-time.After(waitLimit):
		t.Fatal("the agent did not stop")
	}
	want := []string{
		"nodkey: the SSH agent listens on " + path + "; set SSH_AUTH_SOCK to this path for ssh",
		"nodkey: stopped by SIGTERM (exit 143)",
	}
	if got := linesOf(stderr.String()); !slices.Equal(got, want) {
		t.Errorf("stderr %q, want %q", got, want)
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the socket is still there: %v", err)
	}
	// A context that ends without a signal: exit code 0. (Another
	// directory: a child that another test forks can hold the lock of the
	// first agent for a moment.)
	r = testAgentRunner(sb.client(t), shortTempDir(t))
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	stderr = syncBuffer{}
	if code := r.run(ctx2, nil, &stderr); code != exitOK || lastLine(stderr.String()) != "nodkey: stopped (exit 0)" {
		t.Errorf("a context that ended: exit code %d, stderr %q", code, stderr.String())
	}
}

// mustMode checks the type and the mode bits of path.
func mustMode(t *testing.T, path string, typ, perm fs.FileMode) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Type() != typ || fi.Mode().Perm() != perm {
		t.Errorf("%s has mode %s; want %s with %04o", path, fi.Mode(), typ, perm)
	}
}

// listKeys lists the keys of the agent at socket, on a new connection.
func listKeys(t *testing.T, socket string) ([]*agent.Key, error) {
	t.Helper()
	au := &agentUnderTest{socket: socket}
	return au.client(t).List()
}
