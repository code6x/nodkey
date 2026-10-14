package sshauth

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/code6x/nodkey/internal/config"
)

// These tests run the real OpenSSH client, so the session-bind and the
// data to sign come from OpenSSH itself. Some also run the real sshd,
// without root. They skip when ssh or sshd is missing, too old, or cannot
// run here. When the CI environment variable is set, they fail instead:
// CI installs both, so there these tests must run.

// skipOrFail skips the test, or fails it when the CI environment
// variable is set.
func skipOrFail(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("CI") != "" {
		t.Fatalf("CI is set, so this test must run, but: "+format, args...)
	}
	t.Skipf(format, args...)
}

// requireOpenSSH returns the path of the OpenSSH client. It skips the
// test (see skipOrFail) when there is none, or when it is older than
// 8.9, which sends no session-bind.
func requireOpenSSH(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("ssh")
	if err != nil {
		skipOrFail(t, "no ssh program")
	}
	out, err := exec.CommandContext(t.Context(), path, "-V").CombinedOutput() //nolint:gosec // G204: the test runs ssh from PATH.
	if err != nil {
		skipOrFail(t, "ssh -V: %v", err)
	}
	m := regexp.MustCompile(`OpenSSH_(\d+)\.(\d+)`).FindSubmatch(out)
	if m == nil {
		skipOrFail(t, "ssh is not OpenSSH: %q", out)
	}
	major, _ := strconv.Atoi(string(m[1]))
	minor, _ := strconv.Atoi(string(m[2]))
	if major < 8 || major == 8 && minor < 9 {
		skipOrFail(t, "OpenSSH %d.%d sends no session-bind; it needs 8.9 or newer", major, minor)
	}
	return path
}

// shortTempDir returns a new directory with a short path, because a Unix
// socket path must be shorter than about 100 bytes.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "nodkey-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// testAgent is an SSH agent on a Unix socket, as nodkey ssh-agent will
// be. It keeps the session-binds of each connection, and sends each sign
// request through Check and Sign. It records what ssh sent.
type testAgent struct {
	key    Key
	hosts  *config.KnownHosts
	socket string

	mu       sync.Mutex
	replay   [][]byte // if set, the session-binds to send instead of the connection's
	binds    [][]byte // every session-bind, in order
	requests []Request
	logins   []Login
	errs     []error
}

// startTestAgent starts an agent for key in dir.
func startTestAgent(t *testing.T, key Key, hosts *config.KnownHosts, dir string) *testAgent {
	t.Helper()
	a := &testAgent{key: key, hosts: hosts, socket: filepath.Join(dir, "agent.sock")}
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", a.socket)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(30 * time.Second))
				_ = agent.ServeAgent(&agentConn{a: a}, c)
			})
		}
	})
	return a
}

// results returns the sign requests so far, with what Check returned.
func (a *testAgent) results() ([]Request, []Login, []error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.requests, a.logins, a.errs
}

// allBinds returns every session-bind so far.
func (a *testAgent) allBinds() [][]byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.binds
}

// setReplay makes the agent send these session-binds with each request.
func (a *testAgent) setReplay(binds [][]byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.replay = binds
}

// agentConn serves one agent connection. agent.ServeAgent calls it from
// one goroutine.
type agentConn struct {
	a     *testAgent
	binds [][]byte // the session-binds of this connection
}

var errNotSupported = errors.New("not supported by the test agent")

func (c *agentConn) List() ([]*agent.Key, error) {
	pub := c.a.key.PublicKey()
	return []*agent.Key{{Format: pub.Type(), Blob: pub.Marshal(), Comment: "deploy"}}, nil
}

func (c *agentConn) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return c.SignWithFlags(key, data, 0)
}

func (c *agentConn) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	c.a.mu.Lock()
	binds := c.binds
	if c.a.replay != nil {
		binds = c.a.replay
	}
	c.a.mu.Unlock()
	req := Request{Key: key.Marshal(), Data: bytes.Clone(data), Flags: flags, Binds: binds}
	l, err := c.a.key.Check(req, c.a.hosts)
	c.a.mu.Lock()
	c.a.requests = append(c.a.requests, req)
	c.a.logins = append(c.a.logins, l)
	c.a.errs = append(c.a.errs, err)
	c.a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return c.a.key.Sign(l)
}

func (c *agentConn) Extension(name string, contents []byte) ([]byte, error) {
	if name != "session-bind@openssh.com" {
		return nil, agent.ErrExtensionUnsupported
	}
	b := bytes.Clone(contents)
	c.binds = append(c.binds, b)
	c.a.mu.Lock()
	c.a.binds = append(c.a.binds, b)
	c.a.mu.Unlock()
	return nil, nil
}

func (*agentConn) Add(agent.AddedKey) error       { return errNotSupported }
func (*agentConn) Remove(ssh.PublicKey) error     { return errNotSupported }
func (*agentConn) RemoveAll() error               { return errNotSupported }
func (*agentConn) Lock([]byte) error              { return errNotSupported }
func (*agentConn) Unlock([]byte) error            { return errNotSupported }
func (*agentConn) Signers() ([]ssh.Signer, error) { return nil, errNotSupported }

// runSSH runs ssh to addr as user, with the agent at socket, and the
// command "true". ssh knows the host as web-1 with hostKey. opts are more
// ssh options, such as "KexAlgorithms=curve25519-sha256". It returns
// what ssh printed.
func runSSH(t *testing.T, sshPath, socket, addr, user string, hostKey ssh.PublicKey, dir string, opts ...string) ([]byte, error) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	knownHostsFile := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(knownHostsFile, []byte("web-1 "+string(ssh.MarshalAuthorizedKey(hostKey))), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{
		"-F", "/dev/null", // no config file
		"-o", "IdentityFile=" + filepath.Join(dir, "no-such-key"), // no key files, only the agent
		"-o", "UserKnownHostsFile=" + knownHostsFile,
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "HostKeyAlias=web-1",
		"-o", "CheckHostIP=no",
		"-o", "BatchMode=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "UpdateHostKeys=no",
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
		"-o", "ConnectTimeout=10",
		"-o", "LogLevel=DEBUG1",
	}
	for _, o := range opts {
		args = append(args, "-o", o)
	}
	args = append(args, "-p", port, "-l", user, host, "true")
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, sshPath, args...) //nolint:gosec // G204: the test runs ssh from PATH with its own arguments.
	cmd.Env = []string{"SSH_AUTH_SOCK=" + socket, "PATH=" + os.Getenv("PATH"), "HOME=" + dir}
	return cmd.CombinedOutput()
}

// TestOpenSSHClient runs the real OpenSSH client against an in-process
// SSH server, with an agent that sends each sign request through Check
// and Sign. So the session-bind and the data to sign are what OpenSSH
// sends.
func TestOpenSSHClient(t *testing.T) {
	sshPath := requireOpenSSH(t)
	for _, kind := range []keyKind{ed25519Kind, ecdsa256, rsaKind} {
		t.Run(string(kind), func(t *testing.T) {
			dir := shortTempDir(t)
			key := newKey(t, "deploy", kind, 0)
			host := hostSigner(t, ed25519Kind, 1)
			srv := startTestServer(t, host, key.PublicKey())
			hosts := knownHosts(t, map[string]ssh.PublicKey{"web-1": host.PublicKey()})
			a := startTestAgent(t, key, hosts, dir)
			out, err := runSSH(t, sshPath, a.socket, srv.addr, "deploy", host.PublicKey(), dir)
			if err != nil {
				_, _, errs := a.results()
				t.Fatalf("ssh: %v (sign requests: %v)\n%s", err, errs, out)
			}

			// The one session-bind is the server's key exchange: its host
			// key, the session identifier, and its signature.
			binds := a.allBinds()
			if len(binds) != 1 {
				t.Fatalf("ssh sent %d session-binds; want 1", len(binds))
			}
			b, err := parseBind(binds[0])
			if err != nil {
				t.Fatalf("parseBind of OpenSSH's session-bind: %v", err)
			}
			sessions := srv.loginSessions()
			if len(sessions) == 0 || !bytes.Equal(b.sessionID, sessions[0]) {
				t.Error("the session identifier in the session-bind is not the server's")
			}
			if !bytes.Equal(b.hostKey, host.PublicKey().Marshal()) {
				t.Error("the host key in the session-bind is not the server's")
			}
			srv.mu.Lock()
			kexSig := ssh.Marshal(srv.kex[0].sig)
			srv.mu.Unlock()
			if !bytes.Equal(b.signature, kexSig) {
				t.Error("the signature in the session-bind is not the one from the key exchange")
			}
			if b.forwarding {
				t.Error("the session-bind is for forwarding")
			}

			reqs, logins, errs := a.results()
			if len(reqs) != 1 || errs[0] != nil {
				t.Fatalf("%d sign requests, errors %v; want 1 without error", len(reqs), errs)
			}
			l := logins[0]
			if l.Host() != "web-1" || l.RemoteUser() != "deploy" || l.KeyName() != "deploy" || l.c.hostbound {
				t.Errorf("the Login is %v, hostbound %v; want deploy@web-1 with key deploy, publickey", l, l.c.hostbound)
			}
			if kind == rsaKind && reqs[0].Flags == 0 {
				t.Error("OpenSSH asked for an RSA signature without a SHA-2 flag")
			}

			// The same session-bind in a new session of the same host.
			a.setReplay(binds)
			out, err = runSSH(t, sshPath, a.socket, srv.addr, "deploy", host.PublicKey(), dir)
			if err == nil {
				t.Fatalf("ssh with the session-bind of an earlier session worked:\n%s", out)
			}
			_, logins, errs = a.results()
			if len(errs) != 2 || !errors.Is(errs[1], ErrOtherSession) || logins[1] != (Login{}) {
				t.Errorf("the second sign request: %v; want %v", errs, ErrOtherSession)
			}
		})
	}
}

// TestOpenSSHClientRefuses runs the real OpenSSH client in cases that
// Check must refuse.
func TestOpenSSHClientRefuses(t *testing.T) {
	sshPath := requireOpenSSH(t)
	tests := []struct {
		name        string
		user        string
		unknownHost bool     // the broker's known_hosts does not have the server
		toDB1       bool     // the server is db-1, not web-1
		keyHosts    []string // the hosts list of the key
		want        error
	}{
		{name: "unknown host", user: "deploy", unknownHost: true, want: ErrUnknownHost},
		{name: "user name too long", user: strings.Repeat("a", 33), want: ErrUser},
		{name: "a key that lists web-1, and a login to db-1", user: "deploy", toDB1: true,
			keyHosts: []string{"web-1"}, want: ErrHostNotAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := shortTempDir(t)
			key := newKey(t, "deploy", ed25519Kind, 0, tt.keyHosts...)
			web1, db1 := hostSigner(t, ed25519Kind, 1), hostSigner(t, ed25519Kind, 2)
			host := web1
			if tt.toDB1 {
				host = db1
			}
			srv := startTestServer(t, host, key.PublicKey())
			known := map[string]ssh.PublicKey{"db-1": db1.PublicKey()}
			if !tt.unknownHost {
				known["web-1"] = web1.PublicKey()
			}
			a := startTestAgent(t, key, knownHosts(t, known), dir)
			out, err := runSSH(t, sshPath, a.socket, srv.addr, tt.user, host.PublicKey(), dir)
			if err == nil {
				t.Fatalf("ssh worked; want it refused:\n%s", out)
			}
			_, logins, errs := a.results()
			if len(errs) != 1 || !errors.Is(errs[0], tt.want) || logins[0] != (Login{}) {
				t.Fatalf("sign requests: %v; want one refused with %v\n%s", errs, tt.want, out)
			}
		})
	}
}

// requireSSHD returns the path of the OpenSSH server. It skips the test
// (see skipOrFail) when there is none.
func requireSSHD(t *testing.T) string {
	t.Helper()
	if path, err := exec.LookPath("sshd"); err == nil {
		return path
	}
	for _, path := range []string{"/usr/sbin/sshd", "/usr/local/sbin/sshd"} {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	skipOrFail(t, "no sshd program")
	return ""
}

// sshUser returns the name of the user who runs the test: sshd without
// root logs in only that user. It skips the test (see skipOrFail) when
// the name does not match the rule for remote users.
func sshUser(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil || !ValidUser(u.Username) {
		skipOrFail(t, "the user name of this test does not match the rule for remote users")
	}
	return u.Username
}

// syncBuffer is a bytes.Buffer that a process can write while a test
// reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// startSSHD starts the real sshd on 127.0.0.1, as the user who runs the
// test. Its host key is test key 1 of hostKind, and userKey is in its
// authorized_keys. extra are more lines for its config. It returns the
// address. It skips the test (see skipOrFail) when sshd cannot start.
func startSSHD(t *testing.T, sshdPath, dir string, hostKind keyKind, userKey ssh.PublicKey, extra ...string) string {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(privateKey(t, hostKind, 1), "")
	if err != nil {
		t.Fatal(err)
	}
	hostKeyFile := filepath.Join(dir, "host_key")
	if err := os.WriteFile(hostKeyFile, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	authorizedKeys := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(authorizedKeys, ssh.MarshalAuthorizedKey(userKey), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	_, port, _ := net.SplitHostPort(addr)
	lines := []string{
		"ListenAddress 127.0.0.1",
		"Port " + port,
		"HostKey " + hostKeyFile,
		"AuthorizedKeysFile " + authorizedKeys,
		"PidFile none",
		"StrictModes no",
		"UsePAM no",
		"PasswordAuthentication no",
		"KbdInteractiveAuthentication no",
		"PubkeyAuthentication yes",
		"LogLevel DEBUG1",
	}
	cfg := strings.Join(append(lines, extra...), "\n") + "\n"
	cfgFile := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(cfgFile, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, sshdPath, "-D", "-e", "-f", cfgFile) //nolint:gosec // G204: the test runs sshd with its own config.
	log := &syncBuffer{}
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		cancel()
		skipOrFail(t, "sshd cannot start: %v", err)
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		if t.Failed() {
			t.Logf("sshd log:\n%s", log.String())
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			skipOrFail(t, "sshd stopped at once:\n%s", log.String())
		default:
		}
		c, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", addr)
		if err == nil {
			_ = c.Close()
			return addr
		}
		time.Sleep(50 * time.Millisecond)
	}
	skipOrFail(t, "sshd does not listen after 10 seconds:\n%s", log.String())
	return ""
}

// TestOpenSSHHostbound runs the real OpenSSH client against the real
// sshd, which offers publickey-hostbound-v00@openssh.com. So the data to
// sign is real hostbound data, with the host key in it.
func TestOpenSSHHostbound(t *testing.T) {
	sshPath, sshdPath, name := requireOpenSSH(t), requireSSHD(t), sshUser(t)
	dir := shortTempDir(t)
	key := newKey(t, "deploy", ed25519Kind, 0)
	host := hostSigner(t, ed25519Kind, 1)
	other := hostSigner(t, ed25519Kind, 2)
	hosts := knownHosts(t, map[string]ssh.PublicKey{"web-1": host.PublicKey(), "db-1": other.PublicKey()})
	addr := startSSHD(t, sshdPath, dir, ed25519Kind, key.PublicKey())
	a := startTestAgent(t, key, hosts, dir)
	out, err := runSSH(t, sshPath, a.socket, addr, name, host.PublicKey(), dir)
	reqs, logins, errs := a.results()
	if len(reqs) == 0 {
		// sshd did not even accept the key, so the cause is not this
		// package: for example a locked account.
		skipOrFail(t, "ssh made no sign request (%v):\n%s", err, out)
	}
	if err != nil {
		t.Fatalf("ssh: %v (sign requests: %v)\n%s", err, errs, out)
	}
	if len(reqs) != 1 || errs[0] != nil {
		t.Fatalf("%d sign requests, errors %v; want 1 without error", len(reqs), errs)
	}
	l := logins[0]
	if !l.c.hostbound {
		t.Fatalf("ssh used the publickey method; this test needs publickey-hostbound-v00@openssh.com\n%s", out)
	}
	if l.Host() != "web-1" || l.RemoteUser() != name || l.KeyName() != "deploy" {
		t.Errorf("the Login is %v; want %s@web-1 with key deploy", l, name)
	}

	// The same real data, with one thing changed.
	req := reqs[0]
	b, err := parseBind(req.Binds[0])
	if err != nil {
		t.Fatal(err)
	}
	d, err := parseData(req.Data)
	if err != nil {
		t.Fatal(err)
	}
	change := []struct {
		name string
		req  Request
		want error
	}{
		{
			// A valid bind of this session, but for db-1: the data names
			// web-1's host key.
			name: "a bind of db-1 in this session",
			req:  Request{Key: req.Key, Data: req.Data, Flags: req.Flags, Binds: [][]byte{signBind(t, other, "", b.sessionID, false)}},
			want: ErrOtherHost,
		},
		{
			name: "the data with db-1's host key",
			req: Request{Key: req.Key, Flags: req.Flags, Binds: req.Binds, Data: login{
				sessionID: d.sessionID, msg: msgUserAuthRequest, user: d.user, service: serviceConnection,
				method: methodHostbound, hasSignature: 1, algorithm: d.algorithm, key: d.key,
				hostKey: other.PublicKey().Marshal(),
			}.marshal()},
			want: ErrOtherHost,
		},
		{
			name: "a bind of web-1 in another session",
			req:  Request{Key: req.Key, Data: req.Data, Flags: req.Flags, Binds: [][]byte{signBind(t, host, "", newSessionID(t, len(b.sessionID)), false)}},
			want: ErrOtherSession,
		},
		{
			name: "the bind as a forwarding bind",
			req:  Request{Key: req.Key, Data: req.Data, Flags: req.Flags, Binds: [][]byte{signBind(t, host, "", b.sessionID, true)}},
			want: ErrForwarding,
		},
		{
			name: "a byte after the data",
			req:  Request{Key: req.Key, Data: append(bytes.Clone(req.Data), 0), Flags: req.Flags, Binds: req.Binds},
			want: ErrNotLogin,
		},
	}
	for _, c := range change {
		if l, err := key.Check(c.req, hosts); !errors.Is(err, c.want) || l != (Login{}) {
			t.Errorf("%s: %v; want %v", c.name, err, c.want)
		}
	}
	// The real request still passes.
	if _, err := key.Check(req, hosts); err != nil {
		t.Errorf("the real request: %v", err)
	}
}
