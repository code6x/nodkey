package client

import (
	"bytes"
	"context"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/transport"
)

// These tests run the real OpenSSH ssh and ssh-add with nodkey ssh-agent,
// so the session-bind, the data to sign and the refused requests are what
// OpenSSH sends. Some also run the real sshd, without root. They skip
// when a program is missing, too old, or cannot run here. When the CI
// environment variable is set, they fail instead: CI installs OpenSSH, so
// there these tests must run.

// skipOrFail skips the test, or fails it when the CI environment
// variable is set.
func skipOrFail(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("CI") != "" {
		t.Fatalf("CI is set, so this test must run, but: "+format, args...)
	}
	t.Skipf(format, args...)
}

// requireOpenSSH returns the paths of ssh and ssh-add. It skips the test
// (see skipOrFail) when there are none, or when ssh is older than 8.9,
// which sends no session-bind.
func requireOpenSSH(t *testing.T) (sshPath, addPath string) {
	t.Helper()
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		skipOrFail(t, "no ssh program")
	}
	addPath, err = exec.LookPath("ssh-add")
	if err != nil {
		skipOrFail(t, "no ssh-add program")
	}
	out, err := exec.CommandContext(t.Context(), sshPath, "-V").CombinedOutput()
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
	return sshPath, addPath
}

// sshArgs returns the arguments of ssh for a login to addr as user, with
// only the agent's keys, and "true" as the command. ssh knows the host as
// web-1 with hostKey, from a known_hosts file in dir.
func sshArgs(t *testing.T, addr, user string, hostKey ssh.PublicKey, dir string) []string {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	knownHosts := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("web-1 "+string(ssh.MarshalAuthorizedKey(hostKey))), 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{
		"-F", "/dev/null", // no config file
		"-o", "IdentityFile=" + filepath.Join(dir, "no-such-key"), // no key files, only the agent
		"-o", "UserKnownHostsFile=" + knownHosts,
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
		"-p", port, "-l", user, host, "true",
	}
}

// sshEnv returns the environment of ssh: the agent's socket, and env.
func sshEnv(socket, home string, env ...string) []string {
	return append([]string{"SSH_AUTH_SOCK=" + socket, "PATH=" + os.Getenv("PATH"), "HOME=" + home}, env...)
}

// runSSH runs ssh with args and env, and returns what it printed.
func runSSH(t *testing.T, sshPath string, args, env []string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), waitLimit)
	defer cancel()
	cmd := exec.CommandContext(ctx, sshPath, args...) //nolint:gosec // G204: the test runs ssh from PATH with its own arguments.
	cmd.Env = env
	return cmd.CombinedOutput()
}

// TestOpenSSHLogin logs in with the real ssh through the agent and the
// real broker, to an in-process SSH server. Only a login that the person
// approves works. The message shows the reason from the environment of
// ssh, and the command lines of ssh and its parents.
func TestOpenSSHLogin(t *testing.T) {
	t.Parallel()
	sshPath, _ := requireOpenSSH(t)
	for _, tt := range []struct {
		name   string
		answer audit.Answer // "" lets the request expire
	}{
		{"approved", audit.AnswerApproveOnce},
		{"denied", audit.AnswerDeny},
		{"expired", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			host, _ := newSSHKey(t)
			sb := newSSHBroker(t, map[string]ssh.PublicKey{"web-1": host.PublicKey()})
			srv := startSSHServer(t, host, sb.user.PublicKey())
			au := startAgent(t, sb.client(t), agentOptions{proc: &procFS{root: procDir}})
			sb.approver.Auto(tt.answer)
			dir := shortTempDir(t)
			type result struct {
				out []byte
				err error
			}
			done := make(chan result, 1)
			args := sshArgs(t, srv.addr, "deploy", host.PublicKey(), dir)
			go func() {
				out, err := runSSH(t, sshPath, args, sshEnv(au.socket, dir, "NODKEY_REASON=apply the nginx fix"))
				done <- result{out, err}
			}()
			asked := sb.waitAsked(t, 1)[0]
			if tt.answer == "" {
				sb.clock.Advance(sshTimeout)
			}
			res := <-done
			if tt.answer == audit.AnswerApproveOnce {
				if res.err != nil || srv.loginCount() != 1 {
					t.Fatalf("ssh: %v; agent lines %q\n%s", res.err, au.lines(), res.out)
				}
			} else if res.err == nil || srv.loginCount() != 0 {
				t.Fatalf("ssh logged in: %v\n%s", res.err, res.out)
			}
			p := asked.Prompt
			if p.Key != "deploy" || !slices.Equal(p.Hosts, []string{"web-1"}) || p.RemoteUser != "deploy" {
				t.Errorf("the message shows %+v", p)
			}
			if p.Claim.Reason != "apply the nginx fix" || !strings.HasPrefix(p.Claim.Command, sshPath+" ") ||
				!strings.Contains(p.Claim.Command, " ← ") {
				t.Errorf("the claimed part is %+v", p.Claim)
			}
			lines := au.lines()
			if len(lines) == 0 || lines[0] != "nodkey: waiting for approval (request "+p.ShortCode+")" {
				t.Errorf("the agent wrote %q", lines)
			}
			if tt.answer != audit.AnswerApproveOnce &&
				(len(lines) != 2 || lines[1] != "nodkey: no signature (request "+p.ShortCode+"): denied") {
				t.Errorf("the agent wrote %q", lines)
			}
		})
	}
}

// TestOpenSSHSignRequest: what the agent sends the broker for a login of
// the real ssh, which a shell started: the exact key that the agent
// listed, the data and flags of ssh, the one session-bind of ssh, which
// holds the server's key exchange, the command lines of ssh and of 3 of
// its parents, and NODKEY_REASON from the environment of ssh. Nothing
// else of the environment.
func TestOpenSSHSignRequest(t *testing.T) {
	t.Parallel()
	sshPath, _ := requireOpenSSH(t)
	sh := needProgram(t, "sh")
	host, _ := newSSHKey(t)
	userKey, _ := newSSHKey(t)
	srv := startSSHServer(t, host, userKey.PublicKey())
	bodies := make(chan []byte, 1)
	fb := newFakeBroker(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case api.PathKeys:
			ans := api.KeysAnswer{Keys: []api.Key{{Name: "deploy", PublicKey: userKey.PublicKey().Marshal()}}}
			_ = transport.WriteJSON(w, http.StatusOK, ans)
		case api.PathSign:
			bodies <- readBody(t, r)
			transport.WriteError(w, http.StatusForbidden)
		}
	})
	au := startAgent(t, fb.b, agentOptions{proc: &procFS{root: procDir}})
	dir := shortTempDir(t)
	canary := madeUp("canary")
	args := sshArgs(t, srv.addr, "deploy", host.PublicKey(), dir)
	// The shell stays as the parent of ssh: it has more to do after ssh.
	script := `NODKEY_REASON="from ssh" "$0" "$@"; :`
	ctx, cancel := context.WithTimeout(t.Context(), waitLimit)
	defer cancel()
	cmd := exec.CommandContext(ctx, sh, append([]string{"-c", script, sshPath}, args...)...) //nolint:gosec // G204: the test runs ssh through sh.
	cmd.Env = sshEnv(au.socket, dir, "NODKEY_REASON=from the shell", "SECRET_OF_THE_SHELL="+canary)
	out, err := cmd.CombinedOutput()
	if err != nil || srv.loginCount() != 0 {
		t.Fatalf("sh: %v; %d logins\n%s", err, srv.loginCount(), out)
	}
	var body []byte
	select {
	case body = <-bodies:
	default:
		t.Fatalf("the broker got no sign request; agent lines %q\n%s", au.lines(), out)
	}
	if strings.Contains(string(body), canary) {
		t.Error("the request holds a value from the environment")
	}
	var req api.SignRequest
	if err := req.UnmarshalJSON(body); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(req.PublicKey, userKey.PublicKey().Marshal()) || req.Flags != 0 {
		t.Errorf("the request has another key, or the flags %d", req.Flags)
	}
	binds := srv.binds()
	if len(req.Binds) != 1 || len(binds) != 1 || !bytes.Equal(req.Binds[0], binds[0]) {
		t.Errorf("the request has %d session-binds; want the one of the server's key exchange", len(req.Binds))
	}
	// The data to sign starts with the session identifier of the bind.
	var bind struct {
		HostKey, SessionID, Signature []byte
		Forwarding                    bool
	}
	if err := ssh.Unmarshal(binds[0], &bind); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(req.Data, ssh.Marshal(struct{ ID []byte }{bind.SessionID})) ||
		!bytes.Contains(req.Data, []byte("deploy")) {
		t.Error("the data to sign is not the login of ssh")
	}
	want := [][]string{append([]string{sshPath}, args...), cmd.Args, os.Args}
	if parent := realCommandLine(t, os.Getppid()); parent != nil {
		want = append(want, parent)
	}
	if !slices.EqualFunc(req.Commands, want, slices.Equal) {
		t.Errorf("the command lines are\n%q\nwant\n%q", strings.Join(flat(req.Commands), " | "),
			strings.Join(flat(want), " | "))
	}
	if req.Reason != "from ssh" {
		t.Errorf("the reason is %q, want the one of ssh", req.Reason)
	}
}

// TestOpenSSHAgentChecksTheSignature: a signature that the broker gets
// wrong never reaches ssh, which then cannot log in, and a line says why.
// The same for an answer that is not 200, and without a broker.
func TestOpenSSHAgentChecksTheSignature(t *testing.T) {
	t.Parallel()
	sshPath, _ := requireOpenSSH(t)
	host, _ := newSSHKey(t)
	userKey, _ := newSSHKey(t)
	other, _ := newSSHKey(t)
	tests := []struct {
		name string
		sign func(http.ResponseWriter, *api.SignRequest)
		want string
	}{
		{"valid", signWith(userKey, "", ""), ""},
		{"a signature of another key", signWith(other, "", ""),
			"the signature of the broker is not a valid signature of the data"},
		{"another format", signWith(userKey, "", ssh.KeyAlgoECDSA256),
			"the signature of the broker does not fit the key and the sign flags"},
		{"503", func(w http.ResponseWriter, _ *api.SignRequest) {
			transport.WriteError(w, http.StatusServiceUnavailable)
		}, "the broker answered 503 Service Unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := startSSHServer(t, host, userKey.PublicKey())
			fb := newFakeSSHBroker(t, map[string]ssh.PublicKey{"deploy": userKey.PublicKey()}, tt.sign)
			au := startAgent(t, fb.b, agentOptions{})
			dir := shortTempDir(t)
			out, err := runSSH(t, sshPath, sshArgs(t, srv.addr, "deploy", host.PublicKey(), dir), sshEnv(au.socket, dir))
			if tt.want == "" {
				if err != nil || srv.loginCount() != 1 {
					t.Fatalf("ssh: %v; agent lines %q\n%s", err, au.lines(), out)
				}
				return
			}
			if err == nil || srv.loginCount() != 0 {
				t.Fatalf("ssh logged in\n%s", out)
			}
			if got := au.lines(); len(got) != 1 || got[0] != "nodkey: no signature: "+tt.want {
				t.Errorf("the agent wrote %q, want the line %q", got, tt.want)
			}
		})
	}

	t.Run("no broker", func(t *testing.T) {
		t.Parallel()
		srv := startSSHServer(t, host, userKey.PublicKey())
		ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		b, err := newBroker(addr, newTLSKey(t).cert, newTLSKey(t).pin)
		if err != nil {
			t.Fatal(err)
		}
		au := startAgent(t, b, agentOptions{})
		dir := shortTempDir(t)
		out, err := runSSH(t, sshPath, sshArgs(t, srv.addr, "deploy", host.PublicKey(), dir), sshEnv(au.socket, dir))
		if err == nil || srv.loginCount() != 0 {
			t.Fatalf("ssh logged in\n%s", out)
		}
		// Another test may take the free port at once: then the TLS
		// handshake fails instead.
		want := "nodkey: no key list: cannot connect to the broker at " + addr + ": "
		if got := au.lines(); len(got) != 1 || !strings.HasPrefix(got[0], want) {
			t.Errorf("the agent wrote %q, want a line that starts with %q", got, want)
		}
	})
}

// TestOpenSSHAdd: ssh-add lists the broker's keys, by their names. The
// agent refuses ssh-add when it adds or removes keys: the private key
// that ssh-add sends is not kept, and no line holds it.
func TestOpenSSHAdd(t *testing.T) {
	t.Parallel()
	_, addPath := requireOpenSSH(t)
	host, _ := newSSHKey(t)
	sb := newSSHBroker(t, map[string]ssh.PublicKey{"web-1": host.PublicKey()})
	au := startAgent(t, sb.client(t), agentOptions{})
	dir := shortTempDir(t)
	add := func(args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(t.Context(), waitLimit)
		defer cancel()
		cmd := exec.CommandContext(ctx, addPath, args...) //nolint:gosec // G204: the test runs ssh-add from PATH.
		cmd.Env = sshEnv(au.socket, dir)
		cmd.Stdin = strings.NewReader("")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	out, err := add("-L")
	if want := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sb.user.PublicKey()))) + " deploy\n"; err != nil ||
		out != want {
		t.Errorf("ssh-add -L: %v, %q; want %q", err, out, want)
	}
	if out, err := add("-l"); err != nil || !strings.Contains(out, ssh.FingerprintSHA256(sb.user.PublicKey())+" deploy (ED25519)") {
		t.Errorf("ssh-add -l: %v, %q", err, out)
	}
	// A private key that ssh-add sends.
	_, priv := newSSHKey(t)
	block, err := ssh.MarshalPrivateKey(priv, "added key")
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "id_ed25519")
	keyPEM := pem.EncodeToMemory(block)
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	pubFile := keyFile + ".pub"
	if err := os.WriteFile(pubFile, ssh.MarshalAuthorizedKey(sb.user.PublicKey()), 0o600); err != nil {
		t.Fatal(err)
	}
	const refused = "nodkey: refused a request to add, remove, lock or unlock keys: the keys stay on the broker"
	for _, tt := range []struct {
		args     []string
		requests int
	}{
		{[]string{keyFile}, 1},
		{[]string{"-t", "60", keyFile}, 1},
		{[]string{"-d", pubFile}, 1},
		// ssh-add -D removes the keys of SSH protocol 2, then those of
		// protocol 1.
		{[]string{"-D"}, 2},
	} {
		before := len(au.lines())
		out, err := add(tt.args...)
		if err == nil {
			t.Errorf("ssh-add %q worked: %q", tt.args, out)
		}
		if got := au.lines()[before:]; len(got) != tt.requests || slices.ContainsFunc(got, func(l string) bool {
			return l != refused
		}) {
			t.Errorf("ssh-add %q: the agent wrote %q", tt.args, got)
		}
	}
	if out, err := add("-L"); err != nil || strings.Count(out, "\n") != 1 {
		t.Errorf("after the refused requests, ssh-add -L: %v, %q", err, out)
	}
	if strings.Contains(au.log.String(), "added key") {
		t.Error("the agent wrote the comment of the added key")
	}
}

// requireSSHD returns the path of sshd. It skips the test (see
// skipOrFail) when there is none.
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

// sshUserName returns the name of the user who runs the test: sshd
// without root logs in only that user. It skips the test (see
// skipOrFail) when the name does not match the broker's rule for remote
// users.
func sshUserName(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil || !regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._-]{0,31}$`).MatchString(u.Username) {
		skipOrFail(t, "the user name of this test does not match the rule for remote users")
	}
	return u.Username
}

// startSSHD starts the real sshd on 127.0.0.1, as the user who runs the
// test, with the host key hostKey, and userKey in its authorized_keys. It
// returns the address. It skips the test (see skipOrFail) when sshd
// cannot start.
func startSSHD(t *testing.T, sshdPath, dir string, hostKey any, userKey ssh.PublicKey) string {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(hostKey, "")
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
	cfg := strings.Join([]string{
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
	}, "\n") + "\n"
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

// TestOpenSSHLoginToSSHD logs in with the real ssh to the real sshd
// through the agent and the real broker. sshd offers the hostbound
// method, so the data to sign holds the host key too, and sshd checks the
// signature of the broker.
func TestOpenSSHLoginToSSHD(t *testing.T) {
	t.Parallel()
	sshPath, _ := requireOpenSSH(t)
	sshdPath, name := requireSSHD(t), sshUserName(t)
	host, hostPriv := newSSHKey(t)
	sb := newSSHBroker(t, map[string]ssh.PublicKey{"web-1": host.PublicKey()})
	dir := shortTempDir(t)
	addr := startSSHD(t, sshdPath, dir, hostPriv, sb.user.PublicKey())
	au := startAgent(t, sb.client(t), agentOptions{proc: &procFS{root: procDir}})
	sb.approver.Auto(audit.AnswerApproveOnce)
	out, err := runSSH(t, sshPath, sshArgs(t, addr, name, host.PublicKey(), dir), sshEnv(au.socket, dir))
	asked := sb.approver.Asked()
	if len(asked) == 0 {
		// sshd did not even accept the key, so the cause is not the agent:
		// for example a locked account.
		skipOrFail(t, "ssh made no sign request (%v):\n%s", err, out)
	}
	if err != nil {
		t.Fatalf("ssh: %v; agent lines %q\n%s", err, au.lines(), out)
	}
	if p := asked[0].Prompt; p.RemoteUser != name || !slices.Equal(p.Hosts, []string{"web-1"}) {
		t.Errorf("the message shows %+v", p)
	}
	if got := eventNames(sb.audit.waitFor(t, 3)); got != "request decision:approve_once signed" {
		t.Errorf("audit entries %q", got)
	}
}
