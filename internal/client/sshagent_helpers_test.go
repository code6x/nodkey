package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/approval/approvaltest"
	"github.com/code6x/nodkey/internal/broker"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/sshauth"
	"github.com/code6x/nodkey/internal/store"
	"github.com/code6x/nodkey/internal/transport"
)

// The tests of nodkey ssh-agent run the agent in the test process, on a
// socket in a short temporary directory. Its requests go to the real
// broker service (package broker) behind the real transport server, with
// mutual TLS on the loopback address, the real approval core, the fake
// approver and clock, and the real SSH checks (package sshauth); or to a
// test handler (newFakeBroker), for answers that the broker never gives.
// The SSH clients are the agent client of golang.org/x/crypto, and the
// real OpenSSH ssh and ssh-add. The SSH servers are an in-process server
// of golang.org/x/crypto/ssh, and the real sshd.

// sshTimeout is the broker's timeout of an SSH request.
const sshTimeout = 90 * time.Second

// syncBuffer is a bytes.Buffer that goroutines can write while a test
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

// linesOf returns the lines of s, without their line breaks.
func linesOf(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// waitFor waits until ok is true, and fails the test after waitLimit.
func waitFor(t testing.TB, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitLimit)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("waited %s in vain for %s", waitLimit, what)
		}
		time.Sleep(time.Millisecond)
	}
}

// newSSHKey makes an Ed25519 SSH key.
func newSSHKey(t testing.TB) (ssh.AlgorithmSigner, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	as, ok := s.(ssh.AlgorithmSigner)
	if !ok {
		t.Fatal("the signer cannot choose an algorithm")
	}
	return as, priv
}

// sshBroker is a running broker for one SSH test, with one client,
// laptop, and one key, deploy: an Ed25519 key with the rule "always",
// for any host in the broker's known_hosts.
type sshBroker struct {
	addr     string
	key      tlsKey // the broker's TLS key
	laptop   tlsKey // the TLS key of the client laptop
	approver *approvaltest.Approver
	clock    *approvaltest.Clock
	audit    *memAudit
	user     ssh.Signer // the private key of deploy, for the test servers
}

// newSSHBroker starts a broker whose known_hosts has hosts, by name.
func newSSHBroker(t *testing.T, hosts map[string]ssh.PublicKey) *sshBroker {
	t.Helper()
	sb := &sshBroker{
		key:      newTLSKey(t),
		laptop:   newTLSKey(t),
		approver: approvaltest.NewApprover(approverID),
		clock:    approvaltest.NewClock(noon),
		audit:    newMemAudit(),
	}
	var kh strings.Builder
	for name, k := range hosts {
		kh.WriteString(name + " " + string(ssh.MarshalAuthorizedKey(k)))
	}
	known, err := config.ParseKnownHosts([]byte(kh.String()))
	if err != nil {
		t.Fatal(err)
	}
	signer, priv := newSSHKey(t)
	sb.user = signer
	deploy, err := sshauth.NewKey("deploy", priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Broker{
		Telegram: config.Telegram{UserID: approverID, NoticeChatID: approverID, Timeout: secretsTimeout,
			SSHTimeout: sshTimeout},
		Clients: map[string]config.Client{"laptop": {Name: "laptop", Pin: sb.laptop.pin}},
		Keys: map[string]config.Key{
			"deploy": {Name: "deploy", Clients: []string{"laptop"}, Rule: config.Rule{Ask: config.AskAlways}},
		},
		KnownHosts: known,
	}
	core, err := approval.New(cfg, sb.approver, approval.Options{Clock: sb.clock})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := broker.New(broker.Parts{Config: cfg, Audit: sb.audit, Stores: map[string]store.Store{},
		Keys: map[string]sshauth.Key{"deploy": deploy}})
	if err != nil {
		t.Fatal(err)
	}
	sb.addr = serve(t, sb.key, cfg.Clients, svc)
	runCtx, stopRun := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- svc.Run(runCtx, core, nil) }()
	t.Cleanup(func() {
		stopRun()
		select {
		case <-runErr:
		case <-time.After(waitLimit):
			t.Error("Run did not return")
		}
		svc.Close()
	})
	if err := sb.approver.WaitRunning(waitLimit); err != nil {
		t.Fatal(err)
	}
	return sb
}

// client returns a Broker for the client laptop, as Load makes it.
func (sb *sshBroker) client(t testing.TB) *Broker {
	t.Helper()
	b, err := newBroker(sb.addr, sb.laptop.cert, sb.key.pin)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// waitAsked waits until the approver was asked for n messages, and
// returns them.
func (sb *sshBroker) waitAsked(t testing.TB, n int) []approvaltest.Asked {
	t.Helper()
	asked, err := sb.approver.WaitAsked(n, waitLimit)
	if err != nil {
		t.Fatal(err)
	}
	return asked
}

// agentUnderTest is nodkey ssh-agent, serving in the test process.
type agentUnderTest struct {
	socket string
	log    *syncBuffer // what the agent wrote to its stderr
	alog   *agentLog   // the agent's lines, with their budgets
	agent  *sshAgent
	stop   func() // stops the agent, and waits until it has stopped
}

// agentOptions change the agent of startAgent.
type agentOptions struct {
	// proc reads the claimed context. The default is a tree without
	// processes: no claimed context.
	proc *procFS
	// peer replaces peerCredentials.
	peer func(*net.UnixConn) (peer, error)
	// keysTimeout, signTimeout, procTimeout and stopWait replace the
	// limits of the agent, and maxConns the most open connections.
	keysTimeout, signTimeout, procTimeout, stopWait time.Duration
	maxConns                                        int
	// now replaces the clock of the agent's lines.
	now func() time.Time
}

// noDirCheck takes the place of config.CheckParentDirs, which refuses
// the system temporary directory.
func noDirCheck(string) error { return nil }

// startAgent starts the agent with the broker b, until the test ends. Its
// socket is in a new directory of a short temporary directory: the
// directory checks of the real agent refuse the system temporary
// directory, which everyone can write to.
func startAgent(t *testing.T, b *Broker, opts agentOptions) *agentUnderTest {
	t.Helper()
	path := filepath.Join(shortTempDir(t), "a", socketName)
	self, err := currentUID()
	if err != nil {
		t.Fatal(err)
	}
	sock, err := listenAgent(t.Context(), path, self, noDirCheck)
	if err != nil {
		t.Fatal(err)
	}
	au := &agentUnderTest{socket: path, log: &syncBuffer{}}
	log := newAgentLog(au.log)
	if opts.now != nil {
		log.now = opts.now
	}
	au.alog = log
	a := newSSHAgent(b, log, procFS{root: t.TempDir()}, peerCredentials, self)
	au.agent = a
	if opts.proc != nil {
		a.proc = *opts.proc
	}
	if opts.peer != nil {
		a.peer = opts.peer
	}
	for _, o := range []struct {
		to   *time.Duration
		from time.Duration
	}{{&a.keysTimeout, opts.keysTimeout}, {&a.signTimeout, opts.signTimeout}, {&a.procTimeout, opts.procTimeout},
		{&a.stopWait, opts.stopWait}} {
		if o.from > 0 {
			*o.to = o.from
		}
	}
	if opts.maxConns > 0 {
		a.maxConns = opts.maxConns
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.serve(ctx, sock.ln)
		sock.close()
		log.flush()
	}()
	au.stop = func() {
		cancel()
		select {
		case <-done:
		case <-time.After(waitLimit):
			t.Error("the agent did not stop")
		}
	}
	t.Cleanup(au.stop)
	return au
}

// conn connects to the agent, for raw messages (rawCall).
func (au *agentUnderTest) conn(t *testing.T) net.Conn {
	t.Helper()
	c, err := (&net.Dialer{}).DialContext(t.Context(), "unix", au.socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// client connects to the agent, and returns the agent client of
// golang.org/x/crypto on that connection. The client reads the answers
// itself, so do not use rawCall on its connection.
func (au *agentUnderTest) client(t *testing.T) agent.ExtendedAgent {
	t.Helper()
	return agent.NewClient(au.conn(t))
}

// lines returns the lines that the agent wrote so far.
func (au *agentUnderTest) lines() []string { return linesOf(au.log.String()) }

// openConns returns how many connections the agent serves now.
func (au *agentUnderTest) openConns() int {
	au.agent.mu.Lock()
	defer au.agent.mu.Unlock()
	return len(au.agent.conns)
}

// shortCodes returns how many short codes the agent got so far: the lines
// with a short code that it wrote, and those it left out.
func (au *agentUnderTest) shortCodes() int {
	au.alog.mu.Lock()
	defer au.alog.mu.Unlock()
	return au.alog.waiting.lines + au.alog.waiting.dropped
}

// rawCall sends one message on c, and returns the answer.
func rawCall(t *testing.T, c net.Conn, msg []byte) []byte {
	t.Helper()
	if err := c.SetDeadline(time.Now().Add(waitLimit)); err != nil {
		t.Fatal(err)
	}
	if err := writeAgentMessage(c, msg); err != nil {
		t.Fatal(err)
	}
	answer, err := readAgentMessage(c)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	return answer
}

// signRequestMessage returns a sign request for the key blob, the data and
// the flags.
func signRequestMessage(key, data []byte, flags uint32) []byte {
	b := appendString([]byte{agentSignRequest}, key)
	b = appendString(b, data)
	return binary.BigEndian.AppendUint32(b, flags)
}

// extensionMessage returns an extension request.
func extensionMessage(name string, contents []byte) []byte {
	return append(appendString([]byte{agentExtension}, []byte(name)), contents...)
}

// bindAgent sends a session-bind@openssh.com message with contents, and
// reports whether the agent answered success.
func bindAgent(t *testing.T, c net.Conn, contents []byte) bool {
	t.Helper()
	answer := rawCall(t, c, extensionMessage(sessionBindRequest, contents))
	switch {
	case bytes.Equal(answer, []byte{agentSuccess}):
		return true
	case bytes.Equal(answer, failureMessage):
		return false
	}
	t.Fatalf("the answer to a session-bind is % x", answer)
	return false
}

// signatureOf parses the answer to a sign request: the signature, or nil
// for SSH_AGENT_FAILURE.
func signatureOf(t *testing.T, answer []byte) *ssh.Signature {
	t.Helper()
	if bytes.Equal(answer, failureMessage) {
		return nil
	}
	if len(answer) == 0 || answer[0] != agentSignAnswer {
		t.Fatalf("the answer to a sign request is % x", answer)
	}
	r := newWireReader(answer[1:])
	inner := newWireReader(r.string())
	sig := &ssh.Signature{Format: string(inner.string()), Blob: inner.string()}
	if !r.done() || !inner.done() {
		t.Fatalf("the sign answer has another form: % x", answer)
	}
	return sig
}

// sshServer is an in-process SSH server of golang.org/x/crypto/ssh, as in
// the tests of package sshauth. Only userKey may log in. It records its
// host key's signature over the session identifier of each key exchange:
// OpenSSH puts that into the session-bind that it sends to its agent.
type sshServer struct {
	addr    string
	hostKey ssh.PublicKey

	mu      sync.Mutex
	kex     [][]byte      // the session-bind of each key exchange, in order
	ended   int           // the connections whose handshake ended, with a login or without
	logins  int           // the logins that the server accepted
	changed chan struct{} // closed and made new when a handshake ends
}

// recordingSigner signs with a host key and records each signature.
type recordingSigner struct {
	ssh.AlgorithmSigner
	record func(data []byte, sig *ssh.Signature)
}

func (r recordingSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return r.SignWithAlgorithm(rand, data, "")
}

func (r recordingSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	sig, err := r.AlgorithmSigner.SignWithAlgorithm(rand, data, algorithm)
	if err == nil {
		r.record(data, sig)
	}
	return sig, err
}

// marshalBind returns the contents of a session-bind@openssh.com message.
func marshalBind(hostKey ssh.PublicKey, sessionID []byte, sig *ssh.Signature, forwarding bool) []byte {
	return ssh.Marshal(struct {
		HostKey    []byte
		SessionID  []byte
		Signature  []byte
		Forwarding bool
	}{hostKey.Marshal(), sessionID, ssh.Marshal(sig), forwarding})
}

// startSSHServer starts a server with the host key host on the loopback
// address. Only userKey may log in.
func startSSHServer(t *testing.T, host ssh.AlgorithmSigner, userKey ssh.PublicKey) *sshServer {
	t.Helper()
	s := &sshServer{hostKey: host.PublicKey(), changed: make(chan struct{})}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !bytes.Equal(key.Marshal(), userKey.Marshal()) {
				return nil, errors.New("not this key")
			}
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(recordingSigner{host, func(data []byte, sig *ssh.Signature) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.kex = append(s.kex, marshalBind(host.PublicKey(), bytes.Clone(data), sig, false))
	}})
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.addr = ln.Addr().String()
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	wg.Go(func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() { s.serve(nc, cfg) })
		}
	})
	return s
}

// serve serves one connection: it runs each "exec" request as a command
// that exits with 0.
func (s *sshServer) serve(nc net.Conn, cfg *ssh.ServerConfig) {
	defer func() { _ = nc.Close() }()
	_ = nc.SetDeadline(time.Now().Add(2 * waitLimit))
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	// NewServerConn sends the client its success before it returns, so the
	// client can see its login work before the server counts it here. A
	// test waits for the count with loginsAfter.
	s.mu.Lock()
	s.ended++
	if err == nil {
		s.logins++
	}
	close(s.changed)
	s.changed = make(chan struct{})
	s.mu.Unlock()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		ch, chReqs, err := nch.Accept()
		if err != nil {
			return
		}
		go func() {
			for req := range chReqs {
				exec := req.Type == "exec"
				_ = req.Reply(exec, nil)
				if exec {
					_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					_ = ch.Close()
				}
			}
		}()
	}
}

// binds returns the session-bind of each key exchange so far.
func (s *sshServer) binds() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.kex...)
}

// loginsAfter waits until the handshake of n connections has ended, with
// a login or without, and returns how many logins the server accepted.
// Only then is the count final: the server answers a login before it
// counts it, and a refused login ends after the client has given up.
func (s *sshServer) loginsAfter(t testing.TB, n int) int {
	t.Helper()
	deadline := time.NewTimer(waitLimit)
	defer deadline.Stop()
	for {
		s.mu.Lock()
		ended, logins, changed := s.ended, s.logins, s.changed
		s.mu.Unlock()
		if ended >= n {
			return logins
		}
		select {
		case <-changed:
		case <-deadline.C:
			t.Fatalf("the SSH server ended %d handshakes within %s, want %d", ended, waitLimit, n)
			return 0
		}
	}
}

// fakeSSHBroker is a test handler in place of the broker: it lists keys,
// and answers each sign request with sign. It keeps every sign request.
type fakeSSHBroker struct {
	*fakeBroker
	mu    sync.Mutex
	signs []*api.SignRequest
}

// newFakeSSHBroker starts a fake broker that lists keys, by name, and
// answers each sign request with sign.
func newFakeSSHBroker(t *testing.T, keys map[string]ssh.PublicKey,
	sign func(w http.ResponseWriter, req *api.SignRequest)) *fakeSSHBroker {
	t.Helper()
	ans := api.KeysAnswer{Keys: []api.Key{}}
	for name, k := range keys {
		ans.Keys = append(ans.Keys, api.Key{Name: name, PublicKey: k.Marshal()})
	}
	fb := &fakeSSHBroker{}
	fb.fakeBroker = newFakeBroker(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case api.PathKeys:
			if _, err := transport.ReadJSON[api.KeysRequest](w, r); err != nil {
				return
			}
			_ = transport.WriteJSON(w, http.StatusOK, ans)
		case api.PathSign:
			req, err := transport.ReadJSON[api.SignRequest](w, r)
			if err != nil {
				return
			}
			fb.mu.Lock()
			fb.signs = append(fb.signs, req)
			fb.mu.Unlock()
			sign(w, req)
		default:
			transport.WriteError(w, http.StatusNotFound)
		}
	})
	return fb
}

// signRequests returns the sign requests so far.
func (fb *fakeSSHBroker) signRequests() []*api.SignRequest {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	return append([]*api.SignRequest(nil), fb.signs...)
}

// signWith returns a sign handler that signs the data of each request
// with signer, and says that the signature has the format format ("" for
// the format of the signature).
func signWith(signer ssh.AlgorithmSigner, algorithm, format string) func(http.ResponseWriter, *api.SignRequest) {
	return func(w http.ResponseWriter, req *api.SignRequest) {
		sig, err := signer.SignWithAlgorithm(rand.Reader, req.Data, algorithm)
		if err != nil {
			transport.WriteError(w, http.StatusInternalServerError)
			return
		}
		f := format
		if f == "" {
			f = sig.Format
		}
		_ = transport.WriteJSON(w, http.StatusOK, api.SignAnswer{Format: f, Blob: sig.Blob})
	}
}

// shortTempDir returns a new directory with a short path, because the
// path of a Unix socket must be shorter than 108 bytes.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "nodkey-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
