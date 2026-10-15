package broker

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/audit"
)

// sshServer is an in-process SSH server, as in the tests of package
// sshauth. Only userKey may log in. It records its host key's signature
// over the session identifier of each key exchange: OpenSSH puts that
// into the session-bind that it sends to its agent.
type sshServer struct {
	addr    string
	hostKey ssh.PublicKey

	mu     sync.Mutex
	kex    [][]byte // the session-bind of each key exchange
	logins int      // the logins that the server accepted
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

// marshalBind returns the content of a session-bind@openssh.com message.
func marshalBind(hostKey ssh.PublicKey, sessionID []byte, sig *ssh.Signature, forwarding bool) []byte {
	return ssh.Marshal(struct {
		HostKey    []byte
		SessionID  []byte
		Signature  []byte
		Forwarding bool
	}{hostKey.Marshal(), sessionID, ssh.Marshal(sig), forwarding})
}

// startSSHServer starts a server with the host key on the loopback
// address.
func startSSHServer(t *testing.T, host ssh.AlgorithmSigner, userKey ssh.PublicKey) *sshServer {
	t.Helper()
	s := &sshServer{hostKey: host.PublicKey()}
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
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	s.mu.Lock()
	s.logins++
	s.mu.Unlock()
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

// bind returns the session-bind of the newest key exchange.
func (s *sshServer) bind() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.kex) == 0 {
		return nil
	}
	return s.kex[len(s.kex)-1]
}

// loginCount returns how many logins the server accepted.
func (s *sshServer) loginCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logins
}

// brokerSigner is the SSH client's signer: each sign request goes to the
// broker over the API, with the session-bind of the connection, as nodkey
// ssh-agent sends it.
type brokerSigner struct {
	e        *env
	c        *http.Client
	pub      ssh.PublicKey
	binds    func() [][]byte
	commands [][]string

	mu      sync.Mutex
	results []*result
}

// answers returns the statuses of the broker's answers so far.
func (b *brokerSigner) answers() []int {
	b.mu.Lock()
	defer b.mu.Unlock()
	statuses := make([]int, len(b.results))
	for i, r := range b.results {
		statuses[i] = r.status
	}
	return statuses
}

func (b *brokerSigner) PublicKey() ssh.PublicKey { return b.pub }

func (b *brokerSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return b.SignWithAlgorithm(rand, data, b.pub.Type())
}

func (b *brokerSigner) SignWithAlgorithm(_ io.Reader, data []byte, _ string) (*ssh.Signature, error) {
	req := api.SignRequest{
		PublicKey: b.pub.Marshal(), Data: data, Binds: b.binds(), Commands: b.commands, Reason: "apply the nginx fix",
	}
	res := b.e.post(context.Background(), b.c, api.PathSign, req)
	b.mu.Lock()
	b.results = append(b.results, res)
	b.mu.Unlock()
	if res.err != nil {
		return nil, res.err
	}
	if res.status != http.StatusOK {
		return nil, fmt.Errorf("the broker answered %d", res.status)
	}
	ans, err := api.ReadAnswer[api.SignAnswer](bytes.NewReader(res.body))
	if err != nil {
		return nil, err
	}
	return &ssh.Signature{Format: ans.Format, Blob: ans.Blob}, nil
}

// signer returns the signer of the client name for the key name, for
// logins to srv.
func (e *env) signer(client, key string, srv *sshServer) *brokerSigner {
	return &brokerSigner{
		e: e, c: e.httpClient(client), pub: e.userKeys[key].PublicKey(),
		binds:    func() [][]byte { return [][]byte{srv.bind()} },
		commands: [][]string{{"ssh", "deploy@" + srv.addr}, {"ansible-playbook", "site.yml"}},
	}
}

// login logs in to srv as user with signer, and runs one command.
func login(t *testing.T, srv *sshServer, user string, signer ssh.Signer) error {
	t.Helper()
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(srv.hostKey),
		Timeout:         waitLimit,
	}
	nc, err := (&net.Dialer{Timeout: waitLimit}).DialContext(t.Context(), "tcp", srv.addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, chans, reqs, err := ssh.NewClientConn(nc, srv.addr, cfg)
	if err != nil {
		_ = nc.Close()
		return err
	}
	client := ssh.NewClient(conn, chans, reqs)
	defer func() { _ = client.Close() }()
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer func() { _ = session.Close() }()
	return session.Run("true")
}

// signRequest returns a valid request to sign a login with the key to the
// host as user, in a new session, as OpenSSH sends it through the agent:
// a session-bind with the host key's signature over the session
// identifier, and the data to sign of RFC 4252.
func (e *env) signRequest(t testing.TB, key, host, user string) api.SignRequest {
	t.Helper()
	return e.signRequestFor(t, key, e.hosts[host], host, user)
}

// signRequestFor is signRequest for a host with the host key h.
func (e *env) signRequestFor(t testing.TB, key string, h ssh.AlgorithmSigner, host, user string) api.SignRequest {
	t.Helper()
	sid := make([]byte, 32)
	if _, err := rand.Read(sid); err != nil {
		t.Fatal(err)
	}
	sig, err := h.SignWithAlgorithm(rand.Reader, sid, "")
	if err != nil {
		t.Fatal(err)
	}
	pub := e.userKeys[key].PublicKey()
	data := ssh.Marshal(struct {
		SessionID []byte
		Msg       byte
		User      string
		Service   string
		Method    string
		HasSig    bool
		Algorithm string
		Key       []byte
	}{sid, 50, user, "ssh-connection", "publickey", true, pub.Type(), pub.Marshal()})
	return api.SignRequest{
		PublicKey: pub.Marshal(), Data: data, Binds: [][]byte{marshalBind(h.PublicKey(), sid, sig, false)},
		Commands: [][]string{{"ssh", user + "@" + host}}, Reason: "apply the nginx fix",
	}
}

// TestSignRealLogin logs in to an in-process SSH server whose client signs
// through the broker, with the person's approval: the server accepts the
// signature. The message and the audit log name the key, the host from
// the broker's known_hosts, its host key and the remote user.
func TestSignRealLogin(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.approver.Auto(audit.AnswerApproveOnce)
	srv := startSSHServer(t, e.hosts["web-1"], e.userKeys["deploy"].PublicKey())
	if err := login(t, srv, "deploy", e.signer("laptop", "deploy", srv)); err != nil {
		t.Fatalf("login: %v", err)
	}
	asked := e.approver.Asked()
	if len(asked) != 1 {
		t.Fatalf("%d messages, want 1", len(asked))
	}
	p := asked[0].Prompt
	fp := ssh.FingerprintSHA256(e.hosts["web-1"].PublicKey())
	if p.Kind != audit.KindSSHLogin || p.Key != "deploy" || strings.Join(p.Hosts, ",") != "web-1" ||
		p.HostKey != fp || p.RemoteUser != "deploy" || p.WindowMinutes != 15 || !p.Once {
		t.Errorf("the message shows %+v", p)
	}
	if !strings.HasPrefix(p.Claim.Command, "ssh deploy@") || !strings.HasSuffix(p.Claim.Command, " ← ansible-playbook site.yml") {
		t.Errorf("the claimed command is %q", p.Claim.Command)
	}
	events := requestEvents(e.audit.all(), p.RequestID)
	mustEvents(t, events, "request decision:approve_once signed")
	s := subjectOf(events[2])
	if s.Key != "deploy" || strings.Join(s.Hosts, ",") != "web-1" || s.HostKey != fp || s.RemoteUser != "deploy" {
		t.Errorf("the signed entry names %+v", s)
	}
}

// TestSignDeny: a Deny means no signature, and the login fails.
func TestSignDeny(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.approver.Auto(audit.AnswerDeny)
	srv := startSSHServer(t, e.hosts["web-1"], e.userKeys["deploy"].PublicKey())
	if err := login(t, srv, "deploy", e.signer("laptop", "deploy", srv)); err == nil {
		t.Fatal("the login worked after a Deny")
	}
	events := e.audit.all()
	mustEvents(t, requestEvents(events, lastRequestID(t, events)), "request decision:deny denied:approver")
	if srv.loginCount() != 0 {
		t.Error("the server accepted a login")
	}
}

// TestSignNeverAskHosts: a key with ask = "never" and hosts = ["web-1"]
// logs in to web-1 without a tap, with a notice. A real login to db-1,
// which is in the broker's known_hosts but not in the key's hosts, is
// denied without a message.
func TestSignNeverAskHosts(t *testing.T) {
	e := newEnv(t, envOptions{})
	web1 := startSSHServer(t, e.hosts["web-1"], e.userKeys["backup"].PublicKey())
	if err := login(t, web1, "backup", e.signer("ci", "backup", web1)); err != nil {
		t.Fatalf("the login to web-1: %v", err)
	}
	events := e.audit.all()
	mustEvents(t, requestEvents(events, lastRequestID(t, events)), "request grant_used:never_rule signed")
	if len(e.approver.Notices()) != 1 || len(e.approver.Asked()) != 0 {
		t.Errorf("notices %d, messages %d; want 1 and 0", len(e.approver.Notices()), len(e.approver.Asked()))
	}

	db1 := startSSHServer(t, e.hosts["db-1"], e.userKeys["backup"].PublicKey())
	signer := e.signer("ci", "backup", db1)
	if err := login(t, db1, "backup", signer); err == nil {
		t.Fatal("the login to db-1 worked")
	}
	if got := signer.answers(); len(got) != 1 || got[0] != http.StatusForbidden {
		t.Errorf("the broker answered %v, want 403", got)
	}
	events = e.audit.all()
	got := requestEvents(events, lastRequestID(t, events))
	mustEvents(t, got, "request denied:not_allowed")
	if s := subjectOf(got[0]); s.Key != "backup" || len(s.Hosts) != 0 || s.HostKey != "" {
		t.Errorf("the denied request names %+v; want the key and no host", s)
	}
	if len(e.approver.Notices()) != 1 || len(e.approver.Asked()) != 0 || db1.loginCount() != 0 {
		t.Error("the login to db-1 sent a message or a notice, or reached the server")
	}
	if !strings.Contains(e.logs.String(), "the host is not in the hosts list of the key") {
		t.Errorf("the log does not say why:\n%s", e.logs.String())
	}
}

// TestSignWindowGrant: "Approve 15 min" on a login makes a grant for that
// client, key, host key and remote user only.
func TestSignWindowGrant(t *testing.T) {
	e := newEnv(t, envOptions{})
	c := e.httpClient("laptop")
	e.approver.Auto(audit.AnswerApproveWindow)
	srv := startSSHServer(t, e.hosts["web-1"], e.userKeys["deploy"].PublicKey())
	if err := login(t, srv, "deploy", e.signer("laptop", "deploy", srv)); err != nil {
		t.Fatalf("login: %v", err)
	}
	e.approver.Auto("")
	if err := login(t, srv, "deploy", e.signer("laptop", "deploy", srv)); err != nil {
		t.Fatalf("the login with the grant: %v", err)
	}
	if n := len(e.approver.Asked()); n != 1 {
		t.Errorf("%d messages, want 1", n)
	}
	events := e.audit.all()
	mustEvents(t, requestEvents(events, lastRequestID(t, events)), "request grant_used:grant signed")
	// Another remote user, and another host, still ask.
	for i, req := range []api.SignRequest{
		e.signRequest(t, "deploy", "web-1", "root"),
		e.signRequest(t, "deploy", "web-2", "deploy"),
	} {
		p := e.start(c, api.PathSign, req)
		e.waitAsked(2 + i)
		p.cancel()
		p.wait(t)
	}
}

// TestSignRefusals: the broker refuses a sign request that fails a check,
// before any message, and writes it as denied. The log gets the fixed text
// of the check.
func TestSignRefusals(t *testing.T) {
	e := newEnv(t, envOptions{})
	c := e.httpClient("laptop")
	good := func() api.SignRequest { return e.signRequest(t, "deploy", "web-1", "deploy") }
	unknownHost := newHostKey(t)
	tests := []struct {
		name   string
		edit   func(*api.SignRequest)
		status int
		key    string // the key name in the audit log
		log    string // the fixed text in the log
	}{
		{"a key of another client", func(r *api.SignRequest) {
			*r = e.signRequest(t, "backup", "web-1", "deploy")
		}, http.StatusForbidden, "", ""},
		{"a key that the broker does not have", func(r *api.SignRequest) {
			r.PublicKey = newHostKey(t).PublicKey().Marshal()
		}, http.StatusForbidden, "", ""},
		{"no session-bind", func(r *api.SignRequest) { r.Binds = nil },
			http.StatusForbidden, "deploy", "the request has no session-bind"},
		{"two session-binds", func(r *api.SignRequest) { r.Binds = append(r.Binds, r.Binds[0]) },
			http.StatusForbidden, "deploy", "the request has more than one session-bind"},
		{"three session-binds", func(r *api.SignRequest) { r.Binds = append(r.Binds, r.Binds[0], r.Binds[0]) },
			http.StatusBadRequest, "", ""},
		{"a forwarding session-bind", func(r *api.SignRequest) { r.Binds[0][len(r.Binds[0])-1] = 1 },
			http.StatusForbidden, "deploy", "the session-bind is for agent forwarding"},
		{"a host that is not in known_hosts", func(r *api.SignRequest) {
			*r = e.signRequestFor(t, "deploy", unknownHost, "web-9", "deploy")
		}, http.StatusForbidden, "deploy", "the host key is not in the broker's known_hosts"},
		{"the session-bind of another session", func(r *api.SignRequest) {
			r.Binds = e.signRequest(t, "deploy", "web-1", "deploy").Binds
		}, http.StatusForbidden, "deploy", "the data to sign is for another session"},
		{"data that is not a login", func(r *api.SignRequest) { r.Data = []byte("SSHSIG made-up commit") },
			http.StatusForbidden, "deploy", "the data to sign is not an SSH login request"},
		{"a remote user with @", func(r *api.SignRequest) { *r = e.signRequest(t, "deploy", "web-1", "deploy@db-1") },
			http.StatusForbidden, "deploy", "the remote user name is not allowed"},
		{"data over the cap", func(r *api.SignRequest) { r.Data = make([]byte, api.MaxData+1) },
			http.StatusBadRequest, "", ""},
	}
	for _, tt := range tests {
		req := good()
		tt.edit(&req)
		before := len(e.audit.all())
		res := e.post(t.Context(), c, api.PathSign, req)
		if res.err != nil || res.status != tt.status || res.code != "" {
			t.Errorf("%s: %d, %v; want %d without a wait", tt.name, res.status, res.err, tt.status)
			continue
		}
		got := e.audit.waitFor(t, before+2)[before:]
		mustEvents(t, got, "request denied:not_allowed")
		if s := subjectOf(got[0]); s.Key != tt.key || len(s.Hosts) != 0 || s.RemoteUser != "" {
			t.Errorf("%s: the audit log names %+v", tt.name, s)
		}
		if tt.log != "" && !strings.Contains(e.logs.String(), tt.log) {
			t.Errorf("%s: the log does not say %q", tt.name, tt.log)
		}
	}
	if len(e.approver.Asked()) != 0 {
		t.Error("a refused sign request was shown")
	}
}

// TestSSHGrant: one tap grants logins as one user to exactly the listed
// hosts, until the end shown in the message. The broker never signs for
// the grant itself.
func TestSSHGrant(t *testing.T) {
	e := newEnv(t, envOptions{})
	c := e.httpClient("laptop")
	p := e.start(c, api.PathSSHGrant, api.GrantRequest{
		Key: "deploy", User: "deploy", Hosts: []string{"web-1", "web-1", "web-2"}, Seconds: 15 * 60,
		Reason: "apply the nginx fix",
	})
	asked := e.waitAsked(1)
	pr := asked[0].Prompt
	if pr.Kind != audit.KindSSHGrant || pr.Key != "deploy" || strings.Join(pr.Hosts, ",") != "web-1,web-2" ||
		pr.RemoteUser != "deploy" || pr.WindowMinutes != 15 || pr.Once || !pr.GrantEnds.Equal(noon.Add(15*time.Minute)) ||
		pr.Claim.Reason != "apply the nginx fix" {
		t.Errorf("the message shows %+v", pr)
	}
	if code := p.waitCode(t); code != pr.ShortCode {
		t.Errorf("the client got the short code %q, the message has %q", code, pr.ShortCode)
	}
	e.tap(pr.RequestID, audit.AnswerApproveWindow)
	res := p.wait(t)
	mustStatus(t, res, http.StatusOK)
	ans, err := api.ReadAnswer[api.GrantAnswer](bytes.NewReader(res.body))
	if err != nil || ans.Minutes != 15 {
		t.Errorf("the answer: %+v, %v", ans, err)
	}
	mustEvents(t, requestEvents(e.audit.all(), pr.RequestID), "request decision:approve_window")

	for _, host := range []string{"web-1", "web-2"} {
		res := e.post(t.Context(), c, api.PathSign, e.signRequest(t, "deploy", host, "deploy"))
		mustStatus(t, res, http.StatusOK)
		events := e.audit.all()
		mustEvents(t, requestEvents(events, lastRequestID(t, events)), "request grant_used:grant signed")
	}
	if n := len(e.approver.Asked()); n != 1 {
		t.Errorf("%d messages, want 1", n)
	}
	// A host that is not in the list, and another user, still ask.
	for i, req := range []api.SignRequest{
		e.signRequest(t, "deploy", "db-1", "deploy"),
		e.signRequest(t, "deploy", "web-1", "root"),
	} {
		p := e.start(c, api.PathSign, req)
		e.waitAsked(2 + i)
		p.cancel()
		p.wait(t)
	}
	// The grants end at the time in the message.
	e.clock.Advance(15 * time.Minute)
	p = e.start(c, api.PathSign, e.signRequest(t, "deploy", "web-1", "deploy"))
	e.waitAsked(4)
	p.cancel()
	p.wait(t)
}

// TestSSHGrantRefusals: the broker refuses an SSH grant that does not fit
// the key, the user or the hosts, before any message.
func TestSSHGrantRefusals(t *testing.T) {
	e := newEnv(t, envOptions{})
	c := e.httpClient("laptop")
	good := func() api.GrantRequest {
		return api.GrantRequest{Key: "web", User: "deploy", Hosts: []string{"web-1"}, Seconds: 600, Reason: "r"}
	}
	many := make([]string, api.MaxGrantHosts+1)
	for i := range many {
		many[i] = "web-1"
	}
	tests := []struct {
		name   string
		edit   func(*api.GrantRequest)
		status int
		sub    audit.Subject // the names in the audit log
	}{
		{"a bad user name", func(r *api.GrantRequest) { r.User = "deploy@web-1" }, http.StatusForbidden,
			audit.Subject{Key: "web", Hosts: []string{"web-1"}}},
		{"a key whose rule is not window", func(r *api.GrantRequest) { r.Key = "admin" }, http.StatusForbidden,
			audit.Subject{Key: "admin", RemoteUser: "deploy", Hosts: []string{"web-1"}}},
		{"longer than the window", func(r *api.GrantRequest) { r.Seconds = 16 * 60 }, http.StatusForbidden,
			audit.Subject{Key: "web", RemoteUser: "deploy", Hosts: []string{"web-1"}}},
		{"shorter than one minute", func(r *api.GrantRequest) { r.Seconds = 59 }, http.StatusForbidden,
			audit.Subject{Key: "web", RemoteUser: "deploy", Hosts: []string{"web-1"}}},
		{"a huge time", func(r *api.GrantRequest) { r.Seconds = 1 << 62 }, http.StatusForbidden,
			audit.Subject{Key: "web", RemoteUser: "deploy", Hosts: []string{"web-1"}}},
		{"a host not in known_hosts", func(r *api.GrantRequest) { r.Hosts = []string{"web-1", "web-9"} },
			http.StatusForbidden, audit.Subject{Key: "web", RemoteUser: "deploy", Hosts: []string{"web-1"}}},
		{"a host not in the key's hosts", func(r *api.GrantRequest) { r.Hosts = []string{"db-1"} },
			http.StatusForbidden, audit.Subject{Key: "web", RemoteUser: "deploy"}},
		{"no host", func(r *api.GrantRequest) { r.Hosts = nil }, http.StatusForbidden,
			audit.Subject{Key: "web", RemoteUser: "deploy"}},
		{"more than 20 hosts", func(r *api.GrantRequest) { r.Hosts = many }, http.StatusBadRequest, audit.Subject{}},
		{"a key of another client", func(r *api.GrantRequest) { r.Key = "backup" }, http.StatusForbidden,
			audit.Subject{RemoteUser: "deploy", Hosts: []string{"web-1"}}},
		{"an unknown key", func(r *api.GrantRequest) { r.Key = "nope" }, http.StatusForbidden,
			audit.Subject{RemoteUser: "deploy", Hosts: []string{"web-1"}}},
	}
	for _, tt := range tests {
		req := good()
		tt.edit(&req)
		before := len(e.audit.all())
		res := e.post(t.Context(), c, api.PathSSHGrant, req)
		if res.err != nil || res.status != tt.status || res.code != "" {
			t.Errorf("%s: %d, %v; want %d without a wait", tt.name, res.status, res.err, tt.status)
			continue
		}
		got := e.audit.waitFor(t, before+2)[before:]
		mustEvents(t, got, "request denied:not_allowed")
		s := subjectOf(got[0])
		if s.Key != tt.sub.Key || s.RemoteUser != tt.sub.RemoteUser || strings.Join(s.Hosts, ",") != strings.Join(tt.sub.Hosts, ",") {
			t.Errorf("%s: the audit log names %+v, want %+v", tt.name, s, tt.sub)
		}
	}
	if len(e.approver.Asked()) != 0 {
		t.Error("a refused grant was shown")
	}
}

// TestListKeys: a client gets the public keys it may use, sorted by name,
// and no others. Listing is not a request for a secret or a signature, so
// it has no audit entry.
func TestListKeys(t *testing.T) {
	e := newEnv(t, envOptions{})
	for client, want := range map[string][]string{"laptop": {"admin", "deploy", "web"}, "ci": {"backup"}} {
		res := e.post(t.Context(), e.httpClient(client), api.PathKeys, api.KeysRequest{})
		mustStatus(t, res, http.StatusOK)
		ans, err := api.ReadAnswer[api.KeysAnswer](bytes.NewReader(res.body))
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, k := range ans.Keys {
			names = append(names, k.Name)
			if !bytes.Equal(k.PublicKey, e.userKeys[k.Name].PublicKey().Marshal()) {
				t.Errorf("%s: the key %s is not its public key", client, k.Name)
			}
		}
		if strings.Join(names, ",") != strings.Join(want, ",") {
			t.Errorf("%s: keys %v, want %v", client, names, want)
		}
	}
	if res := e.postRaw(t.Context(), e.httpClient("laptop"), api.PathKeys, []byte(`{"key":"x"}`)); res.status != http.StatusBadRequest {
		t.Errorf("a list request with a field: %d, want 400", res.status)
	}
	if n := len(e.audit.all()); n != 0 {
		t.Errorf("listing the keys wrote %d audit entries", n)
	}
}

// TestSignAuditFailure: when the decision entry cannot be written, nothing
// is signed and the login fails.
func TestSignAuditFailure(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.approver.Auto(audit.AnswerApproveOnce)
	e.audit.setFail(func(ev audit.Event) error {
		if _, ok := ev.(audit.Decision); ok {
			return errors.New("made-up disk error")
		}
		return nil
	})
	srv := startSSHServer(t, e.hosts["web-1"], e.userKeys["deploy"].PublicKey())
	signer := e.signer("laptop", "deploy", srv)
	if err := login(t, srv, "deploy", signer); err == nil {
		t.Fatal("the login worked without its decision entry")
	}
	if got := signer.answers(); len(got) != 1 || got[0] != http.StatusServiceUnavailable {
		t.Errorf("the broker answered %v, want 503", got)
	}
	mustEvents(t, e.audit.all(), "request")
	if srv.loginCount() != 0 {
		t.Error("the server accepted a login")
	}
}
