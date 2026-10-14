package sshauth

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/code6x/nodkey/internal/config"
)

// testServer is an in-process SSH server from golang.org/x/crypto/ssh. It
// lets the key userKey log in as any user, and runs "exec" requests as a
// command that exits with 0. It records each signature its host key
// makes: the first of each connection is over the session identifier, in
// the key exchange. That is what OpenSSH puts in a session-bind.
type testServer struct {
	addr    string
	hostKey ssh.PublicKey

	mu       sync.Mutex
	kex      []kexSignature // in order
	sessions [][]byte       // session identifiers of logins, in order
}

// kexSignature is one signature of the server's host key.
type kexSignature struct {
	data []byte // the session identifier, for the first key exchange
	sig  *ssh.Signature
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

// startTestServer starts a server with this host key on 127.0.0.1. Only
// userKey may log in. extraAlgorithms are public key algorithms that the
// server accepts on top of its defaults.
func startTestServer(t testing.TB, host ssh.AlgorithmSigner, userKey ssh.PublicKey, extraAlgorithms ...string) *testServer {
	t.Helper()
	s := &testServer{hostKey: host.PublicKey()}
	cfg := &ssh.ServerConfig{
		// The callback records the session for the test's checks. It
		// grants nothing from that record; the server checks the
		// signature itself.
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) { //nolint:gosec // G408: the record is only for the test's checks.
			if !bytes.Equal(key.Marshal(), userKey.Marshal()) {
				return nil, errors.New("not this key")
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			s.sessions = append(s.sessions, bytes.Clone(conn.SessionID()))
			return &ssh.Permissions{}, nil
		},
	}
	if len(extraAlgorithms) > 0 {
		cfg.PublicKeyAuthAlgorithms = append([]string{
			ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
			ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512,
		}, extraAlgorithms...)
	}
	cfg.AddHostKey(recordingSigner{host, func(data []byte, sig *ssh.Signature) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.kex = append(s.kex, kexSignature{bytes.Clone(data), sig})
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
			wg.Go(func() { serveConn(nc, cfg) })
		}
	})
	return s
}

// serveConn serves one connection until the client closes it, or for at
// most 30 seconds.
func serveConn(nc net.Conn, cfg *ssh.ServerConfig) {
	defer func() { _ = nc.Close() }()
	_ = nc.SetDeadline(time.Now().Add(30 * time.Second))
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		if nch.ChannelType() != "session" {
			_ = nch.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
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

// lastBind returns the session-bind for the newest connection: the host
// key, the session identifier of its key exchange, and the host key's
// signature over it. It is what OpenSSH sends to its agent.
func (s *testServer) lastBind(t testing.TB) []byte {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.kex) == 0 {
		t.Error("the server has made no key exchange")
		return nil
	}
	k := s.kex[len(s.kex)-1]
	return marshalBind(s.hostKey.Marshal(), k.data, ssh.Marshal(k.sig), false)
}

// loginSessions returns the session identifiers of the logins so far.
func (s *testServer) loginSessions() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions
}

// brokerSigner is the client's signer. It sends each sign request through
// Check and Sign, as nodkey ssh-agent and the broker will. So the data to
// sign comes from a real SSH handshake.
type brokerSigner struct {
	key        Key
	hosts      *config.KnownHosts
	binds      func() [][]byte // the session-binds to send with a request
	algorithms []string        // what the signer offers to the server

	mu     sync.Mutex
	logins []Login
	errs   []error
}

func (b *brokerSigner) PublicKey() ssh.PublicKey { return b.key.PublicKey() }

func (b *brokerSigner) Algorithms() []string { return b.algorithms }

func (b *brokerSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return b.SignWithAlgorithm(rand, data, b.key.PublicKey().Type())
}

func (b *brokerSigner) SignWithAlgorithm(_ io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	req := Request{
		Key:   b.key.PublicKey().Marshal(),
		Data:  data,
		Flags: flagsFor(algorithm),
		Binds: b.binds(),
	}
	l, err := b.key.Check(req, b.hosts)
	b.mu.Lock()
	b.logins = append(b.logins, l)
	b.errs = append(b.errs, err)
	b.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return b.key.Sign(l)
}

// results returns the Logins and errors of all sign requests so far.
func (b *brokerSigner) results() ([]Login, []error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.logins, b.errs
}

// dialAndRun logs in to the server as user with signer, and runs one
// command.
func dialAndRun(t *testing.T, srv *testServer, user string, signer ssh.Signer, hostAlgorithm string) error {
	t.Helper()
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(srv.hostKey),
		Timeout:         10 * time.Second,
	}
	if hostAlgorithm != "" {
		cfg.HostKeyAlgorithms = []string{hostAlgorithm}
	}
	nc, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(t.Context(), "tcp", srv.addr)
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

// TestCheckRealHandshake logs in to an in-process SSH server with a client
// whose signer is backed by Check and Sign. So the data to sign is real,
// and the server checks the signature. The session-bind is built as
// OpenSSH builds it: the server's host key, the session identifier, and
// the server's own signature over it from the key exchange.
func TestCheckRealHandshake(t *testing.T) {
	tests := []struct {
		user          keyKind
		algorithm     string // the user key's signature algorithm
		host          keyKind
		hostAlgorithm string // the host key's algorithm in the key exchange
	}{
		{ed25519Kind, ssh.KeyAlgoED25519, ed25519Kind, ssh.KeyAlgoED25519},
		{ecdsa256, ssh.KeyAlgoECDSA256, ecdsa384, ssh.KeyAlgoECDSA384},
		{ecdsa384, ssh.KeyAlgoECDSA384, ecdsa521, ssh.KeyAlgoECDSA521},
		{ecdsa521, ssh.KeyAlgoECDSA521, ecdsa256, ssh.KeyAlgoECDSA256},
		{rsaKind, ssh.KeyAlgoRSASHA256, rsaKind, ssh.KeyAlgoRSASHA256},
		{rsaKind, ssh.KeyAlgoRSASHA512, rsaKind, ssh.KeyAlgoRSASHA512},
		{ed25519Kind, ssh.KeyAlgoED25519, rsaKind, ssh.KeyAlgoRSASHA512},
	}
	for _, tt := range tests {
		name := fmt.Sprintf("user %s %s, host %s %s", tt.user, tt.algorithm, tt.host, tt.hostAlgorithm)
		t.Run(name, func(t *testing.T) {
			key := newKey(t, "deploy", tt.user, 0)
			host := hostSigner(t, tt.host, 1)
			srv := startTestServer(t, host, key.PublicKey())
			hosts := knownHosts(t, map[string]ssh.PublicKey{
				"web-1": host.PublicKey(),
				"db-1":  hostSigner(t, ed25519Kind, 2).PublicKey(),
			})
			signer := &brokerSigner{
				key:        key,
				hosts:      hosts,
				binds:      func() [][]byte { return [][]byte{srv.lastBind(t)} },
				algorithms: []string{tt.algorithm},
			}
			if err := dialAndRun(t, srv, "deploy", signer, tt.hostAlgorithm); err != nil {
				_, errs := signer.results()
				t.Fatalf("login: %v (sign requests: %v)", err, errs)
			}
			logins, errs := signer.results()
			if len(logins) != 1 || errs[0] != nil {
				t.Fatalf("%d sign requests, errors %v; want 1 without error", len(logins), errs)
			}
			l := logins[0]
			if l.Host() != "web-1" || l.RemoteUser() != "deploy" || l.KeyName() != "deploy" {
				t.Errorf("the Login is %v; want deploy@web-1 with key deploy", l)
			}
			if got, want := l.HostKeyFingerprint(), ssh.FingerprintSHA256(host.PublicKey()); got != want {
				t.Errorf("HostKeyFingerprint() = %s; want %s", got, want)
			}
			if l.c.hostbound {
				t.Error("golang.org/x/crypto/ssh used the hostbound method; this test expects publickey")
			}
			if l.c.sign.algorithm != tt.algorithm {
				t.Errorf("the signature algorithm is %s; want %s", l.c.sign.algorithm, tt.algorithm)
			}
			sessions := srv.loginSessions()
			if len(sessions) == 0 || !bytes.Equal(l.c.sign.data[4:4+len(sessions[0])], sessions[0]) {
				t.Error("the signed data does not start with the server's session identifier")
			}
			b, err := parseBind(srv.lastBind(t))
			if err != nil {
				t.Fatal(err)
			}
			sig, err := parseSignature(b.signature)
			if err != nil {
				t.Fatal(err)
			}
			if sig.format != tt.hostAlgorithm {
				t.Errorf("the key exchange signature is %s; want %s", sig.format, tt.hostAlgorithm)
			}
		})
	}
}

// TestCheckRealHandshakeRefuses changes one thing in a real login and
// checks that Check refuses it, so that the server never gets a
// signature.
func TestCheckRealHandshakeRefuses(t *testing.T) {
	tests := []struct {
		name          string
		user          string  // the remote user; default deploy
		key           keyKind // the user key; default Ed25519
		algorithm     string  // the user key's signature algorithm; default the key type
		host          keyKind // the host key; default Ed25519
		hostAlgorithm string  // default the host key type
		unknownHost   bool    // the broker's known_hosts does not have the server
		toDB1         bool    // the server is db-1, not web-1
		keyHosts      []string
		binds         func(t *testing.T, srv *testServer, first []byte) [][]byte
		want          error
	}{
		{
			name: "the session-bind of an earlier session",
			binds: func(_ *testing.T, _ *testServer, first []byte) [][]byte {
				return [][]byte{first}
			},
			want: ErrOtherSession,
		},
		{
			name: "the session-binds of an earlier session and of this one",
			binds: func(t *testing.T, srv *testServer, first []byte) [][]byte {
				return [][]byte{first, srv.lastBind(t)}
			},
			want: ErrManyBinds,
		},
		{
			name: "no session-bind",
			binds: func(*testing.T, *testServer, []byte) [][]byte {
				return nil
			},
			want: ErrNoBind,
		},
		{
			name: "a forwarding session-bind",
			binds: func(t *testing.T, srv *testServer, _ []byte) [][]byte {
				b := bytes.Clone(srv.lastBind(t))
				b[len(b)-1] = 1
				return [][]byte{b}
			},
			want: ErrForwarding,
		},
		{
			name:        "a host that is not in the broker's known_hosts",
			unknownHost: true,
			want:        ErrUnknownHost,
		},
		{
			name: "a remote user name with @",
			user: "deploy@db-1",
			want: ErrUser,
		},
		{
			name: "a remote user name with 33 characters",
			user: "a23456789012345678901234567890123",
			want: ErrUser,
		},
		{
			name:      "a user key with RSA and SHA-1",
			key:       rsaKind,
			algorithm: ssh.KeyAlgoRSA,
			want:      ErrAlgorithm,
		},
		{
			name:          "a host key exchange signed with RSA and SHA-1",
			host:          rsaKind,
			hostAlgorithm: ssh.KeyAlgoRSA,
			want:          ErrBindSignature,
		},
		{
			name:     "a key that lists web-1, and a login to db-1",
			toDB1:    true,
			keyHosts: []string{"web-1"},
			want:     ErrHostNotAllowed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kind := tt.key
			if kind == "" {
				kind = ed25519Kind
			}
			hostKind := tt.host
			if hostKind == "" {
				hostKind = ed25519Kind
			}
			key := newKey(t, "deploy", kind, 0, tt.keyHosts...)
			web1, db1 := hostSigner(t, hostKind, 1), hostSigner(t, ed25519Kind, 2)
			server := web1
			if tt.toDB1 {
				server = db1
			}
			srv := startTestServer(t, server, key.PublicKey(), ssh.KeyAlgoRSA)
			known := map[string]ssh.PublicKey{"db-1": db1.PublicKey()}
			if !tt.unknownHost {
				known["web-1"] = web1.PublicKey()
			}
			hosts := knownHosts(t, known)
			algorithm := tt.algorithm
			if algorithm == "" {
				algorithm = key.PublicKey().Type()
			}
			user := tt.user
			if user == "" {
				user = "deploy"
			}

			// A first session, which works, for its session-bind.
			var first []byte
			if tt.binds != nil {
				good := &brokerSigner{key: key, hosts: hosts, algorithms: []string{key.PublicKey().Type()},
					binds: func() [][]byte { return [][]byte{srv.lastBind(t)} }}
				if err := dialAndRun(t, srv, "deploy", good, ""); err != nil {
					t.Fatalf("the first login: %v", err)
				}
				first = srv.lastBind(t)
			}

			signer := &brokerSigner{key: key, hosts: hosts, algorithms: []string{algorithm}}
			signer.binds = func() [][]byte {
				if tt.binds != nil {
					return tt.binds(t, srv, first)
				}
				return [][]byte{srv.lastBind(t)}
			}
			err := dialAndRun(t, srv, user, signer, tt.hostAlgorithm)
			if err == nil {
				t.Fatal("the login worked; want it refused")
			}
			logins, errs := signer.results()
			if len(errs) != 1 {
				t.Fatalf("%d sign requests (%v); want 1", len(errs), errs)
			}
			if !errors.Is(errs[0], tt.want) {
				t.Errorf("Check: %v; want %v", errs[0], tt.want)
			}
			if logins[0] != (Login{}) {
				t.Errorf("Check returned a Login with its error: %v", logins[0])
			}
		})
	}
}

// TestRealSessionIDLength checks that the key exchanges of
// golang.org/x/crypto/ssh give session identifiers that Check accepts.
func TestRealSessionIDLength(t *testing.T) {
	key := newKey(t, "deploy", ed25519Kind, 0)
	host := hostSigner(t, ed25519Kind, 1)
	srv := startTestServer(t, host, key.PublicKey())
	signer := &brokerSigner{key: key, hosts: knownHosts(t, map[string]ssh.PublicKey{"web-1": host.PublicKey()}),
		algorithms: []string{ssh.KeyAlgoED25519}, binds: func() [][]byte { return [][]byte{srv.lastBind(t)} }}
	if err := dialAndRun(t, srv, "deploy", signer, ""); err != nil {
		t.Fatal(err)
	}
	for _, id := range srv.loginSessions() {
		if !validSessionID(id) {
			t.Errorf("a real session identifier has %s bytes", strconv.Itoa(len(id)))
		}
	}
}
