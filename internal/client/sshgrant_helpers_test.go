package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/approval/approvaltest"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/broker"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/sshauth"
)

// The tests of nodkey ssh-grant run it against the real broker service
// (package broker) behind the real transport server, with mutual TLS on
// the loopback address, the real approval core, the fake approver and the
// fake clock of package approvaltest, and an audit log in memory, as the
// tests of nodkey run do. After a grant, they ask the broker for
// signatures as nodkey ssh-agent does (POST /v1/sign with Post), with
// valid session-binds of the hosts in the broker's known_hosts.

// grantBroker is a running broker for one test of nodkey ssh-grant. Its
// config has:
//
//   - the clients laptop and ci;
//   - the keys deploy (window 15m, laptop and ci, any host), web (window
//     15m, laptop, web-1 and web-2), admin (always, laptop, any host) and
//     backup (never, ci, web-1);
//   - the hosts web-1 (an Ed25519 and an ECDSA host key), web-2 and db-1
//     in known_hosts.
type grantBroker struct {
	addr     string
	key      tlsKey            // the broker's TLS key
	clients  map[string]tlsKey // the TLS keys of laptop and ci
	approver *approvaltest.Approver
	clock    *approvaltest.Clock
	audit    *memAudit
	// userKeys holds the public key of each [key.*] section.
	userKeys map[string]ssh.PublicKey
	// hostKeys holds the host keys of each host, in the order of
	// known_hosts.
	hostKeys map[string][]ssh.AlgorithmSigner
}

// grantWindow is the window of the keys deploy and web.
const grantWindow = 15 * time.Minute

// grantBrokerOptions change a grantBroker before it starts.
type grantBrokerOptions struct {
	// audit, if set, wraps the audit log of the broker, such as to hold a
	// write as a slow disk does.
	audit func(*memAudit) broker.AuditLog
	// contexts, if set, gets the context of each request that reaches the
	// broker, so that a test can wait until the broker has seen a client
	// hang up. It needs room for every request of the test.
	contexts chan<- context.Context
}

// newGrantBroker starts a grantBroker.
func newGrantBroker(t *testing.T) *grantBroker {
	t.Helper()
	return newGrantBrokerWith(t, grantBrokerOptions{})
}

// newGrantBrokerWith starts a grantBroker with the changes of opts.
func newGrantBrokerWith(t *testing.T, opts grantBrokerOptions) *grantBroker {
	t.Helper()
	gb := &grantBroker{
		key:      newTLSKey(t),
		clients:  map[string]tlsKey{"laptop": newTLSKey(t), "ci": newTLSKey(t)},
		approver: approvaltest.NewApprover(approverID),
		clock:    approvaltest.NewClock(noon),
		audit:    newMemAudit(),
		userKeys: make(map[string]ssh.PublicKey),
		hostKeys: make(map[string][]ssh.AlgorithmSigner),
	}
	var kh strings.Builder
	for _, h := range []struct {
		name  string
		ecdsa bool
	}{{"web-1", false}, {"web-1", true}, {"web-2", false}, {"db-1", false}} {
		s := newGrantHostKey(t, h.ecdsa)
		gb.hostKeys[h.name] = append(gb.hostKeys[h.name], s)
		kh.WriteString(h.name + " " + string(ssh.MarshalAuthorizedKey(s.PublicKey())))
	}
	known, err := config.ParseKnownHosts([]byte(kh.String()))
	if err != nil {
		t.Fatal(err)
	}
	window := config.Rule{Ask: config.AskWindow, Window: grantWindow}
	cfg := &config.Broker{
		Telegram: config.Telegram{UserID: approverID, NoticeChatID: approverID, Timeout: secretsTimeout,
			SSHTimeout: 90 * time.Second},
		Clients: map[string]config.Client{
			"laptop": {Name: "laptop", Pin: gb.clients["laptop"].pin},
			"ci":     {Name: "ci", Pin: gb.clients["ci"].pin},
		},
		Keys: map[string]config.Key{
			"deploy": {Name: "deploy", Clients: []string{"laptop", "ci"}, Rule: window},
			"web":    {Name: "web", Clients: []string{"laptop"}, Rule: window, Hosts: []string{"web-1", "web-2"}},
			"admin":  {Name: "admin", Clients: []string{"laptop"}, Rule: config.Rule{Ask: config.AskAlways}},
			"backup": {Name: "backup", Clients: []string{"ci"}, Rule: config.Rule{Ask: config.AskNever, Notify: true},
				Hosts: []string{"web-1"}},
		},
		KnownHosts: known,
	}
	keys := make(map[string]sshauth.Key)
	for name, k := range cfg.Keys {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, err := sshauth.NewKey(name, priv, k.Hosts)
		if err != nil {
			t.Fatal(err)
		}
		keys[name] = key
		gb.userKeys[name] = key.PublicKey()
	}
	core, err := approval.New(cfg, gb.approver, approval.Options{Clock: gb.clock})
	if err != nil {
		t.Fatal(err)
	}
	var log broker.AuditLog = gb.audit
	if opts.audit != nil {
		log = opts.audit(gb.audit)
	}
	svc, err := broker.New(broker.Parts{Config: cfg, Audit: log, Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	var handler http.Handler = svc
	if opts.contexts != nil {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			opts.contexts <- r.Context()
			svc.ServeHTTP(w, r)
		})
	}
	gb.addr = serve(t, gb.key, cfg.Clients, handler)
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
	if err := gb.approver.WaitRunning(waitLimit); err != nil {
		t.Fatal(err)
	}
	return gb
}

// newGrantHostKey makes an SSH host key: ECDSA on P-256, or Ed25519.
func newGrantHostKey(t testing.TB, isECDSA bool) ssh.AlgorithmSigner {
	t.Helper()
	var priv any
	var err error
	if isECDSA {
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	as, ok := s.(ssh.AlgorithmSigner)
	if !ok {
		t.Fatal("the host key cannot choose a signature algorithm")
	}
	return as
}

// client returns a Broker for the client name, as Load makes it.
func (gb *grantBroker) client(t testing.TB, name string) *Broker {
	t.Helper()
	k, ok := gb.clients[name]
	if !ok {
		t.Fatalf("no client %q", name)
	}
	b, err := newBroker(gb.addr, k.cert, gb.key.pin)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// waitAsked waits until the approver was asked for n messages, and returns
// them.
func (gb *grantBroker) waitAsked(t testing.TB, n int) []approvaltest.Asked {
	t.Helper()
	asked, err := gb.approver.WaitAsked(n, waitLimit)
	if err != nil {
		t.Fatal(err)
	}
	return asked
}

// signRequest returns a valid request to sign a login with the key to the
// host as user, in a new session, as nodkey ssh-agent forwards it from
// OpenSSH: a session-bind with the host key's signature over the session
// identifier, and the data to sign of RFC 4252. hostKey picks one of the
// host keys of the host, in the order of known_hosts.
func (gb *grantBroker) signRequest(t testing.TB, key, host string, hostKey int, user string) api.SignRequest {
	t.Helper()
	h := gb.hostKeys[host][hostKey]
	sid := make([]byte, 32)
	if _, err := rand.Read(sid); err != nil {
		t.Fatal(err)
	}
	sig, err := h.SignWithAlgorithm(rand.Reader, sid, "")
	if err != nil {
		t.Fatal(err)
	}
	pub := gb.userKeys[key]
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
	bind := ssh.Marshal(struct {
		HostKey    []byte
		SessionID  []byte
		Signature  []byte
		Forwarding bool
	}{h.PublicKey().Marshal(), sid, ssh.Marshal(sig), false})
	return api.SignRequest{
		PublicKey: pub.Marshal(), Data: data, Binds: [][]byte{bind},
		Commands: [][]string{{"ssh", user + "@" + host}, {"ansible-playbook", "site.yml"}},
		Reason:   "apply the nginx fix",
	}
}

// sign asks the broker for the signature of req as the client b, as nodkey
// ssh-agent does, and checks the signature with the public key of the key.
func (gb *grantBroker) sign(t testing.TB, b *Broker, key string, req api.SignRequest) error {
	t.Helper()
	ans, err := Post[api.SignAnswer](t.Context(), b, api.PathSign, mustJSON(t, req), nil)
	if err != nil {
		return err
	}
	if err := gb.userKeys[key].Verify(req.Data, &ssh.Signature{Format: ans.Format, Blob: ans.Blob}); err != nil {
		t.Errorf("the signature of the broker is not valid: %v", err)
	}
	return nil
}

// mustAsk sends req as the client b, checks that the broker shows it to
// the person as message n, cancels it, and returns the prompt of the
// message. A cancelled request starts no pause and ends no grant.
func (gb *grantBroker) mustAsk(t *testing.T, b *Broker, req api.SignRequest, n int) approval.Prompt {
	t.Helper()
	body := mustJSON(t, req)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := Post[api.SignAnswer](ctx, b, api.PathSign, body, nil)
		done <- err
	}()
	p := gb.waitAsked(t, n)[n-1].Prompt
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a request that waited for the person got a signature")
		}
	case <-time.After(waitLimit):
		t.Fatal("the cancelled request did not end")
	}
	gb.waitEvents(t, p.RequestID, "request denied:cancelled")
	return p
}

// waitEvents waits until the audit log has exactly the entries want for
// the request id, such as "request denied:cancelled".
func (gb *grantBroker) waitEvents(t testing.TB, id, want string) {
	t.Helper()
	deadline := time.NewTimer(waitLimit)
	defer deadline.Stop()
	for {
		gb.audit.mu.Lock()
		events, changed := slices.Clone(gb.audit.events), gb.audit.changed
		gb.audit.mu.Unlock()
		got := grantEventNames(grantEventsOf(events, id))
		if got == want {
			return
		}
		select {
		case <-changed:
		case <-deadline.C:
			t.Fatalf("the audit entries of request %s are %q, want %q", id, got, want)
			return
		}
	}
}

// lastEvents returns the names of the entries of the newest request in
// the audit log.
func (gb *grantBroker) lastEvents() string {
	events := gb.audit.all()
	for i := len(events) - 1; i >= 0; i-- {
		if id := grantSubjectOf(events[i]).RequestID; id != "" {
			return grantEventNames(grantEventsOf(events, id))
		}
	}
	return ""
}

// grantSubjectOf returns the subject of an entry about a request.
func grantSubjectOf(ev audit.Event) audit.Subject {
	switch e := ev.(type) {
	case audit.Request:
		return e.Subject
	case audit.Decision:
		return e.Subject
	case audit.GrantUsed:
		return e.Subject
	case audit.SecretSent:
		return e.Subject
	case audit.Signed:
		return e.Subject
	case audit.Denied:
		return e.Subject
	case audit.Failure:
		return e.Subject
	}
	return audit.Subject{}
}

// grantEventsOf returns the entries of the request id, in order.
func grantEventsOf(events []audit.Event, id string) []audit.Event {
	var out []audit.Event
	for _, ev := range events {
		if grantSubjectOf(ev).RequestID == id {
			out = append(out, ev)
		}
	}
	return out
}

// grantEventNames returns the names of the entries, separated by spaces,
// such as "request grant_used:grant signed".
func grantEventNames(events []audit.Event) string {
	names := make([]string, len(events))
	for i, ev := range events {
		switch e := ev.(type) {
		case audit.Request:
			names[i] = "request"
		case audit.Decision:
			names[i] = "decision:" + string(e.Answer)
		case audit.GrantUsed:
			names[i] = "grant_used:" + string(e.Via)
		case audit.Signed:
			names[i] = "signed"
		case audit.Denied:
			names[i] = "denied:" + string(e.Cause)
		case audit.Failure:
			names[i] = "error:" + string(e.Code)
		default:
			names[i] = fmt.Sprintf("%T", ev)
		}
	}
	return strings.Join(names, " ")
}

// testGranter returns a granter whose broker is b, and whose environment
// is env. It reads no config file. Its clock says noon in UTC.
func testGranter(b *Broker, env []string) granter {
	return granter{
		load: func(string) (*Broker, error) {
			if b == nil {
				return nil, errors.New("this test must not connect to a broker")
			}
			return b, nil
		},
		configPath: func() (string, error) { return "/nonexistent/client.toml", nil },
		environ:    func() []string { return slices.Clone(env) },
		now:        func() time.Time { return noon },
	}
}

// grantIn runs nodkey ssh-grant in the test, with g and ctx, and returns the
// exit code and what it wrote to stderr.
func grantIn(ctx context.Context, g granter, args ...string) (int, string) {
	var stderr bytes.Buffer
	code := g.run(ctx, args, &stderr)
	return code, stderr.String()
}

// grantArgs are the arguments of a request for logins as deploy with the
// key deploy to web-1 and web-2, for 15 minutes, and then extra.
func grantArgs(extra ...string) []string {
	return append([]string{"--key", "deploy", "--user", "deploy", "--host", "web-1", "--host", "web-2",
		"--for", "15m"}, extra...)
}
