package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/approval/approvaltest"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/broker"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/store"
	"github.com/code6x/nodkey/internal/transport"
)

// The tests run nodkey run against the real broker service (package
// broker) behind the real transport server, with mutual TLS on the
// loopback address, the real approval core, the fake approver and the
// fake clock of package approvaltest, and a store and an audit log in
// memory. Answers that the broker never gives come from a test handler
// behind the same transport server (newFakeBroker).

// approverID is the Telegram user ID of the approver.
const approverID int64 = 123456789

// noon is the start of the fake clock.
var noon = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

// waitLimit bounds every wait of a test.
const waitLimit = 20 * time.Second

// secretsTimeout is the broker's timeout of a request for secrets.
const secretsTimeout = 120 * time.Second

// The item IDs of the test secrets.
const (
	idGitHub = "00000000-0000-0000-0000-000000000001"
	idNPM    = "00000000-0000-0000-0000-000000000002"
)

// madeUpValues are the values that madeUp made, so that safe can hide
// them in the output of a test.
var (
	madeUpMu     sync.Mutex
	madeUpValues []string
)

// madeUp returns a made-up secret value, made at run time, so the source
// holds no value that looks like a token. Each call gives a new one.
func madeUp(what string) string {
	v := "made-up-" + what + "-" + rand.Text()
	madeUpMu.Lock()
	defer madeUpMu.Unlock()
	madeUpValues = append(madeUpValues, v)
	return v
}

// safe returns s with every value of madeUp hidden, as it is and in
// base64. A test prints output only through it, so that a test failure
// never shows a value, even when the value leaked.
func safe(s string) string {
	madeUpMu.Lock()
	defer madeUpMu.Unlock()
	for _, v := range madeUpValues {
		s = strings.ReplaceAll(s, v, "[VALUE]")
		s = strings.ReplaceAll(s, base64.StdEncoding.EncodeToString([]byte(v)), "[VALUE IN BASE64]")
	}
	return s
}

// mustNotLeak fails if a text holds value, as it is or in base64. It
// never prints the value.
func mustNotLeak(t testing.TB, value string, texts ...string) {
	t.Helper()
	b64 := base64.StdEncoding.EncodeToString([]byte(value))
	for i, s := range texts {
		if strings.Contains(s, value) || strings.Contains(s, b64) {
			t.Errorf("text %d holds a secret value: %q", i, safe(s))
		}
	}
}

// lastLine returns the last line of s, without its newline.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	return lines[len(lines)-1]
}

// self returns the path of the test binary. Tests use it as a command
// that exists and can be run.
func self(t testing.TB) string {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// sha256Hex returns the SHA-256 of s in hex.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum)
}

// tlsKey is a TLS key of a test, as nodkey keygen makes it.
type tlsKey struct {
	cert tls.Certificate
	pin  config.Pin
	file []byte // the key file, as nodkey keygen writes it
}

// newTLSKey makes a key file as nodkey keygen does (an Ed25519 key in
// PKCS #8 and a self-signed certificate, as two PEM blocks), and reads it
// with transport.ParseKeyFile, the parser of transport.LoadKeyFile.
// transport.GenerateKeyFile itself refuses the system temporary directory,
// which everyone can write to.
func newTLSKey(t testing.TB) tlsKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "nodkey"},
		NotBefore:             noon.Add(-time.Hour),
		NotAfter:              time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})...)
	cert, err := transport.ParseKeyFile(data)
	if err != nil {
		t.Fatal(err)
	}
	return tlsKey{cert: cert, pin: transport.PinOf(cert.Leaf), file: data}
}

// memAudit is an audit log in memory. Append refuses what the real one
// refuses (audit.CheckEvent).
type memAudit struct {
	mu      sync.Mutex
	events  []audit.Event
	changed chan struct{}
}

func newMemAudit() *memAudit { return &memAudit{changed: make(chan struct{})} }

func (a *memAudit) Append(ev audit.Event) (audit.Anchor, error) {
	if err := audit.CheckEvent(ev); err != nil {
		return audit.Anchor{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	close(a.changed)
	a.changed = make(chan struct{})
	n := uint64(len(a.events))
	return audit.Anchor{Seq: n, Hash: sha256.Sum256(fmt.Appendf(nil, "%d", n))}, nil
}

// all returns the events so far.
func (a *memAudit) all() []audit.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.events)
}

// waitFor waits until the log has at least n events, and returns them.
func (a *memAudit) waitFor(t testing.TB, n int) []audit.Event {
	t.Helper()
	deadline := time.NewTimer(waitLimit)
	defer deadline.Stop()
	for {
		a.mu.Lock()
		events, changed := slices.Clone(a.events), a.changed
		a.mu.Unlock()
		if len(events) >= n {
			return events
		}
		select {
		case <-changed:
		case <-deadline.C:
			t.Fatalf("the audit log has %d entries, want %d: %s", len(events), n, eventNames(events))
			return nil
		}
	}
}

// eventNames returns the names of events, separated by spaces, such as
// "request decision:approve_once secret_sent".
func eventNames(events []audit.Event) string {
	names := make([]string, len(events))
	for i, ev := range events {
		switch e := ev.(type) {
		case audit.Request:
			names[i] = "request"
		case audit.Decision:
			names[i] = "decision:" + string(e.Answer)
		case audit.SecretSent:
			names[i] = "secret_sent"
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

// memStore is a store in memory, with the values that a test sets.
type memStore struct {
	mu      sync.Mutex
	items   map[string]string // by item ID
	err     error
	fetches int
}

func (s *memStore) Start(context.Context) error { return nil }

func (s *memStore) Fetch(_ context.Context, id string) (store.Value, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fetches++
	if s.err != nil {
		return store.Value{}, s.err
	}
	v, ok := s.items[id]
	if !ok {
		return store.Value{}, errors.New("mem store: no such item")
	}
	return store.NewValue([]byte(v)), nil
}

func (s *memStore) Close() {}

// fail makes Fetch fail with err.
func (s *memStore) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

// fetched returns how many times Fetch ran.
func (s *memStore) fetched() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fetches
}

// serve runs handler behind the real transport server, with the broker's
// TLS key key and the clients, on the loopback address, until the test
// ends. It returns the address.
func serve(t *testing.T, key tlsKey, clients map[string]config.Client, handler http.Handler) string {
	t.Helper()
	srv, err := transport.NewServer(key.cert, clients, handler, nil)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.Serve(ln) // it returns an error when it stops
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		<-served
	})
	return ln.Addr().String()
}

// testBroker is a running broker for one test, with one client, laptop,
// and two secrets for it, github-token and npm-token, whose rule is
// "always".
type testBroker struct {
	addr     string
	key      tlsKey // the broker's TLS key
	laptop   tlsKey // the TLS key of the client laptop
	approver *approvaltest.Approver
	clock    *approvaltest.Clock
	audit    *memAudit
	store    *memStore
	values   map[string]string // the value of each secret, by its name
}

func newTestBroker(t *testing.T) *testBroker {
	t.Helper()
	return newTestBrokerWith(t, "")
}

// newTestBrokerWith is newTestBroker for a broker whose version is
// version ("" for none).
func newTestBrokerWith(t *testing.T, version string) *testBroker {
	t.Helper()
	tb := &testBroker{
		key:      newTLSKey(t),
		laptop:   newTLSKey(t),
		approver: approvaltest.NewApprover(approverID),
		clock:    approvaltest.NewClock(noon),
		audit:    newMemAudit(),
		values:   map[string]string{"github-token": madeUp("github"), "npm-token": madeUp("npm")},
	}
	tb.store = &memStore{items: map[string]string{
		idGitHub: tb.values["github-token"],
		idNPM:    tb.values["npm-token"],
	}}
	always := config.Rule{Ask: config.AskAlways}
	cfg := &config.Broker{
		Telegram: config.Telegram{UserID: approverID, NoticeChatID: approverID, Timeout: secretsTimeout,
			SSHTimeout: 90 * time.Second},
		Clients: map[string]config.Client{"laptop": {Name: "laptop", Pin: tb.laptop.pin}},
		Stores:  map[string]config.Store{"main": {Name: "main", Type: config.StoreBWS}},
		Secrets: map[string]config.Secret{
			"github-token": {Name: "github-token", Store: "main", ID: idGitHub, Clients: []string{"laptop"},
				Rule: always},
			"npm-token": {Name: "npm-token", Store: "main", ID: idNPM, Clients: []string{"laptop"}, Rule: always},
		},
	}
	core, err := approval.New(cfg, tb.approver, approval.Options{Clock: tb.clock})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := broker.New(broker.Parts{Config: cfg, Audit: tb.audit,
		Stores: map[string]store.Store{"main": tb.store}, Version: version})
	if err != nil {
		t.Fatal(err)
	}
	tb.addr = serve(t, tb.key, cfg.Clients, svc)
	runCtx, stopRun := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- svc.Run(runCtx, core, nil, nil) }()
	t.Cleanup(func() {
		stopRun()
		select {
		case <-runErr:
		case <-time.After(waitLimit):
			t.Error("Run did not return")
		}
		svc.Close()
	})
	if err := tb.approver.WaitRunning(waitLimit); err != nil {
		t.Fatal(err)
	}
	return tb
}

// client returns a Broker for the client laptop, as Load makes it.
func (tb *testBroker) client(t testing.TB) *Broker {
	t.Helper()
	b, err := newBroker(tb.addr, tb.laptop.cert, tb.key.pin)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// waitAsked waits until the approver was asked for n messages, and returns
// them.
func (tb *testBroker) waitAsked(t testing.TB, n int) []approvaltest.Asked {
	t.Helper()
	asked, err := tb.approver.WaitAsked(n, waitLimit)
	if err != nil {
		t.Fatal(err)
	}
	return asked
}

// fakeBroker answers with a test handler instead of the broker service,
// behind the real transport server with mutual TLS. It counts the
// requests that reach the handler.
type fakeBroker struct {
	b        *Broker // for the client laptop
	requests atomic.Int32
}

func newFakeBroker(t *testing.T, handler http.HandlerFunc) *fakeBroker {
	t.Helper()
	key, laptop := newTLSKey(t), newTLSKey(t)
	fb := &fakeBroker{}
	clients := map[string]config.Client{"laptop": {Name: "laptop", Pin: laptop.pin}}
	addr := serve(t, key, clients, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fb.requests.Add(1)
		handler(w, r)
	}))
	b, err := newBroker(addr, laptop.cert, key.pin)
	if err != nil {
		t.Fatal(err)
	}
	fb.b = b
	return fb
}

// execCall is a command that nodkey run would have started.
type execCall struct {
	path       string
	argv, envv []string
}

// fakeExec takes the place of syscall.Exec in a test: it keeps each call,
// and returns err.
type fakeExec struct {
	mu    sync.Mutex
	calls []execCall
	err   error
}

func (f *fakeExec) exec(path string, argv, envv []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, execCall{path: path, argv: slices.Clone(argv), envv: slices.Clone(envv)})
	return f.err
}

// ran returns the calls so far.
func (f *fakeExec) ran() []execCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// testRunner returns a runner whose broker is b, whose environment is
// env, and whose exec is fx. It reads no config file.
func testRunner(b *Broker, env []string, fx *fakeExec) runner {
	return runner{
		load: func(string) (*Broker, error) {
			if b == nil {
				return nil, errors.New("this test must not connect to a broker")
			}
			return b, nil
		},
		configPath: func() (string, error) { return "/nonexistent/client.toml", nil },
		environ:    func() []string { return slices.Clone(env) },
		exec:       fx.exec,
		// The test process must stay dumpable; TestRunNotDumpable checks
		// the real one in a child process.
		notDumpable: func() error { return nil },
	}
}

// runIn runs nodkey run in the test, with r and ctx, and returns the exit
// code and what it wrote to stderr.
func runIn(ctx context.Context, r runner, args ...string) (int, string) {
	var stderr bytes.Buffer
	code := r.run(ctx, args, &stderr, func() {})
	return code, stderr.String()
}
