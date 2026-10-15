package broker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/approval/approvaltest"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/sshauth"
	"github.com/code6x/nodkey/internal/store"
	"github.com/code6x/nodkey/internal/transport"
)

// The tests run the Service behind the real transport server, with mutual
// TLS on the loopback address, the real approval core with the fake
// approver and the fake clock of package approvaltest, fake stores, and an
// audit log in memory that refuses exactly what audit.Logger.Append
// refuses (audit.CheckEvent).

// approverID is the Telegram user ID of the approver.
const approverID int64 = 123456789

// noon is the start of the fake clock.
var noon = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

// waitLimit bounds every wait of a test.
const waitLimit = 20 * time.Second

// madeUp returns a made-up secret value, made at run time, so the source
// holds no value that looks like a token.
func madeUp(what string) string {
	return "made-up-" + what + "-" + rand.Text()
}

// canary returns a made-up secret, made at run time: 32 upper-case
// letters and digits that change often. It is a valid variable name, and
// package claim masks it in every form, as a random-looking word.
func canary() string {
	const letters = "QWERTYUPASDFGHJKLZXCVBNM"
	const digits = "7391542860"
	var b strings.Builder
	for i := range 16 {
		b.WriteByte(letters[(i*7+3)%len(letters)])
		b.WriteByte(digits[(i*3+1)%len(digits)])
	}
	return b.String()
}

// tlsKey is a TLS key of a test, as nodkey keygen makes it.
type tlsKey struct {
	cert tls.Certificate
	pin  config.Pin
}

// newTLSKey makes a key file the way nodkey keygen does (an Ed25519 key
// in PKCS #8 and a self-signed certificate, as two PEM blocks), and reads
// it with transport.ParseKeyFile, the parser of transport.LoadKeyFile.
// transport.GenerateKeyFile itself refuses the system temporary directory,
// which everyone can write to. commonName, if set, goes into the
// certificate.
func newTLSKey(t testing.TB, commonName string) tlsKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if commonName == "" {
		commonName = "nodkey"
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
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
	return tlsKey{cert: cert, pin: transport.PinOf(cert.Leaf)}
}

// syncBuffer is a bytes.Buffer that many goroutines may use.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// fakeAudit is an audit log in memory. Append refuses what the real one
// refuses (audit.CheckEvent), and can fail or wait on command. After a
// failure that holds audit.ErrBroken, every Append fails, as with the
// real log.
type fakeAudit struct {
	mu      sync.Mutex
	events  []audit.Event
	failOn  func(audit.Event) error // if set, Append fails with its error
	broken  error
	gate    chan struct{} // if set, Append waits until it is closed
	gated   chan struct{} // gets a value when an Append starts to wait at the gate
	panicOn func(audit.Event) bool
	changed chan struct{}
}

func newFakeAudit() *fakeAudit {
	return &fakeAudit{changed: make(chan struct{}), gated: make(chan struct{}, 64)}
}

func (f *fakeAudit) Append(ev audit.Event) (audit.Anchor, error) {
	f.mu.Lock()
	gate := f.gate
	f.mu.Unlock()
	if gate != nil {
		select {
		case f.gated <- struct{}{}:
		default:
		}
		<-gate
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.panicOn != nil && f.panicOn(ev) {
		panic("fake audit: a panic on purpose")
	}
	if f.broken != nil {
		return audit.Anchor{}, f.broken
	}
	if f.failOn != nil {
		if err := f.failOn(ev); err != nil {
			if errors.Is(err, audit.ErrBroken) {
				f.broken = err
			}
			return audit.Anchor{}, err
		}
	}
	if err := audit.CheckEvent(ev); err != nil {
		return audit.Anchor{}, err
	}
	f.events = append(f.events, ev)
	close(f.changed)
	f.changed = make(chan struct{})
	n := uint64(len(f.events))
	return audit.Anchor{Seq: n, Hash: sha256.Sum256(fmt.Appendf(nil, "%d", n))}, nil
}

// setFail makes Append fail with the error of fail, or not at all for nil.
func (f *fakeAudit) setFail(fail func(audit.Event) error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failOn = fail
}

// all returns the events so far.
func (f *fakeAudit) all() []audit.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.events)
}

// waitFor waits until the log has at least n events, and returns them.
func (f *fakeAudit) waitFor(t testing.TB, n int) []audit.Event {
	t.Helper()
	deadline := time.NewTimer(waitLimit)
	defer deadline.Stop()
	for {
		f.mu.Lock()
		events, changed := slices.Clone(f.events), f.changed
		f.mu.Unlock()
		if len(events) >= n {
			return events
		}
		select {
		case <-changed:
		case <-deadline.C:
			t.Fatalf("the audit log has %d entries, want at least %d: %s", len(events), n, eventNames(events))
			return nil
		}
	}
}

// eventName returns the name of an event, as in the "event" field.
func eventName(ev audit.Event) string {
	switch e := ev.(type) {
	case audit.Request:
		return "request"
	case audit.Decision:
		return "decision:" + string(e.Answer)
	case audit.GrantUsed:
		return "grant_used:" + string(e.Via)
	case audit.SecretSent:
		return "secret_sent"
	case audit.Signed:
		return "signed"
	case audit.Denied:
		return "denied:" + string(e.Cause)
	case audit.Failure:
		return "error:" + string(e.Code)
	case audit.ForeignTap:
		return "foreign_tap:" + string(e.Cause)
	}
	return fmt.Sprintf("%T", ev)
}

// eventNames returns the names of events, separated by spaces.
func eventNames(events []audit.Event) string {
	names := make([]string, len(events))
	for i, ev := range events {
		names[i] = eventName(ev)
	}
	return strings.Join(names, " ")
}

// subjectOf returns the subject of an event about a request.
func subjectOf(ev audit.Event) audit.Subject {
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

// fakeStore is a store whose values a test sets. It keeps the bytes of
// each value it hands out, so a test can check that the broker cleared
// them.
type fakeStore struct {
	mu      sync.Mutex
	items   map[string]string // by item ID
	err     error
	panic   string // if set, Fetch panics with it
	block   bool   // Fetch waits until its context ends
	fetches int
	given   [][]byte
	started chan struct{} // gets a value when a Fetch starts
}

func newFakeStore() *fakeStore {
	return &fakeStore{items: make(map[string]string), started: make(chan struct{}, 64)}
}

func (f *fakeStore) Start(context.Context) error { return nil }

func (f *fakeStore) Fetch(ctx context.Context, id string) (store.Value, error) {
	f.mu.Lock()
	f.fetches++
	p, err, block := f.panic, f.err, f.block
	value, ok := f.items[id]
	f.mu.Unlock()
	select {
	case f.started <- struct{}{}:
	default:
	}
	switch {
	case p != "":
		panic(p)
	case err != nil:
		return store.Value{}, err
	case block:
		<-ctx.Done()
		return store.Value{}, ctx.Err()
	case !ok:
		return store.Value{}, errors.New("fake store: no such item")
	}
	b := []byte(value)
	f.mu.Lock()
	f.given = append(f.given, b)
	f.mu.Unlock()
	return store.NewValue(b), nil
}

func (f *fakeStore) Close() {}

// set changes the store under its lock, after the broker started.
func (f *fakeStore) set(change func(*fakeStore)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

// fetched returns how many times Fetch ran.
func (f *fakeStore) fetched() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetches
}

// checkCleared fails if a value that the store handed out was not cleared.
func (f *fakeStore) checkCleared(t testing.TB) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, b := range f.given {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Error("a fetched value was not cleared")
		}
	}
}

// The item IDs of the test secrets.
const (
	idGitHub = "00000000-0000-0000-0000-000000000001"
	idNPM    = "00000000-0000-0000-0000-000000000002"
	idDB     = "00000000-0000-0000-0000-000000000003"
	idBackup = "00000000-0000-0000-0000-000000000004"
)

// env is a running broker for one test.
type env struct {
	t        *testing.T
	cfg      *config.Broker
	clock    *approvaltest.Clock
	approver *approvaltest.Approver
	core     *approval.Core
	audit    *fakeAudit
	main     *fakeStore // bws-like store "main"
	vault    *fakeStore // bw-like store "vault"
	values   map[string]string
	svc      *Service
	logs     *syncBuffer // the broker's log, from NewLogger
	srvLogs  *syncBuffer // the transport server's log
	addr     string
	broker   tlsKey
	clients  map[string]tlsKey // laptop, ci
	userKeys map[string]ssh.Signer
	hosts    map[string]ssh.AlgorithmSigner // web-1, web-2, db-1
	alerts   *syncBuffer
	runErr   chan error
	stopRun  context.CancelFunc
}

// envOptions change the environment before it starts.
type envOptions struct {
	// config changes the config.
	config func(*config.Broker)
	// noRun leaves Run out.
	noRun bool
	// wrap, if set, wraps the Service before it goes to the server.
	wrap func(http.Handler) http.Handler
}

// newEnv starts a broker with this config:
//
//   - clients laptop and ci;
//   - secrets github-token (window 15m, laptop), npm-token (window 5m,
//     laptop), db-password (always, laptop, in the store vault), and
//     backup-token (never, with a notice, ci);
//   - keys deploy (window 15m, laptop, any host), web (window 15m, laptop,
//     web-1 and web-2), admin (always, laptop, web-1) and backup (never,
//     ci, web-1 only);
//   - hosts web-1, web-2 and db-1 in known_hosts.
func newEnv(t *testing.T, opts envOptions) *env {
	t.Helper()
	e := &env{
		t:        t,
		clock:    approvaltest.NewClock(noon),
		approver: approvaltest.NewApprover(approverID),
		audit:    newFakeAudit(),
		main:     newFakeStore(),
		vault:    newFakeStore(),
		logs:     new(syncBuffer),
		srvLogs:  new(syncBuffer),
		alerts:   new(syncBuffer),
		broker:   newTLSKey(t, ""),
		clients:  map[string]tlsKey{"laptop": newTLSKey(t, ""), "ci": newTLSKey(t, "")},
		userKeys: make(map[string]ssh.Signer),
		hosts:    make(map[string]ssh.AlgorithmSigner),
		values: map[string]string{
			"github-token": madeUp("github"), "npm-token": madeUp("npm"),
			"db-password": madeUp("db"), "backup-token": madeUp("backup"),
		},
		runErr: make(chan error, 1),
	}
	e.main.items[idGitHub] = e.values["github-token"]
	e.main.items[idNPM] = e.values["npm-token"]
	e.main.items[idBackup] = e.values["backup-token"]
	e.vault.items[idDB] = e.values["db-password"]

	var kh strings.Builder
	for _, name := range []string{"web-1", "web-2", "db-1"} {
		e.hosts[name] = newHostKey(t)
		kh.WriteString(name + " " + string(ssh.MarshalAuthorizedKey(e.hosts[name].PublicKey())))
	}
	known, err := config.ParseKnownHosts([]byte(kh.String()))
	if err != nil {
		t.Fatal(err)
	}
	window := func(d time.Duration) config.Rule { return config.Rule{Ask: config.AskWindow, Window: d} }
	e.cfg = &config.Broker{
		Telegram: config.Telegram{UserID: approverID, NoticeChatID: approverID, Timeout: 120 * time.Second,
			SSHTimeout: 90 * time.Second},
		Clients: map[string]config.Client{
			"laptop": {Name: "laptop", Pin: e.clients["laptop"].pin},
			"ci":     {Name: "ci", Pin: e.clients["ci"].pin},
		},
		Stores: map[string]config.Store{
			"main":  {Name: "main", Type: config.StoreBWS},
			"vault": {Name: "vault", Type: config.StoreBW},
		},
		Secrets: map[string]config.Secret{
			"github-token": {Name: "github-token", Store: "main", ID: idGitHub, Clients: []string{"laptop"},
				Rule: window(15 * time.Minute)},
			"npm-token": {Name: "npm-token", Store: "main", ID: idNPM, Clients: []string{"laptop"},
				Rule: window(5 * time.Minute)},
			"db-password": {Name: "db-password", Store: "vault", ID: idDB, Clients: []string{"laptop"},
				Rule: config.Rule{Ask: config.AskAlways}},
			"backup-token": {Name: "backup-token", Store: "main", ID: idBackup, Clients: []string{"ci"},
				Rule: config.Rule{Ask: config.AskNever, Notify: true}},
		},
		Keys: map[string]config.Key{
			"deploy": {Name: "deploy", Clients: []string{"laptop"}, Rule: window(15 * time.Minute)},
			"web": {Name: "web", Clients: []string{"laptop"}, Rule: window(15 * time.Minute),
				Hosts: []string{"web-1", "web-2"}},
			"admin": {Name: "admin", Clients: []string{"laptop"}, Rule: config.Rule{Ask: config.AskAlways},
				Hosts: []string{"web-1"}},
			"backup": {Name: "backup", Clients: []string{"ci"}, Rule: config.Rule{Ask: config.AskNever, Notify: true},
				Hosts: []string{"web-1"}},
		},
		KnownHosts: known,
	}
	if opts.config != nil {
		opts.config(e.cfg)
	}
	keys := make(map[string]sshauth.Key)
	for name, k := range e.cfg.Keys {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, err := sshauth.NewKey(name, priv, k.Hosts)
		if err != nil {
			t.Fatal(err)
		}
		keys[name] = key
		signer, err := ssh.NewSignerFromSigner(priv)
		if err != nil {
			t.Fatal(err)
		}
		e.userKeys[name] = signer
	}
	core, err := approval.New(e.cfg, e.approver, approval.Options{Clock: e.clock})
	if err != nil {
		t.Fatal(err)
	}
	e.core = core
	svc, err := New(Parts{
		Config: e.cfg,
		Audit:  e.audit,
		Stores: map[string]store.Store{"main": e.main, "vault": e.vault},
		Keys:   keys,
		Logger: NewLogger(e.logs),
	})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	var handler http.Handler = svc
	if opts.wrap != nil {
		handler = opts.wrap(svc)
	}
	srv, err := transport.NewServer(e.broker.cert, e.cfg.Clients, handler, NewLogger(e.srvLogs))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e.addr = ln.Addr().String()
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.Serve(ln) // it returns an error when it stops
	}()
	runCtx, stopRun := context.WithCancel(context.Background())
	e.stopRun = stopRun
	if !opts.noRun {
		e.startRun(runCtx)
	}
	t.Cleanup(func() {
		stopRun()
		if !opts.noRun {
			select {
			case <-e.runErr:
			case <-time.After(waitLimit):
				t.Error("Run did not return")
			}
		}
		closed := make(chan struct{})
		go func() {
			svc.Close()
			close(closed)
		}()
		select {
		case <-closed:
		case <-time.After(waitLimit):
			t.Error("Close did not return")
		}
		_ = srv.Close()
		<-served
	})
	return e
}

// waitIdle waits until the Service works on no request of client. A
// client sees its own hang-up before the broker does.
func (s *Service) waitIdle(t testing.TB, client string) {
	t.Helper()
	deadline := time.Now().Add(waitLimit)
	for {
		s.mu.Lock()
		n := s.inflight[client]
		s.mu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the broker still works on %d requests of %s", n, client)
		}
		time.Sleep(time.Millisecond)
	}
}

// requestContexts returns a wrap for envOptions that sends the context of
// each request to the channel, so a test can wait until the server has
// seen a client hang up.
func requestContexts() (func(http.Handler) http.Handler, chan context.Context) {
	ch := make(chan context.Context, 16)
	wrap := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ch <- r.Context()
			next.ServeHTTP(w, r)
		})
	}
	return wrap, ch
}

// setMaxPerClient changes the cap of requests in progress per client.
func (s *Service) setMaxPerClient(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxPerClient = n
}

// startRun runs the Service with the core until ctx ends.
func (e *env) startRun(ctx context.Context) {
	alert := func(_ context.Context, msg string) error {
		_, err := e.alerts.Write([]byte(msg + "\n"))
		return err
	}
	go func() { e.runErr <- e.svc.Run(ctx, e.core, alert) }()
	if err := e.approver.WaitRunning(waitLimit); err != nil {
		e.t.Fatal(err)
	}
}

// newHostKey makes an Ed25519 SSH host key.
func newHostKey(t testing.TB) ssh.AlgorithmSigner {
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
	return as
}

// result is what a client got for a request.
type result struct {
	status int
	body   []byte
	code   string // the short code of the 102 Processing answer, if one came
	err    error  // a transport error, such as a dropped connection
}

// httpClient returns the client of transport.NewClient for a client name.
func (e *env) httpClient(name string) *http.Client {
	e.t.Helper()
	k, ok := e.clients[name]
	if !ok {
		e.t.Fatalf("no client %q", name)
	}
	c, err := transport.NewClient(e.addr, k.cert, e.broker.pin)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(c.CloseIdleConnections)
	return c
}

// post sends body as JSON to path as the client name, and returns what it
// got. It does not fail the test, so it may run in its own goroutine.
func (e *env) post(ctx context.Context, c *http.Client, path string, body any) *result {
	data, err := json.Marshal(body)
	if err != nil {
		return &result{err: err}
	}
	return e.postRaw(ctx, c, path, data)
}

// postRaw sends data as the body of a request to path.
func (e *env) postRaw(ctx context.Context, c *http.Client, path string, data []byte) *result {
	return e.postCode(ctx, c, path, data, nil)
}

// postCode is postRaw that also passes the short code to onCode when it
// comes, while the request waits.
func (e *env) postCode(ctx context.Context, c *http.Client, path string, data []byte, onCode func(string)) *result {
	var mu sync.Mutex
	res := &result{}
	ctx, cancel := context.WithTimeout(ctx, 2*waitLimit)
	defer cancel()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		Got1xxResponse: func(status int, h textproto.MIMEHeader) error {
			if code, ok := api.ShortCode(status, h); ok {
				mu.Lock()
				res.code = code
				mu.Unlock()
				if onCode != nil {
					onCode(code)
				}
			}
			return nil
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+e.addr+path, bytes.NewReader(data))
	if err != nil {
		return &result{err: err}
	}
	req.Header.Set("Content-Type", api.ContentType)
	resp, err := c.Do(req)
	mu.Lock()
	defer mu.Unlock()
	if err != nil {
		res.err = err
		return res
	}
	defer func() { _ = resp.Body.Close() }()
	res.status = resp.StatusCode
	res.body, res.err = io.ReadAll(io.LimitReader(resp.Body, api.MaxAnswer+1))
	return res
}

// pendingResult is a request that runs in its own goroutine.
type pendingResult struct {
	done   chan *result
	code   chan string // gets the short code when it comes
	cancel context.CancelFunc
}

// start sends a request in its own goroutine.
func (e *env) start(c *http.Client, path string, body any) *pendingResult {
	e.t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		e.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(e.t.Context())
	p := &pendingResult{done: make(chan *result, 1), code: make(chan string, 1), cancel: cancel}
	go func() {
		p.done <- e.postCode(ctx, c, path, data, func(code string) {
			select {
			case p.code <- code:
			default:
			}
		})
	}()
	return p
}

// waitCode waits for the short code of the request.
func (p *pendingResult) waitCode(t testing.TB) string {
	t.Helper()
	select {
	case code := <-p.code:
		return code
	case <-time.After(waitLimit):
		t.Fatal("no short code")
		return ""
	}
}

// wait waits for the result.
func (p *pendingResult) wait(t testing.TB) *result {
	t.Helper()
	select {
	case r := <-p.done:
		p.cancel()
		return r
	case <-time.After(2 * waitLimit):
		t.Fatal("the request did not end")
		return nil
	}
}

// secretsRequest returns a request of one variable for the secret name.
func secretsRequest(variable, name string) api.SecretsRequest {
	return api.SecretsRequest{
		Secrets: []api.SecretRef{{Var: variable, Name: name}},
		Command: []string{"gh", "release", "create", "v1.2.0"},
		Dir:     "/home/dev/src/app",
		Reason:  "publish the release the user asked for",
	}
}

// mustStatus fails unless res has the status.
func mustStatus(t testing.TB, res *result, status int) {
	t.Helper()
	if res.err != nil {
		t.Fatalf("the request failed: %v; want status %d", res.err, status)
	}
	if res.status != status {
		t.Fatalf("status %d (%s), want %d", res.status, res.body, status)
	}
}

// secretsOf decodes the answer of a request for secrets.
func secretsOf(t testing.TB, res *result) map[string]string {
	t.Helper()
	mustStatus(t, res, http.StatusOK)
	ans, err := api.ReadAnswer[api.SecretsAnswer](bytes.NewReader(res.body))
	if err != nil {
		t.Fatalf("the answer: %v", err)
	}
	m := make(map[string]string, len(ans.Secrets))
	for _, s := range ans.Secrets {
		m[s.Var] = string(s.Value)
	}
	return m
}

// waitAsked waits until the approver was asked for n messages.
func (e *env) waitAsked(n int) []approvaltest.Asked {
	e.t.Helper()
	asked, err := e.approver.WaitAsked(n, waitLimit)
	if err != nil {
		e.t.Fatal(err)
	}
	return asked
}

// tap presses a button on the message of the request id.
func (e *env) tap(id string, action audit.Answer) {
	e.t.Helper()
	if err := e.approver.Tap(id, action); err != nil {
		e.t.Fatalf("tap %s: %v", action, err)
	}
}

// requestEvents returns the events of the request id, in order.
func requestEvents(events []audit.Event, id string) []audit.Event {
	var out []audit.Event
	for _, ev := range events {
		if subjectOf(ev).RequestID == id {
			out = append(out, ev)
		}
	}
	return out
}

// mustEvents fails unless the names of events are want.
func mustEvents(t testing.TB, events []audit.Event, want string) {
	t.Helper()
	if got := eventNames(events); got != want {
		t.Errorf("audit entries: %s\nwant: %s", got, want)
	}
}

// lastRequestID returns the request ID of the last event about a request.
func lastRequestID(t testing.TB, events []audit.Event) string {
	t.Helper()
	for i := len(events) - 1; i >= 0; i-- {
		if id := subjectOf(events[i]).RequestID; id != "" {
			return id
		}
	}
	t.Fatal("no event about a request")
	return ""
}

// encodeEvents returns the events as JSON, as the audit log holds them.
func encodeEvents(t testing.TB, events []audit.Event) string {
	t.Helper()
	var b strings.Builder
	for _, ev := range events {
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(ev); err != nil {
			t.Fatal(err)
		}
	}
	return b.String()
}

// approverTexts returns everything the fake approver was asked to show.
func (e *env) approverTexts() string {
	var b strings.Builder
	for _, a := range e.approver.Asked() {
		fmt.Fprintf(&b, "%s\n%+v\n", a.Text, a.Prompt)
	}
	for _, x := range e.approver.Ended() {
		fmt.Fprintf(&b, "%+v\n", x.Prompt)
	}
	for _, p := range e.approver.Notices() {
		fmt.Fprintf(&b, "%s\n%+v\n", approvaltest.Text(p), p)
	}
	return b.String()
}

// rawRequest sends text on a new TLS connection as the client name, and
// returns the status of the answer.
func (e *env) rawRequest(name, text string) int {
	e.t.Helper()
	d := tls.Dialer{Config: transport.ClientTLSConfig(e.clients[name].cert, e.broker.pin)}
	conn, err := d.DialContext(e.t.Context(), "tcp", e.addr)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, text); err != nil {
		e.t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(waitLimit))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		e.t.Fatalf("the answer to %q: %v", strings.SplitN(text, "\r\n", 2)[0], err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}
