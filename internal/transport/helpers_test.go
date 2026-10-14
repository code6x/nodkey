package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/config"
)

// testKey is a key that a test made, with its key file content.
type testKey struct {
	cert tls.Certificate
	pin  config.Pin
	file []byte // the key file, as nodkey keygen writes it
}

// newTestKey makes a new key the way nodkey keygen does.
func newTestKey(t testing.TB) testKey {
	t.Helper()
	data, pin, err := newKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ParseKeyFile(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := PinOf(cert.Leaf); got != pin {
		t.Fatalf("the pin of the parsed key is %s, newKeyFile said %s", got, pin)
	}
	return testKey{cert: cert, pin: pin, file: data}
}

// privateKey returns the private key of k.
func (k testKey) privateKey(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	priv, ok := k.cert.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("not an Ed25519 key")
	}
	return priv
}

// certFor makes a self-signed certificate for the key priv, changed by
// edit, and returns it with priv as a tls.Certificate.
func certFor(t testing.TB, priv ed25519.PrivateKey, edit func(*x509.Certificate)) tls.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "nodkey"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if edit != nil {
		edit(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}
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

// testBroker is a broker server on the loopback address.
type testBroker struct {
	addr  string
	key   testKey
	srv   *Server
	logs  *syncBuffer
	calls atomic.Int32 // requests that reached the handler
}

// whoAmI is the answer of the test handler: the client name it got.
type whoAmI struct {
	Client string `json:"client"`
}

// startBroker starts a broker with the key and the clients. Its handler
// counts its calls and answers with the client name from ClientName. edit,
// if not nil, may change the server before it starts.
func startBroker(t *testing.T, key testKey, clients map[string]config.Client, edit func(*Server)) *testBroker {
	t.Helper()
	b := &testBroker{key: key}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.calls.Add(1)
		name, ok := ClientName(r.Context())
		if !ok {
			WriteError(w, http.StatusForbidden)
			return
		}
		if err := WriteJSON(w, http.StatusOK, whoAmI{Client: name}); err != nil {
			t.Errorf("WriteJSON: %v", err)
		}
	})
	return b.start(t, clients, handler, edit)
}

// start starts b with handler.
func (b *testBroker) start(t *testing.T, clients map[string]config.Client, handler http.Handler,
	edit func(*Server),
) *testBroker {
	t.Helper()
	b.logs = new(syncBuffer)
	logger := slog.New(slog.NewTextHandler(b.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv, err := NewServer(b.key.cert, clients, handler, logger)
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(srv)
	}
	b.srv = srv
	b.addr = listenAndServe(t, srv.Serve, func() { _ = srv.Close() })
	return b
}

// listenAndServe listens on a free loopback port and runs serve on it.
// At the end of the test it calls stop, closes the listener, and waits for
// serve to return. It returns the address.
func listenAndServe(t *testing.T, serve func(net.Listener) error, stop func()) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = serve(ln) // it returns an error when it stops
	}()
	t.Cleanup(func() {
		stop()
		_ = ln.Close() // serve may have closed it already
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("the server did not stop")
		}
	})
	return ln.Addr().String()
}

// clientTable returns a client table with one client per name.
func clientTable(pins map[string]config.Pin) map[string]config.Client {
	m := make(map[string]config.Client, len(pins))
	for name, pin := range pins {
		m[name] = config.Client{Name: name, Pin: pin}
	}
	return m
}

// newTestClient returns the HTTP client of NewClient for the broker b.
func newTestClient(t *testing.T, b *testBroker, key testKey, brokerPin config.Pin) *http.Client {
	t.Helper()
	c, err := NewClient(b.addr, key.cert, brokerPin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	return c
}

// clientWith returns an HTTP client with its own TLS config, for tests that
// act as a hostile or broken client. Each request uses a new connection.
func clientWith(t *testing.T, cfg *tls.Config) *http.Client {
	t.Helper()
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	tr := &http.Transport{
		Proxy:             nil,
		TLSClientConfig:   cfg,
		DisableKeepAlives: true,
		Protocols:         &protocols,
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr}
}

// ask sends a request to the test handler and returns the client name it
// answered with. An error means that the request failed, for example
// because the TLS handshake was refused.
func ask(t *testing.T, c *http.Client, addr string) (string, error) {
	t.Helper()
	name, _, err := askState(t, c, addr, nil)
	return name, err
}

// askState is ask that also returns the TLS state of the connection. edit,
// if not nil, may change the request before it is sent.
func askState(t *testing.T, c *http.Client, addr string, edit func(*http.Request)) (string, *tls.ConnectionState, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+addr+"/whoami", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if edit != nil {
		edit(req)
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return "", resp.TLS, &statusError{resp.StatusCode, string(body)}
	}
	var got whoAmI
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("answer %q: %v", body, err)
	}
	return got.Client, resp.TLS, nil
}

// statusError is the error of askState for an answer that is not 200.
type statusError struct {
	status int
	body   string
}

func (e *statusError) Error() string {
	return http.StatusText(e.status) + ": " + e.body
}

// mustRefuse checks that err is an error that holds want, and that the
// handler of b was not called.
func mustRefuse(t *testing.T, b *testBroker, err error, want string) {
	t.Helper()
	switch {
	case err == nil:
		t.Errorf("the request went through, want an error with %q", want)
	case !strings.Contains(err.Error(), want):
		t.Errorf("error = %q, want one with %q", err, want)
	}
	if n := b.calls.Load(); n != 0 {
		t.Errorf("the handler ran %d times, want 0", n)
	}
}

// checkNoKeyMaterial fails if text holds a part of a private key of keys:
// a line of the PEM block of the private key, or the key in base64 or hex.
func checkNoKeyMaterial(t *testing.T, what, text string, keys ...testKey) {
	t.Helper()
	for _, k := range keys {
		var block *pem.Block
		for rest := k.file; ; {
			block, rest = pem.Decode(rest)
			if block == nil {
				t.Fatal("the key file has no private key")
			}
			if block.Type == pemPrivateKey {
				break
			}
		}
		// Every Ed25519 key in PKCS #8 form starts with the same 16 bytes
		// (about 21 base64 characters), so the first 32 are skipped.
		encoded := base64.StdEncoding.EncodeToString(block.Bytes)
		for i := 32; i+16 <= len(encoded); i += 16 {
			if strings.Contains(text, encoded[i:i+16]) {
				t.Errorf("%s holds a part of a private key in base64", what)
				break
			}
		}
		seed := k.privateKey(t).Seed()
		for _, s := range []string{
			base64.StdEncoding.EncodeToString(seed)[:16],
			base64.RawURLEncoding.EncodeToString(seed)[:16],
			hex.EncodeToString(seed)[:16],
			string(seed[:8]),
		} {
			if strings.Contains(text, s) {
				t.Errorf("%s holds a part of a private key", what)
			}
		}
	}
}

// discardLog returns a logger for an http.Server that drops everything,
// so a test server does not write to stderr.
func discardLog() *log.Logger {
	return log.New(io.Discard, "", 0)
}

// readFile reads a file that the test made.
func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: tests read only files that they made in their own temporary directory.
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// mkdirMode makes the directory dir/name with exactly mode, and returns
// its path.
func mkdirMode(t *testing.T, dir, name string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	// Mkdir applies the umask; set the exact mode.
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// waitForLog waits until the broker's log holds want, and returns the log.
// The server logs a refused handshake in its own goroutine, which may run
// after the client has seen the refusal.
func waitForLog(t *testing.T, b *testBroker, want string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		logs := b.logs.String()
		if strings.Contains(logs, want) {
			return logs
		}
		if time.Now().After(deadline) {
			t.Errorf("the broker's log does not hold %q:\n%s", want, logs)
			return logs
		}
		time.Sleep(10 * time.Millisecond)
	}
}
