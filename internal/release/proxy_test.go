package release

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// Go reads the proxy setting of the environment once per process. So the
// test of the proxy runs the lookup in a child process: the test binary
// again, with TestLatestThroughProxyChild only.

// proxyChildEnv makes TestLatestThroughProxyChild run.
const proxyChildEnv = "NODKEY_TEST_RELEASE_PROXY_CHILD"

// tunnelProxy is a small HTTPS proxy. It keeps what it reads before the
// tunnel, and connects every CONNECT to target.
type tunnelProxy struct {
	target string
	mu     sync.Mutex
	seen   strings.Builder
}

func (p *tunnelProxy) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

func (p *tunnelProxy) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	br := bufio.NewReader(c)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		p.mu.Lock()
		p.seen.WriteString(line)
		p.mu.Unlock()
		if line == "\r\n" {
			break
		}
	}
	var d net.Dialer
	up, err := d.DialContext(context.Background(), "tcp", p.target)
	if err != nil {
		return
	}
	defer func() { _ = up.Close() }()
	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	go func() { _, _ = io.Copy(up, br) }()
	_, _ = io.Copy(c, up)
}

// TestLatestThroughProxyChild runs only as the child of
// TestLatestThroughProxy. The lookup asks https://example.com; the proxy
// connects it to a fake GitHub, whose certificate holds example.com. The
// client may dial only the proxy, so nothing goes to example.com itself.
func TestLatestThroughProxyChild(t *testing.T) {
	if os.Getenv(proxyChildEnv) == "" {
		t.Skip("runs only as the child of TestLatestThroughProxy")
	}
	srv := httptest.NewTLSServer(answer(http.StatusOK, releaseJSON("v0.3.0")))
	defer srv.Close()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	proxy := &tunnelProxy{target: srv.Listener.Addr().String()}
	go proxy.serve(ln)
	// Before the first request: Go reads the setting once.
	t.Setenv("HTTPS_PROXY", "http://proxyuser:proxypass@"+ln.Addr().String())

	c := New(own)
	c.base = "https://example.com"
	tr := c.http.Transport.(*http.Transport)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	tr.TLSClientConfig.RootCAs = pool
	var d net.Dialer
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != ln.Addr().String() {
			return nil, errors.New("the client dialed another address than the proxy")
		}
		return d.DialContext(ctx, network, addr)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	got, err := c.Latest(ctx)
	if err != nil || got != (rel(0, 3, 0)) {
		t.Fatalf("Latest through the proxy: %v, %v", got, err)
	}
	proxy.mu.Lock()
	seen := proxy.seen.String()
	proxy.mu.Unlock()
	// The proxy sees the host, and the user name and the password of the
	// setting, but not the path: it is inside TLS.
	if !strings.HasPrefix(seen, "CONNECT example.com:443 HTTP/1.1\r\n") || strings.Contains(seen, latestPath) {
		t.Errorf("the proxy saw: %q", seen)
	}
}

// TestLatestThroughProxy: the lookup takes the proxy from HTTPS_PROXY, as
// the calls to Telegram do.
func TestLatestThroughProxy(t *testing.T) {
	if os.Getenv(proxyChildEnv) != "" {
		t.Skip("this is the child")
	}
	//nolint:gosec // G204: the test binary itself, with fixed arguments.
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestLatestThroughProxyChild$", "-test.v")
	// No other proxy setting of the test's environment, such as NO_PROXY,
	// may change where the child's call goes.
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); !strings.HasSuffix(strings.ToUpper(name), "_PROXY") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, proxyChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS: TestLatestThroughProxyChild") {
		t.Fatalf("the child: %v\n%s", err, out)
	}
}
