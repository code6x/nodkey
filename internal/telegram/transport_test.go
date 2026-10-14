package telegram

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
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

// Go reads GODEBUG and the proxy setting of the environment once per
// process. So these tests run the client in a child process: the test
// binary again, with TestHTTPClientChild only.

// childEnv names the variable that makes TestHTTPClientChild run, and
// says what it does.
const childEnv = "NODKEY_TEST_HTTP_CHILD"

// connectProxy is a small HTTPS proxy: it keeps what it reads before the
// tunnel, and connects every CONNECT to target.
type connectProxy struct {
	target string
	mu     sync.Mutex
	seen   strings.Builder
}

func (p *connectProxy) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

func (p *connectProxy) handle(c net.Conn) {
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

// childReport is what the child tells the parent, in a test log line.
type childReport struct {
	Protos    []string `json:"protos"`
	ProxySaw  string   `json:"proxy_saw"`
	ProxyAddr string   `json:"proxy_addr"`
	AskErr    string   `json:"ask_err"`
	ControlOK bool     `json:"control_ok"`
}

// TestHTTPClientChild runs only as the child of
// TestHTTPClientDebugAndProxy.
func TestHTTPClientChild(t *testing.T) {
	mode := os.Getenv(childEnv)
	if mode == "" {
		t.Skip("runs only as the child of TestHTTPClientDebugAndProxy")
	}
	token := os.Getenv("NODKEY_TEST_HTTP_TOKEN")
	var mu sync.Mutex
	var protos []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		protos = append(protos, r.Proto)
		mu.Unlock()
		if !strings.HasPrefix(r.URL.Path, "/bot"+token+"/") {
			writeBody(w, 401, `{"ok":false,"error_code":401,"description":"Unauthorized"}`)
			return
		}
		writeBody(w, 200, `{"ok":true,"result":{"message_id":5,"date":1,"chat":{"id":7000001,"type":"private"}}}`)
	}))
	srv.EnableHTTP2 = true // the server offers HTTP/2, as the Bot API does
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	rep := childReport{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	switch mode {
	case "control":
		// Go's default client speaks HTTP/2, and http2debug prints the path.
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig.RootCAs = pool
		tr.Proxy = nil
		// The token comes from the parent test, and srv is local.
		//nolint:gosec // G704: the URL is the local test server.
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/bot"+token+"/getMe", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := (&http.Client{Transport: tr}).Do(req) //nolint:gosec // G704: the URL is the local test server.
		if err == nil {
			_ = resp.Body.Close()
			rep.ControlOK = resp.ProtoMajor == 2
		}
	case "approver":
		ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ln.Close() }()
		rep.ProxyAddr = ln.Addr().String()
		proxy := &connectProxy{target: srv.Listener.Addr().String()}
		go proxy.serve(ln)
		// Before the first request: Go reads the setting once.
		t.Setenv("HTTPS_PROXY", "http://proxyuser:proxypass@"+ln.Addr().String())
		read := func(string) ([]byte, error) { return []byte(token), nil }
		logger := slog.New(slog.NewTextHandler(t.Output(), nil))
		// The proxy connects example.com to srv, whose certificate holds
		// example.com. Nothing goes to example.com itself.
		a, err := newApprover(testTelegramConfig(), Options{Logger: logger}, read, "https://example.com")
		if err != nil {
			t.Fatal(err)
		}
		a.api.http.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
		if _, err := a.Ask(ctx, secretsPrompt()); err != nil {
			rep.AskErr = err.Error()
		}
		proxy.mu.Lock()
		rep.ProxySaw = proxy.seen.String()
		proxy.mu.Unlock()
	}
	mu.Lock()
	rep.Protos = protos
	mu.Unlock()
	out, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("REPORT " + string(out))
}

// TestHTTPClientDebugAndProxy runs the client with GODEBUG=http2debug=2
// against a server that offers HTTP/2, and through an HTTPS proxy whose
// setting holds a user name and a password. The client must speak
// HTTP/1.1, so the debug output never holds the token; the proxy must see
// only the host; and the approver must log the proxy's host, never its
// password. A control run with Go's default HTTP/2 client shows that the
// debug output would hold the token.
func TestHTTPClientDebugAndProxy(t *testing.T) {
	if os.Getenv(childEnv) != "" {
		t.Skip("this is the child")
	}
	token := newCanaryToken(t)
	secret := token[strings.IndexByte(token, ':')+1:]
	run := func(mode string) (string, childReport) {
		t.Helper()
		//nolint:gosec // G204: the test binary itself, with fixed arguments.
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestHTTPClientChild$", "-test.v")
		cmd.Env = append(os.Environ(), "GODEBUG=http2debug=2", childEnv+"="+mode, "NODKEY_TEST_HTTP_TOKEN="+token)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("the child (%s) failed: %v", mode, err) // its output may hold the token
		}
		var rep childReport
		for _, l := range strings.Split(string(out), "\n") {
			if i := strings.Index(l, "REPORT "); i >= 0 {
				if err := json.Unmarshal([]byte(l[i+len("REPORT "):]), &rep); err != nil {
					t.Fatal(err)
				}
			}
		}
		return string(out), rep
	}

	out, rep := run("control")
	if !rep.ControlOK || !strings.Contains(out, secret) {
		t.Errorf("control: HTTP/2 %v, token in the debug output %v; the check would not find a leak",
			rep.ControlOK, strings.Contains(out, secret))
	}

	out, rep = run("approver")
	if rep.AskErr != "" {
		t.Fatalf("Ask through the proxy: %s", rep.AskErr)
	}
	if strings.Contains(out, secret) {
		t.Error("the output of the child holds the token")
	}
	if len(rep.Protos) == 0 {
		t.Error("the server got no request")
	}
	for _, p := range rep.Protos {
		if p != "HTTP/1.1" {
			t.Errorf("the client spoke %s", p)
		}
	}
	if strings.Contains(rep.ProxySaw, secret) || !strings.HasPrefix(rep.ProxySaw, "CONNECT example.com:443 HTTP/1.1\r\n") {
		t.Errorf("the proxy saw: %q", rep.ProxySaw)
	}
	if !strings.Contains(out, "proxy_host="+rep.ProxyAddr) {
		t.Error("the approver did not log the host of the proxy")
	}
	if strings.Contains(out, "proxypass") || strings.Contains(out, "proxyuser") {
		t.Error("the output of the child holds the user name or the password of the proxy")
	}
}
