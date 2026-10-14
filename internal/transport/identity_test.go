package transport

import (
	"bufio"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/config"
)

// TestPipelinedRequestsKeepTheName sends three requests in one write on
// one connection (HTTP/1.1 pipelining), with "OPTIONS *" between them.
// Each must reach the handler through the pin check, with the name of the
// pinned key, and only that name. (From the security review of issue #4.)
func TestPipelinedRequestsKeepTheName(t *testing.T) {
	broker, laptop := newTestKey(t), newTestKey(t)
	b := startBroker(t, broker, clientTable(map[string]config.Pin{"laptop": laptop.pin}), nil)
	d := tls.Dialer{Config: ClientTLSConfig(laptop.cert, broker.pin)}
	conn, err := d.DialContext(t.Context(), "tcp", b.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	post := "POST /whoami HTTP/1.1\r\nHost: broker\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
	options := "OPTIONS * HTTP/1.1\r\nHost: broker\r\nContent-Length: 0\r\n\r\n"
	if _, err := io.WriteString(conn, post+options+post); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	for i := range 3 {
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("answer %d: %v", i+1, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"client":"laptop"`) {
			t.Errorf("answer %d: %d %s", i+1, resp.StatusCode, body)
		}
	}
	if n := b.calls.Load(); n != 3 {
		t.Errorf("the handler ran %d times, want 3", n)
	}
}

// TestHTTP2PrefaceGetsOnlyThePinnedName sends the HTTP/2 preface on a
// connection that negotiated http/1.1. net/http 1.26 and 1.27 pass it to
// the handler as a request "PRI *", through the pin check. Whatever it
// does with it, a handler must never run without the pinned name. (From
// the security review of issue #4.)
func TestHTTP2PrefaceGetsOnlyThePinnedName(t *testing.T) {
	broker, laptop := newTestKey(t), newTestKey(t)
	b := startBroker(t, broker, clientTable(map[string]config.Pin{"laptop": laptop.pin}), nil)
	d := tls.Dialer{Config: ClientTLSConfig(laptop.cert, broker.pin)}
	conn, err := d.DialContext(t.Context(), "tcp", b.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Logf("preface: connection ended: %v (handler calls: %d)", err, b.calls.Load())
		return
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	t.Logf("preface: status %d, body %q, handler calls %d", resp.StatusCode, body, b.calls.Load())
	if resp.StatusCode == http.StatusOK && !strings.Contains(string(body), `"client":"laptop"`) {
		t.Errorf("a 200 answer without the pinned name: %s", body)
	}
	if n := b.calls.Load(); n > 1 {
		t.Errorf("the handler ran %d times, want at most 1", n)
	}
}
