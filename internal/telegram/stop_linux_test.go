package telegram

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestConnectionsResetOnClose: closing a connection of the HTTP client
// resets it (SO_LINGER 0), so the kernel drops what it has not sent yet. A
// getUpdates request that waits in the kernel when the broker stops never
// reaches Telegram later (DESIGN.md section 7). The other side sees the
// reset, not a normal end of the connection.
func TestConnectionsResetOnClose(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	tr, ok := newHTTPClient().Transport.(*http.Transport)
	if !ok || tr.DialContext == nil {
		t.Fatal("the transport has no dialer of its own")
	}
	c, err := tr.DialContext(t.Context(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.SetReadDeadline(time.Now().Add(waitLimit)); err != nil {
		t.Fatal(err)
	}
	_, err = server.Read(make([]byte, 1))
	if !errors.Is(err, syscall.ECONNRESET) {
		t.Errorf("the other side read %v, want a reset (ECONNRESET)", err)
	}
}

// TestRunClosesThePollConnection: when Run returns because its context
// ended, the getUpdates call that waited has ended, and its connection is
// closed: the server sees the client go away. Run sends no getUpdates
// after it returned.
func TestRunClosesThePollConnection(t *testing.T) {
	e := newEnv(t)
	e.f.mu.Lock()
	e.f.pollWait = 2 * waitLimit // the call waits until the client goes away
	e.f.mu.Unlock()
	stop := e.run(t, (&stubCore{}).answer)
	e.f.waitCalls("getUpdates", 1)
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Errorf("Run: %v, want context.Canceled", err)
	}
	e.f.waitFor("the end of the waiting getUpdates call", func() bool { return e.f.pollsGone == 1 })
	time.Sleep(100 * time.Millisecond) // a late call would come now
	if n := len(e.f.callsOf("getUpdates")); n != 1 {
		t.Errorf("%d getUpdates calls, want 1: Run polled after it returned", n)
	}
}

// TestNewLogsTheCAPlaces: when SSL_CERT_FILE or SSL_CERT_DIR is set, Go
// takes the CA certificates that check Telegram's certificate from there,
// and a CA there sees the bot token. New logs each one that is set, with
// its name and its path only.
func TestNewLogsTheCAPlaces(t *testing.T) {
	token := newCanaryToken(t)
	read := func(string) ([]byte, error) { return []byte(token), nil }
	newWithLog := func() string {
		var logs syncBuffer
		logger := slog.New(slog.NewTextHandler(&logs, nil))
		if _, err := newApprover(testTelegramConfig(), Options{Logger: logger}, read, "http://127.0.0.1:1"); err != nil {
			t.Fatal(err)
		}
		return logs.String()
	}
	t.Setenv("SSL_CERT_FILE", "")
	t.Setenv("SSL_CERT_DIR", "")
	if err := os.Unsetenv("SSL_CERT_FILE"); err != nil {
		t.Fatal(err)
	}
	if err := os.Unsetenv("SSL_CERT_DIR"); err != nil {
		t.Fatal(err)
	}
	if logs := newWithLog(); strings.Contains(logs, "CA certificates") {
		t.Errorf("a log line without SSL_CERT_FILE or SSL_CERT_DIR: %s", logs)
	}
	t.Setenv("SSL_CERT_FILE", "/etc/nodkey/test-ca.pem")
	t.Setenv("SSL_CERT_DIR", "/etc/nodkey/ca:/etc/nodkey/more-ca")
	logs := newWithLog()
	for _, want := range []string{"variable=SSL_CERT_FILE path=/etc/nodkey/test-ca.pem",
		`variable=SSL_CERT_DIR path=/etc/nodkey/ca:/etc/nodkey/more-ca`} {
		if !strings.Contains(logs, want) {
			t.Errorf("the log has no %q: %s", want, logs)
		}
	}
	if strings.Contains(logs, token[strings.IndexByte(token, ':')+1:]) {
		t.Error("the log holds the bot token")
	}
}
