package transport

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/config"
)

func TestHeaderLimit(t *testing.T) {
	broker, laptop := newTestKey(t), newTestKey(t)
	b := startBroker(t, broker, clientTable(map[string]config.Pin{"laptop": laptop.pin}), nil)
	c := newTestClient(t, b, laptop, broker.pin)
	_, _, err := askState(t, c, b.addr, func(r *http.Request) {
		r.Header.Set("X-Big", strings.Repeat("a", 16<<10))
	})
	var se *statusError
	if !errors.As(err, &se) || se.status != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("error = %v, want status 431", err)
	}
	if n := b.calls.Load(); n != 0 {
		t.Errorf("the handler ran %d times, want 0", n)
	}
}

func TestHandlerPanic(t *testing.T) {
	broker, laptop := newTestKey(t), newTestKey(t)
	canary := "made-up-canary-" + rand.Text()
	b := &testBroker{key: broker}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/value":
			panic("the value " + canary)
		case "/error":
			panic(fmt.Errorf("an error with %s", canary))
		case "/abort": // an abort on purpose, with a canary in the error
			panic(fmt.Errorf("%w: %s", http.ErrAbortHandler, canary))
		case "/index":
			items := []string{canary}
			_ = items[len(r.URL.Path)] // a runtime error: index out of range
		}
		_ = WriteJSON(w, http.StatusOK, whoAmI{Client: "ok"})
	})
	b.start(t, clientTable(map[string]config.Pin{"laptop": laptop.pin}), handler, nil)
	c := newTestClient(t, b, laptop, broker.pin)
	for _, path := range []string{"/value", "/error", "/index", "/abort"} {
		_, _, err := askState(t, c, b.addr, func(r *http.Request) { r.URL.Path = path })
		if err == nil {
			t.Errorf("%s: the request after a panic got an answer", path)
		}
	}
	logs := b.logs.String()
	if strings.Contains(logs, canary) {
		t.Errorf("the log holds the panic value:\n%s", logs)
	}
	// The abort on purpose is not logged.
	if n := strings.Count(logs, "a handler panicked"); n != 3 {
		t.Errorf("the log has %d panics, want 3:\n%s", n, logs)
	}
	// The log says where: the test's handler function.
	if !strings.Contains(logs, "TestHandlerPanic") || !strings.Contains(logs, "server_test.go:") {
		t.Errorf("the log does not say where the panic happened:\n%s", logs)
	}
	// The server still works.
	if got, err := ask(t, c, b.addr); err != nil || got != "ok" {
		t.Errorf("after the panics: %q, %v", got, err)
	}
}

// TestHandshakeTimeout shows that a connection without a TLS handshake is
// closed.
func TestHandshakeTimeout(t *testing.T) {
	broker, laptop := newTestKey(t), newTestKey(t)
	b := startBroker(t, broker, clientTable(map[string]config.Pin{"laptop": laptop.pin}), func(s *Server) {
		s.http.ReadHeaderTimeout = 200 * time.Millisecond
	})
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", b.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	var ne net.Error
	if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
		t.Fatalf("read = %v, want the broker to close the connection", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("the broker closed the connection after %v", d)
	}
}

// waitBroker starts a broker whose handler reads a JSON body and then
// waits like a request that waits for the approver. It sends the result
// of ReadJSON to read, and what ended the wait to ended: "answered" or
// "cancelled".
func waitBroker(t *testing.T, broker, laptop testKey, readTimeout, wait time.Duration) (
	b *testBroker, read chan error, ended chan string,
) {
	t.Helper()
	read, ended = make(chan error, 1), make(chan string, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := ReadJSON[struct{}](w, r)
		read <- err
		if err != nil {
			return
		}
		select {
		case <-time.After(wait):
			ended <- "answered"
			_ = WriteJSON(w, http.StatusOK, whoAmI{Client: "waited"})
		case <-r.Context().Done():
			ended <- "cancelled"
		}
	})
	b = (&testBroker{key: broker}).start(t, clientTable(map[string]config.Pin{"laptop": laptop.pin}), handler,
		func(s *Server) { s.http.ReadTimeout = readTimeout })
	return b, read, ended
}

// TestLongWaitIsNotCancelled shows that a request can wait for the
// approver longer than the read timeout: ReadJSON lifts it.
func TestLongWaitIsNotCancelled(t *testing.T) {
	broker, laptop := newTestKey(t), newTestKey(t)
	b, read, ended := waitBroker(t, broker, laptop, 500*time.Millisecond, 2*time.Second)
	got, err := ask(t, newTestClient(t, b, laptop, broker.pin), b.addr)
	if err := <-read; err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	if e := <-ended; e != "answered" {
		t.Errorf("the wait was %s, want answered", e)
	}
	if err != nil || got != "waited" {
		t.Errorf("answer %q, %v; want waited", got, err)
	}
}

// TestHangUpCancels shows that the request's context ends when the client
// hangs up, for example when ssh was killed (DESIGN.md section 7).
func TestHangUpCancels(t *testing.T) {
	broker, laptop := newTestKey(t), newTestKey(t)
	b, read, ended := waitBroker(t, broker, laptop, 500*time.Millisecond, 30*time.Second)
	c := newTestClient(t, b, laptop, broker.pin)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	sent := make(chan struct{})
	defer func() { cancel(); <-sent }()
	go func() {
		defer close(sent)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+b.addr+"/wait", strings.NewReader("{}"))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if resp, err := c.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	if err := <-read; err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	cancel() // the client hangs up
	select {
	case e := <-ended:
		if e != "cancelled" {
			t.Errorf("the wait was %s, want cancelled", e)
		}
	case <-time.After(10 * time.Second):
		t.Error("the handler did not see the client hang up")
	}
}

// TestSlowBodyIsRefused shows that the read timeout still holds while the
// body is read.
func TestSlowBodyIsRefused(t *testing.T) {
	broker, laptop := newTestKey(t), newTestKey(t)
	b, read, _ := waitBroker(t, broker, laptop, 500*time.Millisecond, time.Second)
	d := tls.Dialer{Config: ClientTLSConfig(laptop.cert, broker.pin)}
	conn, err := d.DialContext(t.Context(), "tcp", b.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	// A body of 100 bytes, of which only a few come.
	if _, err := io.WriteString(conn, "POST /wait HTTP/1.1\r\nHost: broker\r\nContent-Type: application/json\r\n"+
		"Content-Length: 100\r\n\r\n{\"a\":"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-read:
		if !errors.Is(err, errRead) {
			t.Errorf("ReadJSON = %v, want errRead", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ReadJSON still waits for the body")
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status %d, want 400", resp.StatusCode)
		}
	}
}

// TestWriteDeadlines shows that an answer after a wait for the approver
// gets through, although the wait is longer than the write deadline:
// WriteJSON starts a new one. The connection stays open for the next
// request, and an answer without WriteJSON works there too.
func TestWriteDeadlines(t *testing.T) {
	old := writeTimeout
	writeTimeout = 500 * time.Millisecond
	t.Cleanup(func() { writeTimeout = old })
	broker, laptop := newTestKey(t), newTestKey(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/plain": // an answer without WriteJSON, such as a 404 from a mux
			http.Error(w, "plain", http.StatusTeapot)
		case "/slow": // an answer after a wait for the approver
			time.Sleep(3 * writeTimeout)
			_ = WriteJSON(w, http.StatusOK, whoAmI{Client: "slow"})
		default:
			_ = WriteJSON(w, http.StatusOK, whoAmI{Client: "fast"})
		}
	})
	b := (&testBroker{key: broker}).start(t, clientTable(map[string]config.Pin{"laptop": laptop.pin}), handler, nil)
	c := newTestClient(t, b, laptop, broker.pin) // it keeps the connection open
	var conns []bool                             // for each request: was the connection reused?
	for i, path := range []string{"/fast", "/slow", "/plain"} {
		if i > 0 {
			time.Sleep(2 * writeTimeout) // the deadline of the last answer passes
		}
		ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) { conns = append(conns, info.Reused) },
		})
		_, _, err := askState(t, c, b.addr, func(r *http.Request) {
			r.URL.Path = path
			*r = *r.WithContext(ctx)
		})
		var se *statusError
		if path == "/plain" && errors.As(err, &se) && se.status == http.StatusTeapot {
			err = nil
		}
		if err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
	if len(conns) != 3 || !conns[1] || !conns[2] {
		t.Errorf("the requests did not share one connection: reused %v", conns)
	}
}

// TestSlowReaderIsDropped shows that a client that does not read its
// answer cannot hold the handler: the write deadline ends the write.
func TestSlowReaderIsDropped(t *testing.T) {
	old := writeTimeout
	writeTimeout = 500 * time.Millisecond
	t.Cleanup(func() { writeTimeout = old })
	broker, laptop := newTestKey(t), newTestKey(t)
	wrote := make(chan error, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Far more than the socket buffers hold, written without
		// WriteJSON: only the server's write deadline can end it.
		chunk := make([]byte, 64<<10)
		var err error
		for i := 0; i < 1024 && err == nil; i++ {
			_, err = w.Write(chunk)
		}
		wrote <- err
	})
	b := (&testBroker{key: broker}).start(t, clientTable(map[string]config.Pin{"laptop": laptop.pin}), handler, nil)
	d := tls.Dialer{Config: ClientTLSConfig(laptop.cert, broker.pin)}
	conn, err := d.DialContext(t.Context(), "tcp", b.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, "GET /big HTTP/1.1\r\nHost: broker\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	// The client reads nothing.
	select {
	case err := <-wrote:
		if err == nil {
			t.Error("the handler wrote 64 MiB to a client that reads nothing")
		}
	case <-time.After(15 * time.Second):
		t.Error("the handler still writes to a client that reads nothing")
	}
}

// TestWriteProcessing shows the informational answer that the broker sends
// while a request waits for the approver: 102 Processing with its headers,
// then the final answer, without those headers. The client sees the 102
// before the final answer.
func TestWriteProcessing(t *testing.T) {
	broker, laptop := newTestKey(t), newTestKey(t)
	release := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := ReadJSON[struct{}](w, r); err != nil {
			return
		}
		if err := WriteProcessing(w, http.Header{"x-short-code": {"7qd2"}}); err != nil {
			t.Errorf("WriteProcessing: %v", err)
		}
		<-release // the approver decides
		_ = WriteJSON(w, http.StatusOK, whoAmI{Client: "waited"})
	})
	b := (&testBroker{key: broker}).start(t, clientTable(map[string]config.Pin{"laptop": laptop.pin}), handler, nil)
	c := newTestClient(t, b, laptop, broker.pin)
	got1xx := make(chan string, 2)
	ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{
		Got1xxResponse: func(code int, h textproto.MIMEHeader) error {
			got1xx <- strconv.Itoa(code) + " " + h.Get("X-Short-Code")
			return nil
		},
	})
	type result struct {
		status int
		err    error
	}
	done := make(chan result, 1)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+b.addr+"/wait", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	go func() {
		resp, err := c.Do(req)
		if err != nil {
			done <- result{err: err}
			return
		}
		_, err = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		done <- result{status: resp.StatusCode, err: err}
	}()
	select {
	case got := <-got1xx:
		if got != "102 7qd2" {
			t.Errorf("the informational answer is %q, want 102 with the short code", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no informational answer while the request waits")
	}
	close(release)
	res := <-done
	if res.err != nil || res.status != http.StatusOK {
		t.Errorf("the final answer: %d, %v; want 200", res.status, res.err)
	}
	if len(got1xx) != 0 {
		t.Errorf("more than one informational answer")
	}
}

// TestWriteProcessingHeaderNotInTheAnswer shows that the final answer does
// not carry the headers of the informational answer.
func TestWriteProcessingHeaderNotInTheAnswer(t *testing.T) {
	broker, laptop := newTestKey(t), newTestKey(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := ReadJSON[struct{}](w, r); err != nil {
			return
		}
		_ = WriteProcessing(w, http.Header{"X-Short-Code": {"7qd2"}})
		WriteError(w, http.StatusForbidden)
	})
	b := (&testBroker{key: broker}).start(t, clientTable(map[string]config.Pin{"laptop": laptop.pin}), handler, nil)
	c := newTestClient(t, b, laptop, broker.pin)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+b.addr+"/x", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Short-Code") != "" {
		t.Errorf("final answer %d with X-Short-Code %q; want 403 without it", resp.StatusCode,
			resp.Header.Get("X-Short-Code"))
	}
}
