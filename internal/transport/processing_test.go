package transport

// Regression test from the security review of issue #11 (part A): a
// client that does not take the 102 Processing answer cannot hold the
// handler longer than processingTimeout, and the request's context ends.

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/config"
)

// blockConn is a connection whose writes block until the write deadline
// while block is set, as a socket whose buffers are full.
type blockConn struct {
	net.Conn
	block *atomic.Bool
	mu    sync.Mutex
	wd    time.Time
}

func (c *blockConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.wd = t
	c.mu.Unlock()
	return c.Conn.SetWriteDeadline(t)
}

func (c *blockConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.wd = t
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

func (c *blockConn) Write(p []byte) (int, error) {
	if c.block.Load() {
		c.mu.Lock()
		wd := c.wd
		c.mu.Unlock()
		if wd.IsZero() {
			time.Sleep(time.Minute) // no deadline: the write would hang
		} else {
			time.Sleep(time.Until(wd))
		}
		return 0, os.ErrDeadlineExceeded
	}
	return c.Conn.Write(p)
}

type blockListener struct {
	net.Listener
	block *atomic.Bool
}

func (l blockListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &blockConn{Conn: c, block: l.block}, nil
}

func TestProcessingDoesNotBlock(t *testing.T) {
	old := processingTimeout
	processingTimeout = 300 * time.Millisecond
	t.Cleanup(func() { processingTimeout = old })
	broker, laptop := newTestKey(t), newTestKey(t)
	var block atomic.Bool
	type outcome struct {
		took      time.Duration
		err       error
		cancelled bool
	}
	done := make(chan outcome, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := ReadJSON[struct{}](w, r); err != nil {
			return
		}
		block.Store(true) // the client stops reading; its buffers are full
		start := time.Now()
		err := WriteProcessing(w, http.Header{"Nodkey-Short-Code": {"7qd2"}})
		took := time.Since(start)
		select {
		case <-r.Context().Done():
			done <- outcome{took, err, true}
		case <-time.After(2 * time.Second):
			done <- outcome{took, err, false}
		}
	})
	srv, err := NewServer(broker.cert, clientTable(map[string]config.Pin{"laptop": laptop.pin}), handler, nil)
	if err != nil {
		t.Fatal(err)
	}
	addr := listenAndServe(t, func(ln net.Listener) error { return srv.Serve(blockListener{ln, &block}) },
		func() { _ = srv.Close() })
	c, err := NewClient(addr, laptop.cert, broker.pin)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+addr+"/x", strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		if resp, err := c.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	select {
	case o := <-done:
		t.Logf("WriteProcessing took %v (err %v); the request context ended: %v", o.took, o.err, o.cancelled)
		if o.took > 2*processingTimeout {
			t.Errorf("WriteProcessing blocked %v, more than processingTimeout %v", o.took, processingTimeout)
		}
		if !o.cancelled {
			t.Error("the request goes on after the 102 could not be written")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the handler is stuck in WriteProcessing")
	}
}

// TestWriteJSONBody: the body goes out as it is, marked not to be stored,
// and not changed; bytes that are not JSON are not written.
func TestWriteJSONBody(t *testing.T) {
	body := []byte(`{"secrets":[{"var":"A","value":"dmFsdWU="}]}`)
	keep := slices.Clone(body)
	w := httptest.NewRecorder()
	if err := WriteJSONBody(w, http.StatusOK, body); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || w.Body.String() != string(keep) || w.Header().Get("Cache-Control") != "no-store" ||
		w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("answer %d %q, headers %v", w.Code, w.Body.String(), w.Header())
	}
	if !bytes.Equal(body, keep) {
		t.Error("WriteJSONBody changed the body; the caller clears it")
	}
	w = httptest.NewRecorder()
	if err := WriteJSONBody(w, http.StatusOK, []byte(`{"value":"made-up`)); err == nil || strings.Contains(err.Error(), "made-up") {
		t.Errorf("WriteJSONBody of broken JSON: %v", err)
	}
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "made-up") {
		t.Errorf("answer %d %q, want 500 without the body", w.Code, w.Body.String())
	}
}
