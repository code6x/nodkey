package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The fake Telegram server of the tests of nodkey broker, and the fake
// HTTPS proxy in front of it (see brokerenv_linux_test.go).

// fakeTelegram is a fake Bot API server for the child broker, behind a
// fake HTTPS proxy. It answers like Telegram, and keeps every call.
type fakeTelegram struct {
	t         *testing.T
	token     string // the made-up bot token
	proxyAddr string // the fake proxy
	caFile    string // SSL_CERT_FILE of the child: the test CA
	caDir     string // SSL_CERT_DIR of the child: an empty directory

	mu          sync.Mutex
	calls       []tgCall
	polls       []*tgPoll
	updates     []tgUpdate
	nextUpdate  int64
	nextMsg     int64
	markups     map[int64]json.RawMessage // the buttons of each message, by message ID
	refusePolls int                       // the status of the error answer to every getUpdates; 0 for none
	hold        chan struct{}             // if set, alert messages wait until it is closed
	held        int                       // the alert messages that wait at hold now
	offline     bool                      // the proxy refuses every new connection, as if Telegram were unreachable
	connects    []string                  // what the proxy was asked to connect to
	changed     chan struct{}             // closed and made new on each change
}

// tgCall is one call that the fake got.
type tgCall struct {
	method  string
	body    []byte   // the request body
	msgID   int64    // sendMessage: the message ID of its answer
	buttons []string // sendMessage: the data of its buttons
}

// tgPoll is one getUpdates call.
type tgPoll struct {
	ended bool // the fake is done with it
	gone  bool // it ended because the client went away: it closed the connection
}

// tgUpdate is a queued update.
type tgUpdate struct {
	id  int64
	raw []byte
}

// newFakeTelegram starts a fake Telegram server and its proxy.
func newFakeTelegram(t *testing.T, opts brokerOptions) *fakeTelegram {
	t.Helper()
	f := &fakeTelegram{
		t:           t,
		token:       newBotToken(),
		nextUpdate:  1000,
		nextMsg:     500,
		markups:     make(map[int64]json.RawMessage),
		refusePolls: opts.refusePolls,
		changed:     make(chan struct{}),
	}
	if opts.holdAlerts {
		f.hold = make(chan struct{})
	}
	caPEM, leaf := newTestCA(t)
	certs := t.TempDir()
	f.caFile = filepath.Join(certs, "ca.pem")
	writeTestFile(t, f.caFile, caPEM, 0o600)
	f.caDir = filepath.Join(certs, "none")
	if err := os.Mkdir(f.caDir, 0o700); err != nil {
		t.Fatal(err)
	}

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.proxyAddr = ln.Addr().String()
	tunnels := &chanListener{conns: make(chan net.Conn), done: make(chan struct{}), addr: ln.Addr()}
	srv := &http.Server{Handler: f, ReadHeaderTimeout: brokerWait}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{leaf}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}
	var wg sync.WaitGroup
	wg.Go(func() { _ = srv.Serve(tunnels) })
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() { f.connect(c, tlsConfig, tunnels) })
		}
	})
	t.Cleanup(func() {
		_ = ln.Close()
		_ = srv.Close()
		f.release()
		wg.Wait()
	})
	return f
}

// connect handles one connection to the fake proxy: a CONNECT to
// api.telegram.org, then TLS with the test CA's certificate, and the
// fake's HTTP server. Anything else is refused.
func (f *fakeTelegram) connect(c net.Conn, cfg *tls.Config, tunnels *chanListener) {
	_ = c.SetReadDeadline(time.Now().Add(brokerWait))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		_ = c.Close()
		return
	}
	f.mu.Lock()
	f.connects = append(f.connects, req.Method+" "+req.Host)
	offline := f.offline
	f.mu.Unlock()
	if offline {
		_, _ = io.WriteString(c, "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
		_ = c.Close()
		return
	}
	if req.Method != http.MethodConnect || req.Host != telegramHost+":443" {
		_, _ = io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
		_ = c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		_ = c.Close()
		return
	}
	select {
	case tunnels.conns <- tls.Server(&bufferedConn{Conn: c, r: br}, cfg):
	case <-tunnels.done:
		_ = c.Close()
	}
}

// bufferedConn is a connection whose first bytes may wait in r.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// chanListener is a net.Listener of the connections in conns.
type chanListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
	addr  net.Addr
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *chanListener) Addr() net.Addr { return l.addr }

// newTestCA returns a new CA certificate in PEM, and a certificate for
// api.telegram.org that it signed, with its key.
func newTestCA(t *testing.T) ([]byte, tls.Certificate) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "nodkey test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: telegramHost},
		DNSNames:     []string{telegramHost},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
}

func (f *fakeTelegram) notifyLocked() {
	close(f.changed)
	f.changed = make(chan struct{})
}

// writeTelegram writes an answer of the Bot API.
func writeTelegram(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func (f *fakeTelegram) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest, ok := strings.CutPrefix(r.URL.Path, "/bot")
	token, method, ok2 := strings.Cut(rest, "/")
	if !ok || !ok2 || token != f.token {
		writeTelegram(w, http.StatusUnauthorized, `{"ok":false,"error_code":401,"description":"Unauthorized"}`)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return
	}
	var p struct {
		ChatID      int64           `json:"chat_id"`
		MessageID   int64           `json:"message_id"`
		Offset      int64           `json:"offset"`
		Timeout     int             `json:"timeout"`
		ReplyMarkup json.RawMessage `json:"reply_markup"`
	}
	_ = json.Unmarshal(body, &p) // the fields come from the broker; a test checks what it needs
	call := tgCall{method: method, body: body}
	f.mu.Lock()
	if method == "sendMessage" {
		f.nextMsg++
		call.msgID = f.nextMsg
		call.buttons = buttonData(p.ReplyMarkup)
		f.markups[call.msgID] = p.ReplyMarkup
	}
	f.calls = append(f.calls, call)
	refusePolls, hold := f.refusePolls, f.hold
	f.notifyLocked()
	f.mu.Unlock()

	message := func(id int64) string {
		return fmt.Sprintf(`{"ok":true,"result":{"message_id":%d,"date":1,"chat":{"id":%d,"type":"private"},`+
			`"text":"the text"}}`, id, p.ChatID)
	}
	switch method {
	case "getUpdates":
		if refusePolls != 0 {
			description := map[int]string{
				http.StatusConflict:     "Conflict: terminated by other getUpdates request",
				http.StatusUnauthorized: "Unauthorized",
				http.StatusForbidden:    "Forbidden",
				http.StatusNotFound:     "Not Found",
			}[refusePolls]
			writeTelegram(w, refusePolls, fmt.Sprintf(`{"ok":false,"error_code":%d,"description":%q}`,
				refusePolls, description))
			return
		}
		f.serveUpdates(w, r, p.Offset, time.Duration(p.Timeout)*time.Second)
	case "sendMessage":
		if len(call.buttons) == 0 && hold != nil && !f.waitHold(r, hold) {
			return
		}
		writeTelegram(w, http.StatusOK, message(call.msgID))
	case "editMessageText", "editMessageReplyMarkup":
		writeTelegram(w, http.StatusOK, message(p.MessageID))
	case "answerCallbackQuery":
		writeTelegram(w, http.StatusOK, `{"ok":true,"result":true}`)
	default:
		writeTelegram(w, http.StatusNotFound, `{"ok":false,"error_code":404,"description":"Not Found"}`)
	}
}

// waitHold makes the alert message of r wait until hold is closed, and
// reports true, or until the client goes away, and reports false. held
// counts the messages that wait.
func (f *fakeTelegram) waitHold(r *http.Request, hold chan struct{}) bool {
	f.addHeld(1)
	defer f.addHeld(-1)
	select {
	case <-hold:
		return true
	case <-r.Context().Done():
		return false
	}
}

func (f *fakeTelegram) addHeld(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.held += n
	f.notifyLocked()
}

// serveUpdates answers getUpdates: the queued updates from offset on, or
// none after wait, as Telegram's long polling does.
func (f *fakeTelegram) serveUpdates(w http.ResponseWriter, r *http.Request, offset int64, wait time.Duration) {
	poll := &tgPoll{}
	f.mu.Lock()
	f.polls = append(f.polls, poll)
	f.notifyLocked()
	f.mu.Unlock()
	timer := time.NewTimer(min(max(wait, time.Second), 50*time.Second))
	defer timer.Stop()
	end := func(gone bool) {
		f.mu.Lock()
		poll.ended, poll.gone = true, gone
		f.notifyLocked()
		f.mu.Unlock()
	}
	for {
		f.mu.Lock()
		f.updates = slices.DeleteFunc(f.updates, func(u tgUpdate) bool { return u.id < offset })
		var parts []string
		for _, u := range f.updates {
			parts = append(parts, string(u.raw))
		}
		changed := f.changed
		f.mu.Unlock()
		if len(parts) > 0 {
			end(false)
			writeTelegram(w, http.StatusOK, `{"ok":true,"result":[`+strings.Join(parts, ",")+`]}`)
			return
		}
		select {
		case <-changed:
		case <-timer.C:
			end(false)
			writeTelegram(w, http.StatusOK, `{"ok":true,"result":[]}`)
			return
		case <-r.Context().Done():
			end(true)
			return
		}
	}
}

// buttonData returns the callback data of each button in reply_markup.
func buttonData(markup json.RawMessage) []string {
	var kb struct {
		InlineKeyboard [][]struct {
			CallbackData string `json:"callback_data"`
		} `json:"inline_keyboard"`
	}
	if len(markup) == 0 || json.Unmarshal(markup, &kb) != nil {
		return nil
	}
	var data []string
	for _, row := range kb.InlineKeyboard {
		for _, b := range row {
			data = append(data, b.CallbackData)
		}
	}
	return data
}

// setOffline makes the proxy refuse every new connection, or take them
// again: Telegram cannot be reached, or it can again. A connection that
// the proxy took before stays.
func (f *fakeTelegram) setOffline(offline bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.offline = offline
}

// release lets the alert messages that wait go on.
func (f *fakeTelegram) release() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hold != nil {
		close(f.hold)
		f.hold = nil
	}
}

// waitFor waits until cond, which runs with f.mu held, is true.
func (f *fakeTelegram) waitFor(what string, cond func() bool) {
	f.t.Helper()
	deadline := time.NewTimer(brokerWait)
	defer deadline.Stop()
	for {
		f.mu.Lock()
		ok, changed := cond(), f.changed
		f.mu.Unlock()
		if ok {
			return
		}
		select {
		case <-changed:
		case <-deadline.C:
			f.t.Fatalf("waited %s in vain for %s", brokerWait, what)
		}
	}
}

// askedLocked returns the messages with buttons: those of requests.
func (f *fakeTelegram) askedLocked() []tgCall {
	var out []tgCall
	for _, c := range f.calls {
		if c.method == "sendMessage" && len(c.buttons) > 0 {
			out = append(out, c)
		}
	}
	return out
}

// asked returns how many messages with buttons the fake got.
func (f *fakeTelegram) asked() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.askedLocked())
}

// waitAsk waits for the n-th message with buttons, and returns its
// message ID and the request ID in its buttons.
func (f *fakeTelegram) waitAsk(n int) (int64, string) {
	f.t.Helper()
	f.waitFor(fmt.Sprintf("message %d with buttons", n), func() bool { return len(f.askedLocked()) >= n })
	f.mu.Lock()
	c := f.askedLocked()[n-1]
	f.mu.Unlock()
	_, id, _ := strings.Cut(c.buttons[len(c.buttons)-1], ":")
	return c.msgID, id
}

// waitAlert waits for a message without buttons whose request body holds
// text, and returns the body.
func (f *fakeTelegram) waitAlert(text string) string {
	f.t.Helper()
	var body string
	f.waitFor("an alert with "+strconv.Quote(text), func() bool {
		for _, c := range f.calls {
			if c.method == "sendMessage" && len(c.buttons) == 0 && strings.Contains(string(c.body), text) {
				body = string(c.body)
				return true
			}
		}
		return false
	})
	return body
}

// waitHeld waits until n alert messages wait at hold at the same time.
func (f *fakeTelegram) waitHeld(n int) {
	f.t.Helper()
	f.waitFor(fmt.Sprintf("%d alert messages that wait at the same time", n), func() bool { return f.held >= n })
}

// alertCount returns the number of messages without buttons whose request
// body holds text.
func (f *fakeTelegram) alertCount(text string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c.method == "sendMessage" && len(c.buttons) == 0 && strings.Contains(string(c.body), text) {
			n++
		}
	}
	return n
}

// tap queues a press of the approver, in the private chat, on the message
// msgID with the buttons that the broker sent there, with the button data
// data. It returns the ID of the press (the callback query).
func (f *fakeTelegram) tap(msgID int64, data string) string {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextUpdate++
	id := "cb" + strconv.FormatInt(f.nextUpdate, 10)
	msg := map[string]any{
		"message_id": msgID, "date": 1, "text": "the text",
		"chat": map[string]any{"id": approverID, "type": "private"},
	}
	if m := f.markups[msgID]; len(m) > 0 {
		msg["reply_markup"] = m
	}
	raw, err := json.Marshal(map[string]any{
		"update_id": f.nextUpdate,
		"callback_query": map[string]any{
			"id":            id,
			"from":          map[string]any{"id": approverID, "is_bot": false, "first_name": "Test"},
			"chat_instance": "1",
			"data":          data,
			"message":       msg,
		},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	f.updates = append(f.updates, tgUpdate{id: f.nextUpdate, raw: raw})
	f.notifyLocked()
	return id
}

// waitTapAnswer waits for the answer to the press id
// (answerCallbackQuery), and returns the text that the phone shows.
func (f *fakeTelegram) waitTapAnswer(id string) string {
	f.t.Helper()
	var text string
	f.waitFor("the answer to the press "+id, func() bool {
		for _, c := range f.calls {
			var p struct {
				ID   string `json:"callback_query_id"`
				Text string `json:"text"`
			}
			if c.method == "answerCallbackQuery" && json.Unmarshal(c.body, &p) == nil && p.ID == id {
				text = p.Text
				return true
			}
		}
		return false
	})
	return text
}

// waitPolling waits until a getUpdates call waits for an answer.
func (f *fakeTelegram) waitPolling() {
	f.t.Helper()
	f.waitFor("a getUpdates call that waits", func() bool {
		return len(f.polls) > 0 && !f.polls[len(f.polls)-1].ended
	})
}

// waitPollsGone waits until every getUpdates call has ended, the last one
// because the client went away: it closed the connection while the call
// waited.
func (f *fakeTelegram) waitPollsGone() {
	f.t.Helper()
	f.waitFor("the end of every getUpdates call", func() bool {
		if len(f.polls) == 0 || !f.polls[len(f.polls)-1].gone {
			return false
		}
		return !slices.ContainsFunc(f.polls, func(p *tgPoll) bool { return !p.ended })
	})
}

// pollCount returns the number of getUpdates calls so far.
func (f *fakeTelegram) pollCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.polls)
}

// bodies returns every request body that the fake got, one per line.
func (f *fakeTelegram) bodies() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var b strings.Builder
	for _, c := range f.calls {
		b.WriteString(c.method + " " + string(c.body) + "\n")
	}
	return b.String()
}

// proxied returns what the proxy was asked to connect to.
func (f *fakeTelegram) proxied() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.connects)
}
