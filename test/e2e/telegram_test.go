//go:build e2e

package e2e

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
	"html"
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

// The fake Telegram server of the end-to-end test, and the fake HTTPS
// proxy in front of it. This is the approach of the tests of nodkey
// broker in cmd/nodkey (brokerfake_linux_test.go): the broker reaches the
// fake through HTTPS_PROXY. The proxy takes only a CONNECT to
// api.telegram.org, and answers the TLS handshake itself, with a
// certificate of a test CA that the broker trusts through SSL_CERT_FILE
// (and an empty SSL_CERT_DIR). So the broker runs its real Telegram code,
// and nothing goes to the real Bot API: no other CA is trusted, so even a
// call that missed the proxy could not finish its TLS handshake, and the
// bot token is only sent after it.

// telegramHost is the host of the Bot API.
const telegramHost = "api.telegram.org"

// approverID is the made-up Telegram user ID of the approver. The private
// chat with the approver has the same ID.
const approverID int64 = 7000001

// The button data of DESIGN.md section 7: the prefix and the request ID.
const (
	tapOnce   = "o:" // Approve once
	tapWindow = "w:" // Approve N min, and Approve on an SSH grant
	tapDeny   = "d:" // Deny
)

// fakeTelegram is a fake Bot API server behind a fake HTTPS proxy. It
// answers like Telegram, and keeps every call, for the checks and for the
// canary search.
type fakeTelegram struct {
	token     string // the made-up bot token
	proxyAddr string // the fake proxy
	caFile    string // SSL_CERT_FILE of the broker: the test CA
	caDir     string // SSL_CERT_DIR of the broker: an empty directory

	mu         sync.Mutex
	calls      []tgCall
	updates    []tgUpdate
	nextUpdate int64
	nextMsg    int64
	markups    map[int64]json.RawMessage // the buttons of each message, by message ID
	connects   []string                  // what the proxy was asked to connect to
	changed    chan struct{}             // closed and made new on each change
}

// tgCall is one call that the fake got.
type tgCall struct {
	method  string
	body    []byte   // the request body
	msgID   int64    // sendMessage: the message ID of its answer; editMessageText: the message it edits
	buttons []string // sendMessage: the data of its buttons
}

// tgUpdate is a queued update.
type tgUpdate struct {
	id  int64
	raw []byte
}

// tgMessage is a message with buttons: the message of a request.
type tgMessage struct {
	id        int64    // the message ID
	requestID string   // the request ID in the button data
	buttons   []string // the button data
	text      string   // the text that the person sees: HTML tags removed, entities decoded
}

// newFakeTelegram starts a fake Telegram server and its proxy, until the
// test ends. The certificate of its test CA goes into the directory dir.
func newFakeTelegram(t *testing.T, dir string) *fakeTelegram {
	t.Helper()
	f := &fakeTelegram{
		token:      newBotToken(t),
		nextUpdate: 1000,
		nextMsg:    500,
		markups:    make(map[int64]json.RawMessage),
		changed:    make(chan struct{}),
	}
	caPEM, leaf := newTestCA(t)
	f.caFile = filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(f.caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	f.caDir = filepath.Join(dir, "none")
	if err := os.Mkdir(f.caDir, 0o700); err != nil {
		t.Fatal(err)
	}

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.proxyAddr = ln.Addr().String()
	tunnels := &chanListener{conns: make(chan net.Conn), done: make(chan struct{}), addr: ln.Addr()}
	srv := &http.Server{Handler: f, ReadHeaderTimeout: waitLimit}
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
		wg.Wait()
	})
	return f
}

// newBotToken returns a made-up bot token: digits, ":", and 35 random
// characters.
func newBotToken(t *testing.T) string {
	t.Helper()
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000_000))
	if err != nil {
		t.Fatal(err)
	}
	secret := strings.Map(func(r rune) rune {
		if r >= '2' && r <= '7' {
			return r
		}
		return r | 0x20 // some lower-case letters
	}, rand.Text()+rand.Text())
	return strconv.FormatInt(1_000_000_000+n.Int64(), 10) + ":" + secret[:35]
}

// connect handles one connection to the fake proxy: a CONNECT to
// api.telegram.org, then TLS with the test CA's certificate, and the
// fake's HTTP server. Anything else is refused.
func (f *fakeTelegram) connect(c net.Conn, cfg *tls.Config, tunnels *chanListener) {
	_ = c.SetReadDeadline(time.Now().Add(waitLimit))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		_ = c.Close()
		return
	}
	f.mu.Lock()
	f.connects = append(f.connects, req.Method+" "+req.Host)
	f.mu.Unlock()
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
		Subject:               pkix.Name{CommonName: "nodkey e2e test CA"},
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
	call := tgCall{method: method, body: body, msgID: p.MessageID}
	f.mu.Lock()
	if method == "sendMessage" {
		f.nextMsg++
		call.msgID = f.nextMsg
		call.buttons = buttonData(p.ReplyMarkup)
		f.markups[call.msgID] = p.ReplyMarkup
	}
	f.calls = append(f.calls, call)
	f.notifyLocked()
	f.mu.Unlock()

	message := func(id int64) string {
		return fmt.Sprintf(`{"ok":true,"result":{"message_id":%d,"date":1,"chat":{"id":%d,"type":"private"},`+
			`"text":"the text"}}`, id, p.ChatID)
	}
	switch method {
	case "getUpdates":
		f.serveUpdates(w, r, p.Offset, time.Duration(p.Timeout)*time.Second)
	case "sendMessage":
		writeTelegram(w, http.StatusOK, message(call.msgID))
	case "editMessageText", "editMessageReplyMarkup":
		writeTelegram(w, http.StatusOK, message(p.MessageID))
	case "answerCallbackQuery":
		writeTelegram(w, http.StatusOK, `{"ok":true,"result":true}`)
	default:
		writeTelegram(w, http.StatusNotFound, `{"ok":false,"error_code":404,"description":"Not Found"}`)
	}
}

// serveUpdates answers getUpdates: the queued updates from offset on, or
// none after wait, as Telegram's long polling does.
func (f *fakeTelegram) serveUpdates(w http.ResponseWriter, r *http.Request, offset int64, wait time.Duration) {
	timer := time.NewTimer(min(max(wait, time.Second), 50*time.Second))
	defer timer.Stop()
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
			writeTelegram(w, http.StatusOK, `{"ok":true,"result":[`+strings.Join(parts, ",")+`]}`)
			return
		}
		select {
		case <-changed:
		case <-timer.C:
			writeTelegram(w, http.StatusOK, `{"ok":true,"result":[]}`)
			return
		case <-r.Context().Done():
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

// waitFor waits until cond, which runs with f.mu held, is true.
func (f *fakeTelegram) waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.NewTimer(waitLimit)
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
			t.Fatalf("waited %s in vain for %s", waitLimit, what)
		}
	}
}

// messagesLocked returns every message that the broker sent: those with
// buttons, of requests, and those without, alerts and notices.
func (f *fakeTelegram) messagesLocked() []tgCall {
	var out []tgCall
	for _, c := range f.calls {
		if c.method == "sendMessage" {
			out = append(out, c)
		}
	}
	return out
}

// sent returns how many messages the fake got, with buttons or without.
func (f *fakeTelegram) sent() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.messagesLocked())
}

// waitMessage waits for the n-th message, and returns it. The program p
// asks for it, and waits for the tap. waitMessage fails when that message
// has no buttons, an alert or a notice, which this test never expects,
// and when p ends first: then no message comes.
func (f *fakeTelegram) waitMessage(t *testing.T, n int, p *proc) tgMessage {
	t.Helper()
	deadline := time.NewTimer(waitLimit)
	defer deadline.Stop()
	for ended := false; ; {
		f.mu.Lock()
		got, changed := len(f.messagesLocked()) >= n, f.changed
		f.mu.Unlock()
		switch {
		case got:
		case ended:
			t.Fatalf("%s ended before message %d came; its output:\n%s", p.name, n, p.output())
		default:
			select {
			case <-changed:
			case <-p.done:
				ended = true // look once more: the message may have come just before
			case <-deadline.C:
				t.Fatalf("waited %s in vain for message %d", waitLimit, n)
			}
			continue
		}
		break
	}
	f.mu.Lock()
	c := f.messagesLocked()[n-1]
	f.mu.Unlock()
	text := shownText(t, c.body)
	if len(c.buttons) == 0 {
		t.Fatalf("message %d has no buttons: an alert or a notice went out:\n%s", n, redact(text))
	}
	_, id, _ := strings.Cut(c.buttons[len(c.buttons)-1], ":")
	return tgMessage{id: c.msgID, requestID: id, buttons: c.buttons, text: text}
}

// unasked returns the text of each message without buttons: an alert or a
// notice.
func (f *fakeTelegram) unasked(t *testing.T) []string {
	t.Helper()
	f.mu.Lock()
	calls := f.messagesLocked()
	f.mu.Unlock()
	var out []string
	for _, c := range calls {
		if len(c.buttons) == 0 {
			out = append(out, shownText(t, c.body))
		}
	}
	return out
}

// otherCalls returns every call to the fake, as the method and the body,
// except the messages with buttons and the edits of them: the calls that
// must not hold claimed text.
func (f *fakeTelegram) otherCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	asked := make(map[int64]bool)
	for _, c := range f.calls {
		if c.method == "sendMessage" && len(c.buttons) > 0 {
			asked[c.msgID] = true
		}
	}
	var out []string
	for _, c := range f.calls {
		switch {
		case c.method == "sendMessage" && len(c.buttons) > 0:
		case c.method == "editMessageText" && asked[c.msgID]:
		default:
			out = append(out, c.method+" "+string(c.body))
		}
	}
	return out
}

// shownText returns the text of a sendMessage or editMessageText body as
// the person sees it: the HTML of the message without its tags, with its
// entities decoded. The broker writes only <code> tags.
func shownText(t *testing.T, body []byte) string {
	t.Helper()
	var p struct {
		Text      string `json:"text"`
		ParseMode string `json:"parse_mode"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("a message body is not JSON: %v", err)
	}
	if p.ParseMode != "HTML" {
		t.Errorf("a message has parse_mode %q, want HTML", p.ParseMode)
	}
	plain := strings.NewReplacer("<code>", "", "</code>", "").Replace(p.Text)
	if strings.ContainsAny(plain, "<>") {
		t.Errorf("a message has HTML tags other than <code>: %q", redact(p.Text))
	}
	return html.UnescapeString(plain)
}

// tap presses the button of m whose data starts with prefix, as the
// approver, in the private chat, on the message with the buttons that the
// broker sent there. It returns the text that the phone shows. A tap can
// come before the broker knows that its message was sent; then the phone
// shows "Not ready yet. Tap again in a moment.", and the person taps
// again.
func (f *fakeTelegram) tap(t *testing.T, m tgMessage, prefix string) string {
	t.Helper()
	if !slices.Contains(m.buttons, prefix+m.requestID) {
		t.Fatalf("message %d has no button %s: its buttons are %q", m.id, prefix, m.buttons)
	}
	for try := 1; ; try++ {
		answer := f.waitTapAnswer(t, f.queueTap(t, m.id, prefix+m.requestID))
		if !strings.Contains(answer, "Not ready yet") {
			return answer
		}
		if try == 100 {
			t.Fatalf("every tap on message %d came too early", m.id)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// queueTap queues a press of the approver on the message msgID with the
// button data data, and returns the ID of the press (the callback query).
func (f *fakeTelegram) queueTap(t *testing.T, msgID int64, data string) string {
	t.Helper()
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
		t.Fatal(err)
	}
	f.updates = append(f.updates, tgUpdate{id: f.nextUpdate, raw: raw})
	f.notifyLocked()
	return id
}

// waitTapAnswer waits for the answer to the press id
// (answerCallbackQuery), and returns the text that the phone shows.
func (f *fakeTelegram) waitTapAnswer(t *testing.T, id string) string {
	t.Helper()
	var text string
	f.waitFor(t, "the answer to the press "+id, func() bool {
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

// waitResult waits until the broker has edited the message m to show the
// end of its request, and returns the last line of the new text, such as
// "👍 approved once by you at 14:02:41".
func (f *fakeTelegram) waitResult(t *testing.T, m tgMessage) string {
	t.Helper()
	var body []byte
	f.waitFor(t, fmt.Sprintf("the edit of message %d", m.id), func() bool {
		for _, c := range f.calls {
			if c.method == "editMessageText" && c.msgID == m.id {
				body = c.body
				return true
			}
		}
		return false
	})
	text := shownText(t, body)
	return text[strings.LastIndex(text, "\n")+1:]
}

// bodies returns every request body that the fake got, each after the name
// of its method.
func (f *fakeTelegram) bodies() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		out = append(out, c.method+" "+string(c.body))
	}
	return out
}

// shownTexts returns the text of every message and every edit of a
// message, as the person sees it.
func (f *fakeTelegram) shownTexts(t *testing.T) []string {
	t.Helper()
	f.mu.Lock()
	calls := slices.Clone(f.calls)
	f.mu.Unlock()
	var out []string
	for _, c := range calls {
		if c.method == "sendMessage" || c.method == "editMessageText" {
			out = append(out, shownText(t, c.body))
		}
	}
	return out
}

// proxied returns what the proxy was asked to connect to.
func (f *fakeTelegram) proxied() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.connects)
}
