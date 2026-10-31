package ntfy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
)

// fakeServer is a small ntfy server: publish as JSON on "/", a POST of
// text to a topic, and a JSON stream of a topic. Tokens are made at run
// time.
type fakeServer struct {
	t                       *testing.T
	srv                     *httptest.Server
	publishToken, readToken string
	requestTopic, answer    string

	mu        sync.Mutex
	published []publishMessage    // the messages on "/", in order
	answers   []fakeMessage       // the messages of the answer topic
	subs      map[int]chan []byte // the open streams
	nextSub   int
	nextID    int
	// replayAll makes a stream send every message of the topic, whatever
	// since says: a server that sends a message twice.
	replayAll bool
	// failPublish, if not 0, is the status of every publish.
	failPublish int
	// closeAtOnce makes a stream end right after its open event.
	closeAtOnce bool
	// connected gets a value when a stream opens.
	connected chan struct{}
	// since holds the since parameter of each stream.
	since []string
}

type fakeMessage struct {
	id   string
	time int64
	line []byte
}

func randomToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 15)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "tk_" + hex.EncodeToString(b)
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	f := &fakeServer{
		t:            t,
		publishToken: randomToken(t),
		readToken:    randomToken(t),
		requestTopic: "nodkey-requests",
		answer:       "nodkey-answers",
		subs:         make(map[int]chan []byte),
		connected:    make(chan struct{}, 100),
	}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(func() {
		f.drop()
		f.srv.Close()
	})
	return f
}

func (f *fakeServer) newID() string {
	f.nextID++
	return fmt.Sprintf("m%011d", f.nextID)
}

func (f *fakeServer) serve(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/":
		f.publish(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/"+f.answer:
		f.post(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/"+f.answer+"/json":
		f.stream(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (f *fakeServer) publish(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+f.publishToken {
		http.Error(w, `{"code":40101,"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var m publishMessage
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	if f.failPublish != 0 {
		status := f.failPublish
		f.mu.Unlock()
		http.Error(w, "failed", status)
		return
	}
	f.published = append(f.published, m)
	id := f.newID()
	f.mu.Unlock()
	if m.Topic != f.requestTopic {
		f.t.Errorf("publish to topic %q", m.Topic)
	}
	if len(m.Message) > maxMessageBytes {
		f.t.Errorf("publish of %d bytes: ntfy would send an attachment", len(m.Message))
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "time": time.Now().Unix(), "event": "message", "topic": m.Topic})
}

// post is a POST of text to the answer topic: the press of an http
// button, or anyone else who writes there.
func (f *fakeServer) post(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	f.add(string(body), nil)
	_, _ = io.WriteString(w, `{"id":"x","event":"message"}`)
}

// add puts a message with the text body on the answer topic, with extra
// fields, and sends it to the open streams.
func (f *fakeServer) add(body string, extra map[string]any) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := f.newID()
	ev := map[string]any{"id": id, "time": time.Now().Unix(), "expires": time.Now().Add(time.Hour).Unix(),
		"event": "message", "topic": f.answer, "message": body}
	for k, v := range extra {
		ev[k] = v
	}
	line, _ := json.Marshal(ev)
	line = append(line, '\n')
	f.answers = append(f.answers, fakeMessage{id: id, time: time.Now().Unix(), line: line})
	for _, c := range f.subs {
		select {
		case c <- line:
		default:
			f.t.Errorf("a stream is full")
		}
	}
	return id
}

// addLine sends a raw line to the open streams.
func (f *fakeServer) addLine(line []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.subs {
		c <- append(line, '\n')
	}
}

func (f *fakeServer) stream(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+f.readToken {
		http.Error(w, `{"code":40301,"error":"forbidden"}`, http.StatusForbidden)
		return
	}
	since := r.URL.Query().Get("since")
	c := make(chan []byte, 4096)
	f.mu.Lock()
	f.since = append(f.since, since)
	var old [][]byte
	switch {
	case f.replayAll:
		for _, m := range f.answers {
			old = append(old, m.line)
		}
	case since == "":
	default:
		ts, err := strconv.ParseInt(since, 10, 64)
		after := false
		for _, m := range f.answers {
			if (err == nil && m.time >= ts) || after {
				old = append(old, m.line)
			}
			if m.id == since {
				after = true
			}
		}
	}
	id := f.nextSub
	f.nextSub++
	f.subs[id] = c
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		delete(f.subs, id)
		f.mu.Unlock()
	}()

	w.Header().Set("Content-Type", "application/x-ndjson")
	fl := w.(http.Flusher)
	_, _ = fmt.Fprintf(w, `{"id":"open1","time":%d,"event":"open","topic":%q}`+"\n", time.Now().Unix(), f.answer)
	for _, l := range old {
		_, _ = w.Write(l)
	}
	fl.Flush()
	select {
	case f.connected <- struct{}{}:
	default:
	}
	f.mu.Lock()
	closeNow := f.closeAtOnce
	f.mu.Unlock()
	if closeNow {
		return
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case l, ok := <-c:
			if !ok {
				return // dropped
			}
			_, _ = w.Write(l)
			fl.Flush()
		}
	}
}

// drop closes every open stream: the subscription is lost.
func (f *fakeServer) drop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, c := range f.subs {
		close(c)
		delete(f.subs, id)
	}
}

// waitConnected waits until a stream opens.
func (f *fakeServer) waitConnected() {
	f.t.Helper()
	select {
	case <-f.connected:
	case <-time.After(10 * time.Second):
		f.t.Fatal("no stream opened")
	}
}

// last returns the newest published message.
func (f *fakeServer) last() publishMessage {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.published) == 0 {
		f.t.Fatal("nothing published")
	}
	return f.published[len(f.published)-1]
}

func (f *fakeServer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.published)
}

// press presses the button with the label of m, as the phone does: a POST
// of its body to its URL.
func (f *fakeServer) press(m publishMessage, label string) {
	f.t.Helper()
	for _, a := range m.Actions {
		if a.Label != label {
			continue
		}
		req, err := http.NewRequestWithContext(context.Background(), a.Method, a.URL, strings.NewReader(a.Body))
		if err != nil {
			f.t.Fatal(err)
		}
		resp, err := f.srv.Client().Do(req)
		if err != nil {
			f.t.Fatal(err)
		}
		_ = resp.Body.Close()
		return
	}
	f.t.Fatalf("no button %q", label)
}

func (f *fakeServer) config() Config {
	pt, err := NewToken(f.publishToken)
	if err != nil {
		f.t.Fatal(err)
	}
	rt, err := NewToken(f.readToken)
	if err != nil {
		f.t.Fatal(err)
	}
	return Config{Server: f.srv.URL, RequestTopic: f.requestTopic, AnswerTopic: f.answer, PublishToken: pt, ReadToken: rt}
}

// logBuffer collects log lines, safe for many goroutines.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// fakeCore is the core's rule of one answer: the first answer to a
// request that waits counts; later ones get ErrUnknownRequest.
type fakeCore struct {
	mu      sync.Mutex
	waiting map[string]approval.MessageID
	got     chan approval.Answer
	calls   int
}

func newFakeCore() *fakeCore {
	return &fakeCore{waiting: make(map[string]approval.MessageID), got: make(chan approval.Answer, 100)}
}

func (c *fakeCore) wait(id string, m approval.MessageID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.waiting[id] = m
}

func (c *fakeCore) answer(a approval.Answer) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	m, ok := c.waiting[a.RequestID]
	if !ok {
		return approval.ErrUnknownRequest
	}
	if m != a.Message {
		return approval.ErrWrongMessage
	}
	if a.Action != audit.AnswerRevoke {
		delete(c.waiting, a.RequestID)
	}
	c.got <- a
	return nil
}

func (c *fakeCore) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// expect waits for one counted answer.
func (c *fakeCore) expect(t *testing.T) approval.Answer {
	t.Helper()
	select {
	case a := <-c.got:
		return a
	case <-time.After(10 * time.Second):
		t.Fatal("no answer counted")
	}
	return approval.Answer{}
}

// none checks that no answer counts for a while.
func (c *fakeCore) none(t *testing.T) {
	t.Helper()
	select {
	case a := <-c.got:
		t.Fatalf("an answer counted: %+v", a)
	case <-time.After(200 * time.Millisecond):
	}
}

// harness is an approver with a fake server and a fake core, with Run
// running.
type harness struct {
	t    *testing.T
	f    *fakeServer
	a    *Approver
	core *fakeCore
	logs *logBuffer
	done chan error
}

func newApproverFor(t *testing.T, f *fakeServer, logs *logBuffer) *Approver {
	t.Helper()
	a, err := newApprover(f.config(), Options{Logger: slog.New(slog.NewTextHandler(logs, nil))}, f.srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	a.firstBackoff, a.maxBackoff = 10*time.Millisecond, 50*time.Millisecond
	a.api.sleep = func(ctx context.Context, _ time.Duration) error { return sleep(ctx, time.Millisecond) }
	return a
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	f := newFakeServer(t)
	h := &harness{t: t, f: f, core: newFakeCore(), logs: &logBuffer{}, done: make(chan error, 1)}
	h.a = newApproverFor(t, f, h.logs)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { h.done <- h.a.Run(ctx, h.core.answer) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-h.done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("Run returned %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("Run did not return")
		}
	})
	f.waitConnected()
	return h
}

// ask asks p and tells the fake core that p waits on its message.
func (h *harness) ask(p approval.Prompt) (approval.Shown, publishMessage) {
	h.t.Helper()
	s, err := h.a.Ask(context.Background(), p)
	if err != nil {
		h.t.Fatal(err)
	}
	h.core.wait(p.RequestID, s.ID)
	return s, h.f.last()
}

func newRequestID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// secretsPrompt is the prompt of a secrets request with all three buttons.
func secretsPrompt(t *testing.T) approval.Prompt {
	t.Helper()
	return approval.Prompt{
		RequestID: newRequestID(t), ShortCode: "k3f9", Kind: audit.KindSecrets,
		Client: "laptop", Secrets: []string{"GH_TOKEN"},
		Claim:   approval.Claim{Vars: "GH_TOKEN", Command: "gh pr list", Dir: "/home/dev/app", Reason: "list the PRs"},
		Expires: time.Now().Add(90 * time.Second), TimeLeft: 90 * time.Second,
		Once: true, WindowMinutes: 15,
	}
}

// valueOf returns the value in the buttons of m.
func valueOf(t *testing.T, m publishMessage) string {
	t.Helper()
	if len(m.Actions) == 0 {
		t.Fatal("no buttons")
	}
	var b answerBody
	if err := json.Unmarshal([]byte(m.Actions[0].Body), &b); err != nil {
		t.Fatal(err)
	}
	return b.Value
}

// postAnswer posts an answer body to the answer topic, as anyone could.
func (h *harness) postAnswer(id, action, value string) {
	h.t.Helper()
	body, _ := json.Marshal(answerBody{Request: id, Action: action, Value: value})
	h.f.add(string(body), nil)
}
