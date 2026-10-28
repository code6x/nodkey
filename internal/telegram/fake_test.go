package telegram

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// The tests talk to a fake Telegram server on localhost, never to the
// real Bot API. All IDs and the bot token are made up; the token is made
// at run time, so the source holds nothing that looks like a token.

// Made-up Telegram IDs.
const (
	approverID   int64 = 7000001
	otherUserID  int64 = 7000002
	noticeChatID int64 = -100700003
	groupChatID  int64 = -100700004
)

// waitLimit bounds every wait of a test.
const waitLimit = 10 * time.Second

// newCanaryToken returns a new made-up bot token: digits, ":", and 35
// random base64url characters. Tests search all output for it.
func newCanaryToken(t testing.TB) string {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	id := 1_000_000_000 + uint64(binary.BigEndian.Uint32(b[:4]))%1_000_000_000
	secret := base64.RawURLEncoding.EncodeToString(b[4:])[:35]
	return strconv.FormatUint(id, 10) + ":" + secret
}

// fakeCall is one call that the fake server got.
type fakeCall struct {
	Method string
	Raw    []byte         // the request body
	Body   map[string]any // the request body, decoded with UseNumber
	MsgID  int64          // sendMessage: the message ID of its answer
}

func (c fakeCall) num(key string) int64 {
	n, ok := c.Body[key].(json.Number)
	if !ok {
		return 0
	}
	v, err := n.Int64()
	if err != nil {
		return 0
	}
	return v
}

func (c fakeCall) str(key string) string {
	s, _ := c.Body[key].(string)
	return s
}

func (c fakeCall) has(key string) bool {
	_, ok := c.Body[key]
	return ok
}

// field returns the raw JSON of a top-level field of the body, or "-".
func (c fakeCall) field(key string) string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(c.Raw, &m); err != nil {
		return "(not JSON)"
	}
	v, ok := m[key]
	if !ok {
		return "-"
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, v); err != nil {
		return "(not JSON)"
	}
	return buf.String()
}

// buttonData returns the callback data of each button in the body.
func (c fakeCall) buttonData() []string {
	var body struct {
		ReplyMarkup *inlineKeyboard `json:"reply_markup"`
	}
	if err := json.Unmarshal(c.Raw, &body); err != nil || body.ReplyMarkup == nil {
		return nil
	}
	var data []string
	for _, row := range body.ReplyMarkup.InlineKeyboard {
		for _, b := range row {
			data = append(data, b.CallbackData)
		}
	}
	return data
}

// requestID returns the request ID in the buttons of a sendMessage call.
func (c fakeCall) requestID() string {
	data := c.buttonData()
	if len(data) == 0 {
		return ""
	}
	return strings.TrimPrefix(data[len(data)-1], dataDeny)
}

// fakeReply is a scripted answer.
type fakeReply struct {
	status int
	body   string
}

// fakeUpdate is a queued update.
type fakeUpdate struct {
	id  int64
	raw json.RawMessage
}

// fakeMessage is a message that the fake sent, as Telegram keeps it.
type fakeMessage struct {
	chatID   int64
	markup   json.RawMessage // the reply_markup, or nil for none
	editDate int64           // 0 until it is edited
}

// fakeTelegram is a fake Bot API server. It answers like Telegram, unless
// a test scripted another answer for a method.
type fakeTelegram struct {
	t     testing.TB
	token string
	srv   *httptest.Server

	mu         sync.Mutex
	calls      []fakeCall
	updates    []fakeUpdate
	nextUpdate int64
	nextMsg    int64
	nextTap    int
	replies    map[string][]fakeReply
	held       map[string]chan struct{}
	messages   map[int64]*fakeMessage // by message ID
	presses    map[string]fakePress   // the presses that tap queued, by callback query ID
	changed    chan struct{}          // closed and made new on each change
	pollWait   time.Duration          // how long getUpdates waits for an update
	// pollsGone counts the getUpdates calls that ended because the client
	// went away before the answer: it closed the connection.
	pollsGone int
}

// fakePress is a button press that tap queued.
type fakePress struct {
	update int64 // its update ID
	calls  int   // how many calls the fake had when it was queued
}

func newFake(t testing.TB) *fakeTelegram {
	t.Helper()
	f := &fakeTelegram{
		t:          t,
		token:      newCanaryToken(t),
		nextUpdate: 1000,
		nextMsg:    500,
		replies:    make(map[string][]fakeReply),
		held:       make(map[string]chan struct{}),
		messages:   make(map[int64]*fakeMessage),
		presses:    make(map[string]fakePress),
		changed:    make(chan struct{}),
		pollWait:   time.Second,
	}
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	return f
}

// notifyLocked wakes the waiters. f.mu must be held.
func (f *fakeTelegram) notifyLocked() {
	close(f.changed)
	f.changed = make(chan struct{})
}

func writeBody(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func (f *fakeTelegram) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest, ok := strings.CutPrefix(r.URL.Path, "/bot")
	token, method, ok2 := strings.Cut(rest, "/")
	if !ok || !ok2 || token != f.token {
		writeBody(w, http.StatusUnauthorized, `{"ok":false,"error_code":401,"description":"Unauthorized"}`)
		return
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}
	body := map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	_ = dec.Decode(&body) // a test checks the fields it needs
	call := fakeCall{Method: method, Raw: raw, Body: body}
	f.mu.Lock()
	if method == "sendMessage" {
		f.nextMsg++
		call.MsgID = f.nextMsg
	}
	f.calls = append(f.calls, call)
	var reply *fakeReply
	if q := f.replies[method]; len(q) > 0 {
		reply = &q[0]
		f.replies[method] = q[1:]
	} else {
		// Telegram has the message, or the edit, even when its answer
		// comes late. It is kept with the call in one step, so a test
		// that sees the call also sees the message as the call left it.
		f.keepLocked(call)
	}
	hold := f.held[method]
	f.notifyLocked()
	f.mu.Unlock()

	if hold != nil {
		select {
		case <-hold:
		case <-r.Context().Done():
			return
		}
	}
	if reply != nil {
		writeBody(w, reply.status, reply.body)
		return
	}
	switch method {
	case "getUpdates":
		f.serveUpdates(w, r, call)
	case "sendMessage":
		chatType := "private"
		if call.num("chat_id") < 0 {
			chatType = "supergroup"
		}
		msg, _ := json.Marshal(map[string]any{
			"message_id": call.MsgID, "date": 1,
			"chat": map[string]any{"id": call.num("chat_id"), "type": chatType},
			"text": "the text",
		})
		writeBody(w, http.StatusOK, `{"ok":true,"result":`+string(msg)+`}`)
	case "editMessageText", "editMessageReplyMarkup":
		msg, _ := json.Marshal(map[string]any{
			"message_id": call.num("message_id"), "date": 1, "edit_date": 2,
			"chat": map[string]any{"id": call.num("chat_id"), "type": "private"},
			"text": "the text",
		})
		writeBody(w, http.StatusOK, `{"ok":true,"result":`+string(msg)+`}`)
	case "answerCallbackQuery":
		writeBody(w, http.StatusOK, `{"ok":true,"result":true}`)
	default:
		writeBody(w, http.StatusNotFound, `{"ok":false,"error_code":404,"description":"Not Found"}`)
	}
}

// keepLocked notes what a call that worked changes in the messages, as
// Telegram keeps them: a new message, or an edit. f.mu must be held.
func (f *fakeTelegram) keepLocked(c fakeCall) {
	var body struct {
		ReplyMarkup json.RawMessage `json:"reply_markup"`
	}
	_ = json.Unmarshal(c.Raw, &body) // the fields come from the client
	switch c.Method {
	case "sendMessage":
		f.messages[c.MsgID] = &fakeMessage{chatID: c.num("chat_id"), markup: body.ReplyMarkup}
	case "editMessageText", "editMessageReplyMarkup":
		if m := f.messages[c.num("message_id")]; m != nil {
			m.markup, m.editDate = body.ReplyMarkup, 2
		}
	}
}

// editByOther changes the message msgID as someone else with the bot
// token would: it gets an edit date, and, if markup is set, new buttons.
// With markup nil, the buttons stay, as after an edit that sends the same
// buttons again (check 8 of docs/manual-telegram-test.md). A real edit
// without reply_markup removes the buttons.
func (f *fakeTelegram) editByOther(msgID int64, markup any, editDate bool) {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.messages[msgID]
	if m == nil {
		f.t.Fatalf("the fake did not send message %d", msgID)
	}
	if markup != nil {
		raw, err := json.Marshal(markup)
		if err != nil {
			f.t.Fatal(err)
		}
		m.markup = raw
	}
	if editDate {
		m.editDate = 4
	}
}

// serveUpdates answers getUpdates: the queued updates from offset on, at
// most limit, or none after pollWait.
func (f *fakeTelegram) serveUpdates(w http.ResponseWriter, r *http.Request, call fakeCall) {
	offset, limit := call.num("offset"), int(call.num("limit"))
	if limit <= 0 {
		limit = 100
	}
	deadline := time.NewTimer(f.pollWait)
	defer deadline.Stop()
	for {
		f.mu.Lock()
		f.updates = slices.DeleteFunc(f.updates, func(u fakeUpdate) bool { return u.id < offset })
		if len(f.updates) > 0 {
			var parts []string
			for _, u := range f.updates[:min(limit, len(f.updates))] {
				parts = append(parts, string(u.raw))
			}
			f.mu.Unlock()
			writeBody(w, http.StatusOK, `{"ok":true,"result":[`+strings.Join(parts, ",")+`]}`)
			return
		}
		changed := f.changed
		f.mu.Unlock()
		select {
		case <-changed:
		case <-deadline.C:
			writeBody(w, http.StatusOK, `{"ok":true,"result":[]}`)
			return
		case <-r.Context().Done():
			f.mu.Lock()
			f.pollsGone++
			f.notifyLocked()
			f.mu.Unlock()
			return
		}
	}
}

// reply makes the next call of method get this answer.
func (f *fakeTelegram) reply(method string, status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.replies[method] = append(f.replies[method], fakeReply{status: status, body: body})
}

// hold makes the calls of method wait, after the fake noted them, until
// release is called.
func (f *fakeTelegram) hold(method string) (release func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch := make(chan struct{})
	f.held[method] = ch
	var once sync.Once
	return func() {
		once.Do(func() {
			f.mu.Lock()
			delete(f.held, method)
			f.mu.Unlock()
			close(ch)
		})
	}
}

// addUpdateLocked queues an update and returns its ID. f.mu must be held.
func (f *fakeTelegram) addUpdateLocked(u map[string]any) int64 {
	f.nextUpdate++
	u["update_id"] = f.nextUpdate
	raw, err := json.Marshal(u)
	if err != nil {
		f.t.Fatal(err)
	}
	f.updates = append(f.updates, fakeUpdate{id: f.nextUpdate, raw: raw})
	f.notifyLocked()
	return f.nextUpdate
}

// addRawUpdate queues an update as raw JSON with this ID.
func (f *fakeTelegram) addRawUpdate(id int64, raw string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updates = append(f.updates, fakeUpdate{id: id, raw: json.RawMessage(raw)})
	f.notifyLocked()
}

// tapSpec describes a button press.
type tapSpec struct {
	from      int64
	chatID    int64
	chatType  string
	msgID     int64
	data      string
	inline    bool   // a button of an inline message: no message
	noMessage bool   // no message and no inline message ID
	text      string // the text of the message
	game      string
	// The message as Telegram has it, if the fake sent it: its buttons
	// and its edit date go into the press. These change that.
	edited bool // the press says the message was edited
	markup any  // the buttons in the press, instead of the fake's
	bare   bool // the press holds no buttons and no edit date
}

// goodTap returns a press by the approver in the private chat on message
// msgID.
func goodTap(msgID int64, data string) tapSpec {
	return tapSpec{from: approverID, chatID: approverID, chatType: "private", msgID: msgID, data: data}
}

// tap queues a button press and returns its callback query ID. The press
// holds the message as the fake has it at this moment.
func (f *fakeTelegram) tap(s tapSpec) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextTap++
	id := "cb" + strconv.Itoa(f.nextTap)
	q := map[string]any{
		"id":            id,
		"from":          map[string]any{"id": s.from, "is_bot": false, "first_name": "Test"},
		"chat_instance": "42",
		"data":          s.data,
	}
	if s.game != "" {
		q["game_short_name"] = s.game
	}
	switch {
	case s.inline:
		q["inline_message_id"] = "inline-1"
	case s.noMessage:
	default:
		text := s.text
		if text == "" {
			text = "the text"
		}
		m := map[string]any{
			"message_id": s.msgID, "date": 1, "text": text,
			"chat": map[string]any{"id": s.chatID, "type": s.chatType},
		}
		if kept := f.messages[s.msgID]; kept != nil && kept.chatID == s.chatID && !s.bare {
			if !emptyMarkup(kept.markup) {
				m["reply_markup"] = kept.markup
			}
			if kept.editDate != 0 {
				m["edit_date"] = kept.editDate
			}
		}
		if s.edited {
			m["edit_date"] = 3
		}
		if s.markup != nil {
			m["reply_markup"] = s.markup
		}
		q["message"] = m
	}
	update := f.addUpdateLocked(map[string]any{"callback_query": q})
	f.presses[id] = fakePress{update: update, calls: len(f.calls)}
	return id
}

// emptyMarkup reports whether a reply_markup has no buttons. Telegram then
// leaves it out of a message.
func emptyMarkup(raw json.RawMessage) bool {
	var k inlineKeyboard
	if len(raw) == 0 || json.Unmarshal(raw, &k) != nil {
		return true
	}
	for _, row := range k.InlineKeyboard {
		if len(row) > 0 {
			return false
		}
	}
	return true
}

// waitFor waits until cond, which runs with f.mu held, is true.
func (f *fakeTelegram) waitFor(what string, cond func() bool) {
	f.t.Helper()
	timer := time.NewTimer(waitLimit)
	defer timer.Stop()
	for {
		f.mu.Lock()
		ok, changed := cond(), f.changed
		f.mu.Unlock()
		if ok {
			return
		}
		select {
		case <-changed:
		case <-timer.C:
			f.t.Fatalf("waited %s in vain for %s", waitLimit, what)
		}
	}
}

// callsOf returns the calls of method, oldest first.
func (f *fakeTelegram) callsOf(method string) []fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.callsOfLocked(method)
}

func (f *fakeTelegram) callsOfLocked(method string) []fakeCall {
	var out []fakeCall
	for _, c := range f.calls {
		if c.Method == method {
			out = append(out, c)
		}
	}
	return out
}

// allCalls returns every call, oldest first.
func (f *fakeTelegram) allCalls() []fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// waitCalls waits until method was called n times, and returns the calls.
func (f *fakeTelegram) waitCalls(method string, n int) []fakeCall {
	f.t.Helper()
	f.waitFor(strconv.Itoa(n)+" calls of "+method, func() bool { return len(f.callsOfLocked(method)) >= n })
	return f.callsOf(method)
}

// waitAnswer waits for the answerCallbackQuery of the press id.
func (f *fakeTelegram) waitAnswer(id string) fakeCall {
	f.t.Helper()
	return f.waitAnswers(id, 1)[0]
}

// waitAnswers waits until the press id got n answers, and returns them,
// oldest first. A press gets more than one when Telegram sends it again,
// such as after a restart.
func (f *fakeTelegram) waitAnswers(id string, n int) []fakeCall {
	f.t.Helper()
	var found []fakeCall
	f.waitFor(strconv.Itoa(n)+" answers to button press "+id, func() bool {
		found = nil
		for _, c := range f.callsOfLocked("answerCallbackQuery") {
			if c.str("callback_query_id") == id {
				found = append(found, c)
			}
		}
		return len(found) >= n
	})
	return found
}

// waitHandled waits until Run is done with the press id, which tap
// queued: it answered it, reported it if it did not count, and updated its
// message if it does that. Run handles one update after the other, and it
// asks for more updates only when it is done with the ones it has. So a
// getUpdates call that came after the press, with an offset past it,
// shows that Run is done with the press.
func (f *fakeTelegram) waitHandled(id string) {
	f.t.Helper()
	f.mu.Lock()
	p, ok := f.presses[id]
	f.mu.Unlock()
	if !ok {
		f.t.Fatalf("tap did not queue a button press %s", id)
	}
	f.waitFor("the end of button press "+id, func() bool {
		for _, c := range f.calls[p.calls:] {
			if c.Method == "getUpdates" && c.num("offset") > p.update {
				return true
			}
		}
		return false
	})
}

// syncBuffer is a bytes.Buffer for many goroutines.
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

// sleepLog records the waits of the client, and does not wait.
type sleepLog struct {
	mu    sync.Mutex
	waits []time.Duration
}

func (s *sleepLog) sleep(ctx context.Context, d time.Duration) error {
	s.mu.Lock()
	s.waits = append(s.waits, d)
	s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	time.Sleep(time.Millisecond) // so a loop does not spin hot
	return nil
}

func (s *sleepLog) all() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.waits)
}

// tapLog records the reports for the audit log.
type tapLog struct {
	mu   sync.Mutex
	taps []audit.ForeignTap
}

func (l *tapLog) add(t audit.ForeignTap) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.taps = append(l.taps, t)
}

func (l *tapLog) all() []audit.ForeignTap {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.taps)
}

// testEnv is an Approver that talks to a fake server.
type testEnv struct {
	f      *fakeTelegram
	a      *Approver
	logs   *syncBuffer // text lines of the logger
	sleeps *sleepLog
	taps   *tapLog
}

func testTelegramConfig() config.Telegram {
	return config.Telegram{
		TokenFile:    "/run/credentials/nodkey.service/telegram-token",
		UserID:       approverID,
		NoticeChatID: noticeChatID,
		Timeout:      120 * time.Second,
		SSHTimeout:   90 * time.Second,
	}
}

// newEnv returns an Approver for a new fake server.
func newEnv(t *testing.T) *testEnv {
	t.Helper()
	return newEnvFor(t, newFake(t))
}

// newEnvFor returns an Approver for the fake server f.
func newEnvFor(t *testing.T, f *fakeTelegram) *testEnv {
	t.Helper()
	e := &testEnv{f: f, logs: &syncBuffer{}, sleeps: &sleepLog{}, taps: &tapLog{}}
	logger := slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	read := func(string) ([]byte, error) { return []byte(f.token + "\n"), nil }
	a, err := newApprover(testTelegramConfig(), Options{Logger: logger, ForeignTap: e.taps.add}, read, f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	a.api.timeout = 3 * time.Second
	a.api.pollTimeout = 5 * time.Second
	a.api.sleep = e.sleeps.sleep
	e.a = a
	return e
}

// run starts Run with answer. stop cancels it and returns its error. The
// test cleanup stops it too, before the fake server closes.
func (e *testEnv) run(t *testing.T, answer func(approval.Answer) error) (stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.a.Run(ctx, answer) }()
	var once sync.Once
	var err error
	stop = func() error {
		once.Do(func() {
			cancel()
			select {
			case err = <-done:
			case <-time.After(waitLimit):
				t.Error("Run did not return")
			}
		})
		return err
	}
	t.Cleanup(func() { _ = stop() })
	return stop
}

// runToEnd runs Run with answer until it returns on its own, and returns
// its error.
func (e *testEnv) runToEnd(t *testing.T, answer func(approval.Answer) error) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.a.Run(ctx, answer) }()
	select {
	case err := <-done:
		return err
	case <-time.After(waitLimit):
		t.Fatal("Run did not return")
		return nil
	}
}

// stubCore is a stand-in for the approval core: it notes each answer and
// returns err.
type stubCore struct {
	mu      sync.Mutex
	answers []approval.Answer
	err     error
}

func (s *stubCore) answer(a approval.Answer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.answers = append(s.answers, a)
	return s.err
}

func (s *stubCore) all() []approval.Answer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.answers)
}

func (s *stubCore) setErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

// testID returns a valid request ID made from n.
func testID(n byte) string {
	var b [16]byte
	for i := range b {
		b[i] = n + byte(i)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
