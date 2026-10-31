package ntfy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
)

func TestAskPayload(t *testing.T) {
	h := newHarness(t)
	p := secretsPrompt(t)
	s, m := h.ask(p)

	if m.Priority != priorityAsk || m.SequenceID != "" || m.Title != "🔑 Secrets · request k3f9" {
		t.Errorf("message: priority %d, sequence %q, title %q", m.Priority, m.SequenceID, m.Title)
	}
	wantLabels := []string{"Approve once", "Approve 15 min", "Deny"}
	wantActions := []string{"once", "window", "deny"}
	if len(m.Actions) != 3 {
		t.Fatalf("got %d buttons, want 3", len(m.Actions))
	}
	value := valueOf(t, m)
	for i, a := range m.Actions {
		if a.Label != wantLabels[i] || a.Action != "http" || a.Method != http.MethodPost || !a.Clear ||
			a.URL != h.f.srv.URL+"/"+h.f.answer {
			t.Errorf("button %d: %+v", i, a)
		}
		var b answerBody
		if err := json.Unmarshal([]byte(a.Body), &b); err != nil {
			t.Fatal(err)
		}
		if b.Request != p.RequestID || b.Action != wantActions[i] || b.Value != value {
			t.Errorf("button %d body: %+v", i, b)
		}
	}
	if len(value) != 22 || value == p.RequestID {
		t.Errorf("value %q is not a new 16-byte value", value)
	}
	if strings.Contains(string(s.ID), value) || strings.Contains(s.Text, value) || strings.Contains(m.Message, value) {
		t.Error("the value is in the message ID or the text")
	}
	for _, want := range []string{"✅ machine: laptop", "✅ secrets: GH_TOKEN", claimedHead, "command: gh pr list",
		"[ Approve once ] [ Approve 15 min ] [ Deny ]"} {
		if !strings.Contains(s.Text, want) {
			t.Errorf("text has no %q:\n%s", want, s.Text)
		}
	}
	if strings.Contains(h.logs.String(), value) {
		t.Error("the value is in the log")
	}

	// A second request gets another value; without a window, no such
	// button.
	p2 := secretsPrompt(t)
	p2.WindowMinutes = 0
	_, m2 := h.ask(p2)
	if len(m2.Actions) != 2 || m2.Actions[0].Label != "Approve once" || m2.Actions[1].Label != "Deny" {
		t.Errorf("buttons without a window: %+v", m2.Actions)
	}
	if valueOf(t, m2) == value {
		t.Error("two requests have the same value")
	}
}

func TestAnswerCounts(t *testing.T) {
	for _, label := range []string{"Approve once", "Approve 15 min", "Deny"} {
		t.Run(label, func(t *testing.T) {
			h := newHarness(t)
			p := secretsPrompt(t)
			s, m := h.ask(p)
			h.f.press(m, label)
			got := h.core.expect(t)
			want := map[string]audit.Answer{"Approve once": audit.AnswerApproveOnce,
				"Approve 15 min": audit.AnswerApproveWindow, "Deny": audit.AnswerDeny}[label]
			if got.RequestID != p.RequestID || got.Action != want || got.Message != s.ID || got.UserID != 0 {
				t.Errorf("answer %+v", got)
			}
		})
	}
}

func TestWrongValue(t *testing.T) {
	h := newHarness(t)
	p := secretsPrompt(t)
	_, m := h.ask(p)
	other := newRequestID(t) // 16 random bytes, not the value
	h.postAnswer(p.RequestID, "once", other)
	h.core.none(t)
	if h.core.callCount() != 0 {
		t.Error("a wrong value reached the core")
	}
	// The request still waits: the right value counts.
	h.f.press(m, "Approve once")
	h.core.expect(t)
}

func TestValueOfAnotherRequest(t *testing.T) {
	h := newHarness(t)
	p1, p2 := secretsPrompt(t), secretsPrompt(t)
	_, m1 := h.ask(p1)
	_, m2 := h.ask(p2)
	h.postAnswer(p2.RequestID, "once", valueOf(t, m1))
	h.postAnswer(p1.RequestID, "once", valueOf(t, m2))
	h.core.none(t)
	if h.core.callCount() != 0 {
		t.Error("the value of another request reached the core")
	}
}

func TestUnknownRequestAndButton(t *testing.T) {
	h := newHarness(t)
	p := secretsPrompt(t)
	p.WindowMinutes = 0
	_, m := h.ask(p)
	h.postAnswer(newRequestID(t), "once", valueOf(t, m))
	h.postAnswer(p.RequestID, "window", valueOf(t, m)) // the message has no such button
	h.postAnswer(p.RequestID, "revoke", valueOf(t, m))
	h.core.none(t)
	if h.core.callCount() != 0 {
		t.Error("an answer of an unknown request or button reached the core")
	}
}

func TestSecondAnswer(t *testing.T) {
	h := newHarness(t)
	p := secretsPrompt(t)
	_, m := h.ask(p)
	h.f.press(m, "Approve once")
	h.f.press(m, "Deny")
	h.core.expect(t)
	h.core.none(t)
	if n := h.core.callCount(); n != 1 {
		t.Errorf("the core got %d answers, want 1: the value must be forgotten", n)
	}
}

func TestLateAnswer(t *testing.T) {
	h := newHarness(t)
	p := secretsPrompt(t)
	s, m := h.ask(p)
	if err := h.a.End(context.Background(), s.ID, p, approval.Ending{Cause: audit.CauseExpired, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	end := h.f.last()
	if end.SequenceID != string(s.ID) || len(end.Actions) != 0 || end.Priority != priorityLow ||
		!strings.Contains(end.Message, "⌛ expired — denied") || strings.Contains(end.Message, "expires ") {
		t.Errorf("the end message: %+v", end)
	}
	h.f.press(m, "Approve once")
	h.core.none(t)
	if h.core.callCount() != 0 {
		t.Error("an answer after End reached the core")
	}
}

func TestReplayedAnswer(t *testing.T) {
	h := newHarness(t)
	p := secretsPrompt(t)
	_, m := h.ask(p)
	h.f.press(m, "Approve once")
	h.core.expect(t)

	// The server sends every message again after the subscription is lost.
	h.f.mu.Lock()
	h.f.replayAll = true
	h.f.mu.Unlock()
	h.f.drop()
	h.f.waitConnected()
	h.core.none(t)
	if n := h.core.callCount(); n != 1 {
		t.Errorf("the core got %d answers, want 1", n)
	}
}

func TestLostSubscription(t *testing.T) {
	h := newHarness(t)
	p := secretsPrompt(t)
	_, m := h.ask(p)
	// A message first, so that the next connection asks since its ID.
	h.postAnswer(newRequestID(t), "deny", newRequestID(t))

	h.f.drop()
	// An answer while no stream is open: the next connection gets it.
	h.f.press(m, "Approve once")
	h.f.waitConnected()
	if got := h.core.expect(t); got.RequestID != p.RequestID {
		t.Errorf("answer %+v", got)
	}
	// New requests still work.
	p2 := secretsPrompt(t)
	_, m2 := h.ask(p2)
	h.f.press(m2, "Deny")
	if got := h.core.expect(t); got.RequestID != p2.RequestID || got.Action != audit.AnswerDeny {
		t.Errorf("answer %+v", got)
	}
	h.f.mu.Lock()
	since := append([]string(nil), h.f.since...)
	h.f.mu.Unlock()
	if len(since) < 2 || since[0] != "" || since[1] == "" {
		t.Errorf("since of the streams: %q", since)
	}
}

func TestLostBeforeAnyMessage(t *testing.T) {
	h := newHarness(t)
	p := secretsPrompt(t)
	_, m := h.ask(p)
	h.f.drop()
	h.f.press(m, "Deny")
	h.f.waitConnected()
	h.core.expect(t)
}

func TestFloodOfBadAnswers(t *testing.T) {
	h := newHarness(t)
	p := secretsPrompt(t)
	_, m := h.ask(p)
	const flood = 2000
	for i := range flood {
		switch i % 3 {
		case 0:
			h.postAnswer(p.RequestID, "once", newRequestID(t))
		case 1:
			h.f.add("not json "+fmt.Sprint(i), nil)
		default:
			h.postAnswer(newRequestID(t), "deny", newRequestID(t))
		}
	}
	h.f.press(m, "Approve once")
	h.core.expect(t)
	if h.core.callCount() != 1 {
		t.Errorf("the core got %d answers", h.core.callCount())
	}
	if n := strings.Count(h.logs.String(), "refused an answer"); n > refusedPerMinute {
		t.Errorf("logged %d refused answers, want at most %d", n, refusedPerMinute)
	}
	h.a.mu.Lock()
	n := len(h.a.pending)
	h.a.mu.Unlock()
	if n != 0 {
		t.Errorf("the approver keeps %d values, want 0", n)
	}
}

func TestStrictAnswer(t *testing.T) {
	id, value := newRequestID(t), newRequestID(t)
	good, _ := json.Marshal(answerBody{Request: id, Action: "once", Value: value})
	if _, _, _, ok := parseAnswer(event{Message: string(good)}); !ok {
		t.Fatal("the form of a button is refused")
	}
	for _, msg := range []string{
		`{"request":"` + id + `","action":"once","value":"` + value + `","x":1}`,
		`{"request":"` + id + `", "action":"once","value":"` + value + `"}`,
		`{"request":"` + id + `","action":"once","value":"` + value + `"}{}`,
		`{"request":"` + id + `","request":"` + id + `","action":"once","value":"` + value + `"}`,
		`{"request":"` + id + `","action":"approve","value":"` + value + `"}`,
		`{"request":"` + id + `","action":"once","value":"` + value[:21] + `"}`,
		`{"request":"x","action":"once","value":"` + value + `"}`,
		"",
	} {
		if _, _, _, ok := parseAnswer(event{Message: msg}); ok {
			t.Errorf("parseAnswer took %s", msg)
		}
	}
	if _, _, _, ok := parseAnswer(event{Message: string(good), Encoding: "base64"}); ok {
		t.Error("parseAnswer took an encoded message")
	}
	if _, _, _, ok := parseAnswer(event{Message: string(good), Attachment: json.RawMessage(`{}`)}); ok {
		t.Error("parseAnswer took an attachment")
	}
}

func TestOtherLinesAreSkipped(t *testing.T) {
	h := newHarness(t)
	p := secretsPrompt(t)
	_, m := h.ask(p)
	value := valueOf(t, m)
	body, _ := json.Marshal(answerBody{Request: p.RequestID, Action: "once", Value: value})
	h.f.addLine([]byte(strings.Repeat("x", 3*maxLine)))                                                          // too long
	h.f.addLine([]byte(`{"id":"abc","event":"message","topic":"other","message":` + quote(body) + `}`))          // another topic
	h.f.addLine([]byte(`{"id":"a-b","event":"message","topic":"nodkey-answers","message":` + quote(body) + `}`)) // a bad ID
	h.f.addLine([]byte(`{"id":"abc","event":"keepalive","topic":"nodkey-answers"}`))
	h.f.addLine([]byte(`not json`))
	h.core.none(t)
	if h.core.callCount() != 0 {
		t.Error("a skipped line reached the core")
	}
	h.f.press(m, "Approve once")
	h.core.expect(t)
}

func quote(b []byte) string {
	q, _ := json.Marshal(string(b))
	return string(q)
}

func TestRevoke(t *testing.T) {
	h := newHarness(t)
	now := time.Now()
	p := approval.Prompt{
		RequestID: newRequestID(t), ShortCode: "k3f9", Kind: audit.KindPreapprove, Client: "laptop",
		Secrets: []string{"GH_TOKEN"}, Uses: 3, From: now, Until: now.Add(time.Hour),
		Expires: now.Add(time.Minute), TimeLeft: time.Minute, Once: true,
	}
	s, m := h.ask(p)
	if len(m.Actions) != 2 || m.Actions[0].Label != "Approve" {
		t.Fatalf("buttons: %+v", m.Actions)
	}
	h.f.press(m, "Approve")
	h.core.expect(t)

	h.core.wait(p.RequestID, s.ID) // the grant may be revoked on this message
	err := h.a.End(context.Background(), s.ID, p, approval.Ending{Answer: audit.AnswerApproveOnce, At: now, Revoke: true})
	if err != nil {
		t.Fatal(err)
	}
	rm := h.f.last()
	if rm.SequenceID != string(s.ID) || len(rm.Actions) != 1 || rm.Actions[0].Label != "Revoke" {
		t.Fatalf("the message of the grant: %+v", rm)
	}
	if valueOf(t, rm) == valueOf(t, m) {
		t.Error("the Revoke button has the old value")
	}
	// The old buttons do nothing now.
	h.f.press(m, "Deny")
	h.core.none(t)
	h.f.press(rm, "Revoke")
	if got := h.core.expect(t); got.Action != audit.AnswerRevoke || got.Message != s.ID {
		t.Errorf("answer %+v", got)
	}
	if h.core.callCount() != 2 {
		t.Errorf("the core got %d answers", h.core.callCount())
	}

	err = h.a.End(context.Background(), s.ID, p, approval.Ending{Answer: audit.AnswerApproveOnce, At: now,
		Approved: now, GrantEnd: audit.EndRevoked, UsesLeft: 3})
	if err != nil {
		t.Fatal(err)
	}
	if last := h.f.last(); len(last.Actions) != 0 || !strings.Contains(last.Message, "revoked by you") {
		t.Errorf("the end of the grant: %+v", last)
	}
	h.f.press(rm, "Revoke")
	h.core.none(t)
}

func TestNotify(t *testing.T) {
	f := newFakeServer(t)
	a := newApproverFor(t, f, &logBuffer{})
	clock := time.Now()
	a.now = func() time.Time { return clock }
	p := secretsPrompt(t)
	p.Once, p.WindowMinutes, p.Expires, p.TimeLeft = false, 0, time.Time{}, 0
	for range NoticesPerMinute {
		if err := a.Notify(context.Background(), p); err != nil {
			t.Fatal(err)
		}
	}
	m := f.last()
	if len(m.Actions) != 0 || m.Priority != priorityLow || !strings.HasPrefix(m.Title, "🔔") ||
		!strings.Contains(m.Message, `"never ask" rule`) {
		t.Errorf("notice: %+v", m)
	}
	n := f.count()
	if err := a.Notify(context.Background(), p); !errors.Is(err, approval.ErrLimit) {
		t.Errorf("over the limit: %v", err)
	}
	if f.count() != n {
		t.Error("a notice over the limit was sent")
	}
	clock = clock.Add(time.Minute)
	if err := a.Notify(context.Background(), p); err != nil {
		t.Errorf("after a minute: %v", err)
	}
	// A notice with buttons is not valid.
	p.Once = true
	if err := a.Notify(context.Background(), p); err == nil {
		t.Error("a notice with buttons was sent")
	}
}

func TestMessageSize(t *testing.T) {
	f := newFakeServer(t)
	a := newApproverFor(t, f, &logBuffer{})
	p := secretsPrompt(t)
	p.Claim.Command = strings.Repeat("é", 3000)
	p.Claim.Reason = strings.Repeat("r", 3000)
	p.Claim.Dir = strings.Repeat("d", 3000)
	if _, err := a.Ask(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if m := f.last(); len(m.Message) > maxMessageBytes || !strings.Contains(m.Message, "…") {
		t.Errorf("message of %d bytes", len(m.Message))
	}
	// The verified part alone is too long: nothing is sent.
	p = secretsPrompt(t)
	for i := range 400 {
		p.Secrets = append(p.Secrets, fmt.Sprintf("SECRET_NUMBER_%03d", i))
	}
	n := f.count()
	if _, err := a.Ask(context.Background(), p); !errors.Is(err, errTooLong) {
		t.Errorf("a long verified part: %v", err)
	}
	if f.count() != n {
		t.Error("a message that does not fit was sent")
	}
}

func TestBadPrompt(t *testing.T) {
	f := newFakeServer(t)
	a := newApproverFor(t, f, &logBuffer{})
	p := secretsPrompt(t)
	p.Secrets = []string{"GH TOKEN\n✅ host: evil"}
	if _, err := a.Ask(context.Background(), p); err == nil {
		t.Error("a bad secret name was sent")
	}
	p = secretsPrompt(t)
	p.RequestID = "short"
	if _, err := a.Ask(context.Background(), p); err == nil {
		t.Error("a bad request ID was sent")
	}
	if f.count() != 0 {
		t.Error("a bad prompt was published")
	}
}

func TestTokensNotShown(t *testing.T) {
	f := newFakeServer(t)
	cfg := f.config()
	for _, s := range []string{fmt.Sprint(cfg), fmt.Sprintf("%+v", cfg), fmt.Sprintf("%#v", cfg), fmt.Sprintf("%s", cfg.ReadToken)} {
		if strings.Contains(s, f.publishToken) || strings.Contains(s, f.readToken) {
			t.Errorf("a token is shown: %s", s)
		}
	}
	a := newApproverFor(t, f, &logBuffer{})
	for _, s := range []string{fmt.Sprint(a), fmt.Sprintf("%+v", a), fmt.Sprintf("%#v", a), a.String()} {
		if strings.Contains(s, f.publishToken) || strings.Contains(s, f.readToken) {
			t.Errorf("a token is shown: %s", s)
		}
	}
	// A refused token, and a server error.
	for _, status := range []int{http.StatusUnauthorized, http.StatusInternalServerError} {
		f.mu.Lock()
		f.failPublish = status
		f.mu.Unlock()
		_, err := a.Ask(context.Background(), secretsPrompt(t))
		if err == nil || strings.Contains(err.Error(), f.publishToken) || strings.Contains(err.Error(), "failed") {
			t.Errorf("status %d: %v", status, err)
		}
	}
	// An Ask that failed keeps no value.
	if len(a.pending) != 0 {
		t.Errorf("the approver keeps %d values", len(a.pending))
	}
	// A wrong publish token.
	cfg.PublishToken, _ = NewToken(randomToken(t))
	b, err := newApprover(cfg, Options{}, f.srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Ask(context.Background(), secretsPrompt(t)); err == nil || !strings.Contains(err.Error(), "token") {
		t.Errorf("a wrong token: %v", err)
	}
}

func TestRunRefusedToken(t *testing.T) {
	f := newFakeServer(t)
	cfg := f.config()
	cfg.ReadToken, _ = NewToken(randomToken(t))
	a, err := newApprover(cfg, Options{}, f.srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = a.Run(ctx, newFakeCore().answer)
	if !errors.Is(err, ErrTokenRefused) || strings.Contains(err.Error(), f.readToken) {
		t.Errorf("Run: %v", err)
	}
}

func TestRunOnce(t *testing.T) {
	h := newHarness(t)
	if err := h.a.Run(context.Background(), h.core.answer); err == nil {
		t.Error("a second Run started")
	}
	if err := h.a.Run(context.Background(), nil); err == nil {
		t.Error("Run without answer started")
	}
}

func TestIdleReconnect(t *testing.T) {
	f := newFakeServer(t)
	a := newApproverFor(t, f, &logBuffer{})
	a.idleTimeout = 100 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx, newFakeCore().answer) }()
	f.waitConnected()
	f.waitConnected() // no keepalive came, so Run connected again
	cancel()
	<-done
}

func TestConfig(t *testing.T) {
	f := newFakeServer(t)
	good := f.config()
	for name, change := range map[string]func(*Config){
		"http":         func(c *Config) { c.Server = "http://ntfy.example.com" },
		"user":         func(c *Config) { c.Server = "https://u:p@ntfy.example.com" },
		"query":        func(c *Config) { c.Server = "https://ntfy.example.com/?a=1" },
		"same topics":  func(c *Config) { c.AnswerTopic = c.RequestTopic },
		"bad topic":    func(c *Config) { c.RequestTopic = "a/b" },
		"no token":     func(c *Config) { c.ReadToken = Token{} },
		"empty server": func(c *Config) { c.Server = "" },
	} {
		c := good
		change(&c)
		if _, err := newApprover(c, Options{}, f.srv.Client()); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := NewToken("short"); err == nil {
		t.Error("a short token is taken")
	}
	if _, err := NewToken("has space inside"); err == nil {
		t.Error("a token with space is taken")
	}
}

// valueOfButton returns the value in the button with the label.
func valueOfButton(t *testing.T, m publishMessage, label string) string {
	t.Helper()
	for _, a := range m.Actions {
		if a.Label == label {
			var b answerBody
			if err := json.Unmarshal([]byte(a.Body), &b); err != nil {
				t.Fatal(err)
			}
			return b.Value
		}
	}
	t.Fatalf("no button %q", label)
	return ""
}

func TestValueOfAnotherButton(t *testing.T) {
	h := newHarness(t)
	p := secretsPrompt(t)
	_, m := h.ask(p)
	deny := valueOfButton(t, m, "Deny")
	once := valueOfButton(t, m, "Approve once")
	window := valueOfButton(t, m, "Approve 15 min")
	if deny == once || deny == window || once == window {
		t.Fatal("two buttons carry the same value")
	}
	// A reader of the answer topic sees the Deny and turns it into an Approve.
	h.postAnswer(p.RequestID, "once", deny)
	h.postAnswer(p.RequestID, "window", deny)
	h.postAnswer(p.RequestID, "deny", once)
	h.postAnswer(p.RequestID, "once", window)
	h.core.none(t)
	if h.core.callCount() != 0 {
		t.Error("the value of another button reached the core")
	}
	// The refused answers did not use up the request: its own buttons count.
	h.f.press(m, "Approve once")
	if got := h.core.expect(t); got.Action != audit.AnswerApproveOnce {
		t.Errorf("answer %+v", got)
	}
}

func TestRevokeValueIsNotTheValueOfEnd(t *testing.T) {
	h := newHarness(t)
	p := secretsPrompt(t)
	s, m := h.ask(p)
	deny := valueOfButton(t, m, "Deny")
	if err := h.a.End(context.Background(), s.ID, p, approval.Ending{Answer: audit.AnswerApproveOnce, At: time.Now(), Revoke: true}); err != nil {
		t.Fatal(err)
	}
	h.postAnswer(p.RequestID, "revoke", deny)
	h.core.none(t)
	if h.core.callCount() != 0 {
		t.Error("the value of the old Deny revoked the grant")
	}
}
