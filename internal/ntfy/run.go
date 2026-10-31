package ntfy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
)

const (
	// maxLine is the longest line of the subscription that Run reads. An
	// answer is about 120 bytes, and ntfy adds its own fields; a message
	// of the server is at most a few kilobytes. A longer line is skipped.
	maxLine = 16 << 10
	// refusedPerMinute is the most refused answers that Run logs in one
	// minute. It counts the others, and logs how many it dropped with the
	// first refused answer after that minute. So a flood of bad answers
	// cannot fill the journal.
	refusedPerMinute = 20
)

// ErrTokenRefused: the server answered the subscription with 401 or 403:
// it does not let the read token read the answer topic. Only a new token
// or new access rules help, so Run stops.
var ErrTokenRefused = errors.New("ntfy: the server does not let the read token read the answer topic")

// errPanic: Run stopped because handling an answer panicked.
var errPanic = errors.New("ntfy: the subscription stopped after a panic; no answers can come any more")

// reportWindow counts the refused answers that Run logged in one minute.
type reportWindow struct {
	start   time.Time
	n       int
	dropped int
}

// take reports whether one more refused answer may be logged at now, and
// counts it. dropped is the number dropped in the minute before, when
// that minute has just ended.
func (w *reportWindow) take(now time.Time) (ok bool, dropped int) {
	if w.start.IsZero() || now.Sub(w.start) >= time.Minute {
		dropped = w.dropped
		*w = reportWindow{start: now}
	}
	if w.n >= refusedPerMinute {
		w.dropped++
		return false, dropped
	}
	w.n++
	return true, dropped
}

// event is the part of a line of the subscription that Run reads
// (https://docs.ntfy.sh/subscribe/api/#json-message-format). The server
// may add fields of its own, so other fields are ignored here; the answer
// in Message is read strictly.
type event struct {
	ID         string          `json:"id"`
	Event      string          `json:"event"`
	Topic      string          `json:"topic"`
	Message    string          `json:"message"`
	Encoding   string          `json:"encoding"`
	Attachment json.RawMessage `json:"attachment"`
}

// Run reads the answer topic and passes each valid answer to answer,
// until ctx ends or the server refuses the read token. It always returns
// why it stopped, and never panics.
//
//   - An answer counts only with the exact form that a button sends, for
//     a request that waits, with a button that its message has, and with
//     the value of that request, compared in constant time. Any other
//     answer never reaches answer. Run logs at most refusedPerMinute of
//     them in a minute, and how many more it dropped.
//   - After an answer that counted, or that the core refused because the
//     request no longer waits or expired, Run forgets the value. So the
//     same answer, sent again, does nothing.
//   - When the subscription is lost, Run connects again, with a growing
//     wait, and asks for the messages since the last one it read. So
//     nothing is lost, and a message that comes twice does nothing.
//   - When no line comes for idleTimeout (ntfy sends a keepalive every
//     45 seconds), Run connects again.
func (a *Approver) Run(ctx context.Context, answer func(approval.Answer) error) (err error) {
	if answer == nil {
		return errors.New("ntfy: Run needs a function for the answers")
	}
	if !a.running.CompareAndSwap(false, true) {
		return errors.New("ntfy: Run is running already")
	}
	defer a.running.Store(false)
	defer func() {
		if r := recover(); r != nil {
			err = errPanic
			a.log.LogAttrs(context.WithoutCancel(ctx), slog.LevelError, "ntfy: the subscription stopped after a panic")
		}
	}()
	// Before the first message, a new connection asks for the messages
	// since this second, so that no answer is lost between two
	// connections.
	since := strconv.FormatInt(a.now().Unix(), 10)
	first := true
	backoff := a.firstBackoff
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("ntfy: the subscription stopped: %w", err)
		}
		q := since
		if first {
			q = "" // only new messages: the first connection
		}
		read, e := a.subscribe(ctx, q, func(ev event) {
			since = ev.ID
			a.handle(ctx, ev, answer)
		})
		first = false
		if ctx.Err() != nil {
			return fmt.Errorf("ntfy: the subscription stopped: %w", ctx.Err())
		}
		if errors.Is(e, ErrTokenRefused) {
			a.log.LogAttrs(ctx, slog.LevelError, "ntfy: the server refused the read token; no answers can come any more",
				slog.String("error", e.Error()))
			return e
		}
		if read {
			backoff = a.firstBackoff
		}
		// A server that sends one event and closes again resets the wait
		// each time, so this warning has a budget too.
		if ok, _ := a.lost.take(a.now()); ok {
			a.log.LogAttrs(ctx, slog.LevelWarn, "ntfy: the subscription was lost; connecting again",
				slog.String("error", e.Error()), slog.Duration("wait", backoff))
		}
		if err := sleep(ctx, backoff); err != nil {
			return fmt.Errorf("ntfy: the subscription stopped: %w", err)
		}
		backoff = min(2*backoff, a.maxBackoff)
	}
}

// subscribe makes one connection to the answer topic, and passes each
// message event to fn, until the connection ends. It returns why, and
// whether a message or a keepalive came. since is "" for only new messages.
func (a *Approver) subscribe(ctx context.Context, since string, fn func(event)) (read bool, err error) {
	const call = "subscribe"
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	idle := time.AfterFunc(a.idleTimeout, cancel)
	defer idle.Stop()
	u := a.api.base + "/" + a.answerTopic + "/json"
	if since != "" {
		u += "?since=" + url.QueryEscape(since)
	}
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, u, nil)
	if err != nil {
		return false, &callError{call: call, reason: "cannot make the request"}
	}
	req.Header.Set("Authorization", "Bearer "+a.api.readToken.value)
	resp, err := a.api.http.Do(req)
	if err != nil {
		return false, &callError{call: call, reason: netReason(err)}
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return false, fmt.Errorf("%w (%d)", ErrTokenRefused, resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return false, &callError{call: call, reason: "the server refused the subscription", status: resp.StatusCode}
	}
	r := bufio.NewReaderSize(resp.Body, maxLine)
	skip := false // the rest of a line that is too long
	for {
		line, err := r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			skip = true
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return read, &callError{call: call, reason: "the server closed the subscription"}
			}
			if cctx.Err() != nil && ctx.Err() == nil {
				return read, &callError{call: call, reason: "no keepalive came in time"}
			}
			return read, &callError{call: call, reason: "the subscription failed"}
		}
		idle.Reset(a.idleTimeout)
		if skip {
			skip = false
			a.limited(ctx, "ntfy: skipped a line of the subscription that is too long")
			continue
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var ev event
		if json.Unmarshal(line, &ev) != nil {
			a.limited(ctx, "ntfy: skipped a line of the subscription that is not valid")
			continue
		}
		if ev.Event == "message" || ev.Event == "keepalive" {
			// Only these show a server that works. ntfy sends an open
			// event on every connection, also one that it closes at once.
			read = true
		}
		if ev.Event != "message" {
			continue // open, keepalive, and others
		}
		if !idPattern.MatchString(ev.ID) || ev.Topic != a.answerTopic {
			a.limited(ctx, "ntfy: skipped a message of the subscription that is not valid")
			continue
		}
		fn(ev)
	}
}

// handle checks one message of the answer topic, and passes it to answer
// if it counts.
func (a *Approver) handle(ctx context.Context, ev event, answer func(approval.Answer) error) {
	id, action, value, ok := parseAnswer(ev)
	if !ok {
		a.refuse(ctx, ev.ID, "the answer does not have the form of a button", "")
		return
	}
	e, msg := a.lookup(id)
	if e == nil {
		a.refuse(ctx, ev.ID, "no request with this ID waits for an answer here", id)
		return
	}
	// The value first, so the answer says nothing about the request
	// without it. It must be the value of the button of its own action.
	want, has := e.values[action]
	if !has {
		// A zero value cannot match: compare anyway, to take the same time.
		want = [16]byte{}
	}
	if subtle.ConstantTimeCompare(value[:], want[:]) != 1 || !has {
		a.refuse(ctx, ev.ID, "the value is not the value of this button of the request", id)
		return
	}
	if msg == "" {
		// Ask is still sending the message. The value stays, so the same
		// answer may count when it comes again.
		a.log.LogAttrs(ctx, slog.LevelInfo, "ntfy: an answer came before its message was sent",
			slog.String("request_id", id))
		return
	}
	// UserID is 0: ntfy does not say who pressed the button. The value is
	// the proof. With [ntfy], the core takes an answer with user ID 0 and
	// records the channel and the answer topic (Core.fromApprover).
	err := answer(approval.Answer{RequestID: id, Action: action, Message: msg, UserID: 0})
	switch {
	case err == nil, errors.Is(err, approval.ErrUnknownRequest), errors.Is(err, approval.ErrExpired):
		a.forget(id, e)
	}
	if err != nil && !errors.Is(err, approval.ErrTooEarly) {
		a.refuse(ctx, ev.ID, "the core refused the answer", id)
	}
}

// parseAnswer reads the answer in ev strictly: only the exact form that
// json.Marshal makes of an answerBody, with a known action, a valid
// request ID, and a value of 16 bytes.
func parseAnswer(ev event) (id string, action audit.Answer, value [16]byte, ok bool) {
	if ev.Encoding != "" || len(ev.Attachment) != 0 || len(ev.Message) > 256 {
		return "", "", value, false
	}
	var b answerBody
	dec := json.NewDecoder(bytes.NewReader([]byte(ev.Message)))
	dec.DisallowUnknownFields()
	if dec.Decode(&b) != nil {
		return "", "", value, false
	}
	// The exact form: no other spaces, no field twice, nothing after it.
	if again, err := json.Marshal(b); err != nil || string(again) != ev.Message {
		return "", "", value, false
	}
	for k, v := range actionNames {
		if v == b.Action {
			action = k
		}
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(b.Value)
	if action == "" || !validRequestID(b.Request) || err != nil || len(raw) != len(value) {
		return "", "", value, false
	}
	copy(value[:], raw)
	return b.Request, action, value, true
}

// refuse logs an answer that did not count, at most refusedPerMinute in a
// minute. msgID is the ntfy ID of the answer; id is its request ID, or ""
// when it has none. Neither is a secret; the value is never logged.
func (a *Approver) refuse(ctx context.Context, msgID, why, id string) {
	a.limited(ctx, "ntfy: refused an answer",
		slog.String("why", why), slog.String("ntfy_id", msgID), slog.String("request_id", id))
}

// limited logs a warning about something that the answer topic sent, in
// the budget of refusedPerMinute lines in a minute for all such warnings.
// Anyone who can write to the topic can make them, so none may go round
// the budget.
func (a *Approver) limited(ctx context.Context, msg string, attrs ...slog.Attr) {
	a.mu.Lock()
	ok, dropped := a.refused.take(a.now())
	a.mu.Unlock()
	if dropped > 0 {
		a.log.LogAttrs(ctx, slog.LevelWarn, "ntfy: dropped the log lines of refused answers, to keep the log small",
			slog.Int("dropped", dropped), slog.Int("limit_per_minute", refusedPerMinute))
	}
	if !ok {
		return
	}
	a.log.LogAttrs(ctx, slog.LevelWarn, msg, attrs...)
}
