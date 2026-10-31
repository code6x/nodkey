// Package ntfy is the ntfy approver of the broker (issue #24). It sends
// each request as a message with buttons to a topic of an ntfy server
// (https://ntfy.sh), and reads the answers from a second topic.
//
// Each button is an ntfy "http" action: the phone sends a POST to the
// answer topic of the same server, with the request ID, the answer and a
// random value. The value is 16 bytes from crypto/rand, new for each
// request, and only in the message and in the broker's memory. It is not
// the request ID, which is in the audit log and the journal. ntfy does
// not say who pressed a button, so the value is the only proof: an answer
// counts only with the value of its own request. Run reads the answer
// topic with a long-lived subscription, so the broker needs no open port.
//
// When a request ends, End replaces its message (the same sequence ID)
// with the result and no buttons, and forgets the value. A scheduled grant
// that started keeps one Revoke button, with a new value.
//
// No error and no log line of this package holds a token, a value, or Go's
// error text.
package ntfy

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
)

// NoticesPerMinute is the most notices that Notify sends in any 60
// seconds, for all clients together.
const NoticesPerMinute = 20

// maxPending is the most requests and grants whose value the approver
// keeps. Ask fails when it holds that many.
const maxPending = 4096

// The priorities of ntfy (https://docs.ntfy.sh/publish/#message-priority).
const (
	priorityLow  = 2 // notices, and the message after its request ended
	priorityAsk  = 4 // a request that waits for an answer
	priorityHigh = 5 // an alert
)

// alertTimeout bounds Alert, also when its context has no deadline.
const alertTimeout = 30 * time.Second

// ErrNoticeLimit: Notify sent NoticesPerMinute notices in the last 60
// seconds, so it sends no more. It wraps approval.ErrLimit, because
// nothing was sent.
var ErrNoticeLimit = fmt.Errorf("ntfy: too many notices in the last minute: %w", approval.ErrLimit)

// Options are the optional parts of an Approver.
type Options struct {
	// Logger gets refused answers and problems with the server. The
	// default drops them. No line holds a token or a value.
	Logger *slog.Logger
}

// Approver is the ntfy approver: an approval.Approver. Make it with New.
// Ask, End, Notify and Alert are safe for use by many goroutines. Run runs
// once at a time.
type Approver struct {
	api          *client
	requestTopic string
	answerTopic  string
	log          *slog.Logger
	now          func() time.Time // the clock of the limits; tests replace it

	// The waits of Run; tests make them short.
	firstBackoff, maxBackoff, idleTimeout time.Duration

	running atomic.Bool

	mu sync.Mutex
	// pending holds the value of each request that waits for an answer,
	// and of each scheduled grant with a Revoke button, by request ID.
	pending map[string]*pending
	notices []time.Time
	refused reportWindow
	lost    reportWindow // the warnings about a lost subscription; only Run uses it
}

// pending is what the approver keeps for one request.
type pending struct {
	// values holds the value of each button, by its action. The values
	// differ, so the value of a Deny button never counts as an approval.
	values map[audit.Answer][16]byte
	msg    approval.MessageID // "" until Ask has the ID of the message
}

// newPending returns the state of a message with one button for each of
// actions, each with a value of its own.
func newPending(msg approval.MessageID, actions []audit.Answer) *pending {
	e := &pending{values: make(map[audit.Answer][16]byte, len(actions)), msg: msg}
	for _, act := range actions {
		e.values[act] = newValue()
	}
	return e
}

var _ approval.Approver = (*Approver)(nil)

// New returns the ntfy approver for cfg. Errors never show a token.
func New(cfg Config, opts Options) (*Approver, error) {
	return newApprover(cfg, opts, newHTTPClient())
}

// newApprover is New with the HTTP client. Tests use the client of a fake
// server.
func newApprover(cfg Config, opts Options, hc *http.Client) (*Approver, error) {
	base, err := cfg.check()
	if err != nil {
		return nil, err
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	hc.CheckRedirect = noRedirect
	return &Approver{
		api: &client{
			http: hc, base: base, publishToken: cfg.PublishToken, readToken: cfg.ReadToken,
			timeout: callTimeout, sleep: sleep,
		},
		requestTopic: cfg.RequestTopic,
		answerTopic:  cfg.AnswerTopic,
		log:          logger,
		now:          time.Now,
		firstBackoff: time.Second,
		maxBackoff:   30 * time.Second,
		idleTimeout:  2 * time.Minute,
		pending:      make(map[string]*pending),
	}, nil
}

// Format shows only the type, never a token.
func (*Approver) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "ntfy.Approver") }

// String returns only the type, never a token.
func (*Approver) String() string { return "ntfy.Approver" }

// answerBody is the body that a button sends to the answer topic. Run
// takes only this exact form, as json.Marshal makes it.
type answerBody struct {
	Request string `json:"request"`
	Action  string `json:"action"`
	Value   string `json:"value"`
}

// The actions in an answer body.
var actionNames = map[audit.Answer]string{
	audit.AnswerApproveOnce:   "once",
	audit.AnswerApproveWindow: "window",
	audit.AnswerDeny:          "deny",
	audit.AnswerRevoke:        "revoke",
}

// newValue returns 16 random bytes. It panics only if crypto/rand fails,
// which Go never lets it do.
func newValue() [16]byte {
	var v [16]byte
	_, _ = rand.Read(v[:])
	return v
}

// buttons returns the ntfy actions for the request id, each with the value
// that e holds for its action.
func (a *Approver) buttons(id string, e *pending, labels []string, actions []audit.Answer) []action {
	url := a.api.base + "/" + a.answerTopic
	out := make([]action, len(labels))
	for i := range labels {
		v := e.values[actions[i]]
		value := base64.RawURLEncoding.EncodeToString(v[:])
		body, _ := json.Marshal(answerBody{Request: id, Action: actionNames[actions[i]], Value: value})
		out[i] = action{Action: "http", Label: labels[i], URL: url, Method: http.MethodPost, Body: string(body), Clear: true}
	}
	return out
}

// Ask publishes the message of p to the request topic, with the buttons
// that p allows, and returns its ID and its text. Each button carries a
// new random value. It fails when p is not valid or the message does not
// fit; the core then denies the request.
func (a *Approver) Ask(ctx context.Context, p approval.Prompt) (approval.Shown, error) {
	if err := ctx.Err(); err != nil {
		return approval.Shown{}, err
	}
	if err := checkPrompt(p, false); err != nil {
		return approval.Shown{}, err
	}
	limit := maxMessageBytes - lastLineRoom
	if p.Kind.IsPreapprove() {
		limit -= lastLineRoom // the line of the approval and the line of the end
	}
	labels, actions := buttonLabels(p)
	e := newPending("", actions)
	t := title(p, false)
	pm := publishMessage{
		Topic: a.requestTopic, Title: t, Priority: priorityAsk,
		Actions: a.buttons(p.RequestID, e, labels, actions),
	}
	// The text, and the whole publish body with the buttons, must fit.
	b, err := fitBodyWith(p, false, limit, func(b string) bool {
		pm.Message = b + "\n" + expiryLine(p)
		return fitsPublish(pm)
	})
	if err != nil {
		return approval.Shown{}, err
	}
	msg := b + "\n" + expiryLine(p)
	pm.Message = msg
	if err := a.add(p.RequestID, e); err != nil {
		return approval.Shown{}, err
	}
	id, err := a.api.publish(ctx, pm, true)
	if err != nil {
		a.forget(p.RequestID, e)
		return approval.Shown{}, err
	}
	m := approval.MessageID(id)
	a.mu.Lock()
	e.msg = m
	a.mu.Unlock()
	return approval.Shown{ID: m, Text: t + "\n" + msg + "\n" + buttonsLine(labels)}, nil
}

// End replaces the message m after its request ended: the same lines,
// with the result instead of the expiry, and no buttons. It forgets the
// value of the request. With e.Revoke, the message keeps one Revoke
// button, with a new value.
func (a *Approver) End(ctx context.Context, m approval.MessageID, p approval.Prompt, e approval.Ending) error {
	if !idPattern.MatchString(string(m)) {
		return errors.New("ntfy: End: the message ID is not one that Ask returned")
	}
	pm := publishMessage{
		Topic: a.requestTopic, Title: title(p, false), Priority: priorityLow, SequenceID: string(m),
	}
	if e.Revoke && validRequestID(p.RequestID) {
		entry := newPending(m, []audit.Answer{audit.AnswerRevoke})
		a.replace(p.RequestID, entry)
		pm.Actions = a.buttons(p.RequestID, entry, []string{"Revoke"}, []audit.Answer{audit.AnswerRevoke})
	} else {
		a.forget(p.RequestID, nil)
	}
	pm.Message = endingBody(p, e, func(s string) bool {
		pm.Message = s
		return fitsPublish(pm)
	})
	_, err := a.api.publish(ctx, pm, true)
	return err
}

// Notify publishes a silent notice of the use p, with a low priority and
// no buttons. It sends nothing when ctx has ended, and nothing when it
// sent NoticesPerMinute notices in the last 60 seconds: then it returns
// ErrNoticeLimit. It makes one try.
func (a *Approver) Notify(ctx context.Context, p approval.Prompt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := checkPrompt(p, true); err != nil {
		return err
	}
	pm := publishMessage{Topic: a.requestTopic, Title: title(p, true), Priority: priorityLow}
	b, err := fitBodyWith(p, true, maxMessageBytes, func(b string) bool {
		pm.Message = b
		return fitsPublish(pm)
	})
	if err != nil {
		return err
	}
	if !a.takeNotice() {
		a.log.LogAttrs(ctx, slog.LevelWarn, "ntfy: too many notices in the last minute; the use is denied",
			slog.String("request_id", p.RequestID), slog.Int("limit", NoticesPerMinute))
		return ErrNoticeLimit
	}
	pm.Message = b
	_, err = a.api.publish(ctx, pm, false)
	return err
}

// Alert publishes msg with a high priority, for a problem the person must
// see. msg is the broker's own text. It takes at most alertTimeout.
func (a *Approver) Alert(ctx context.Context, msg string) error {
	return a.text(ctx, "⚠️ nodkey", msg, priorityHigh)
}

// Inform publishes msg with a low priority, for a notice that needs no
// action now, such as a newer release (DESIGN.md section 15). msg is the
// broker's own text. It takes at most alertTimeout.
func (a *Approver) Inform(ctx context.Context, msg string) error {
	return a.text(ctx, "ℹ️ nodkey", msg, priorityLow)
}

// text publishes the broker's own msg, for Alert and Inform.
func (a *Approver) text(ctx context.Context, title, msg string, priority int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, alertTimeout)
	defer cancel()
	pm := publishMessage{Topic: a.requestTopic, Title: title, Message: cutBytes(msg, 3000), Priority: priority}
	for n := 3000; !fitsPublish(pm) && n > 100; n /= 2 {
		pm.Message = cutBytes(msg, n)
	}
	_, err := a.api.publish(ctx, pm, true)
	return err
}

// add keeps the value e of the request id. It fails when the request has
// one already, or when the approver holds maxPending.
func (a *Approver) add(id string, e *pending) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.pending[id]; ok {
		return errors.New("ntfy: Ask: the request has a message already")
	}
	if len(a.pending) >= maxPending {
		return errors.New("ntfy: Ask: too many requests wait for an answer")
	}
	a.pending[id] = e
	return nil
}

// replace keeps the value e of the request id, in place of the one it had.
func (a *Approver) replace(id string, e *pending) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pending[id] = e
}

// forget drops the value of the request id: only if it is still e, or
// whatever it is when e is nil.
func (a *Approver) forget(id string, e *pending) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e == nil || a.pending[id] == e {
		delete(a.pending, id)
	}
}

// lookup returns the state of the request id, and the message it waits on.
// The values of e never change after e is made.
func (a *Approver) lookup(id string) (e *pending, msg approval.MessageID) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e = a.pending[id]
	if e == nil {
		return nil, ""
	}
	return e, e.msg
}

// takeNotice reports whether a notice may go out now, and counts it.
func (a *Approver) takeNotice() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.notices = slices.DeleteFunc(a.notices, func(t time.Time) bool { return now.Sub(t) >= time.Minute })
	if len(a.notices) >= NoticesPerMinute {
		return false
	}
	a.notices = append(a.notices, now)
	return true
}
