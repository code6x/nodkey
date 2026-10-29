package approvaltest

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
)

// tapPatience is how long Tap waits for the core to take an answer. The
// core takes answers for a request only after Ask returned its message.
const tapPatience = 10 * time.Second

var (
	errNotRunning = errors.New("approvaltest: Run is not running, so no answer reaches the core")
	errNoMessage  = errors.New("approvaltest: the core did not ask for a message for this request")
)

// Asked is a message that the core asked the fake approver to send.
type Asked struct {
	Prompt  approval.Prompt
	Message approval.MessageID
	Text    string
}

// Ended is a call of End: the update of a message after its request
// ended.
type Ended struct {
	Message approval.MessageID
	Prompt  approval.Prompt
	Ending  approval.Ending
}

// Approver is a fake approval.Approver. It keeps what the core asked it to
// show, and answers on command, as the person would: approve, deny,
// nothing, or late (DESIGN.md section 17). It can also fail, to test that
// the core then denies. It is safe for use by many goroutines.
type Approver struct {
	userID int64

	mu        sync.Mutex
	answer    func(approval.Answer) error // set while Run runs
	asked     []Asked
	ended     []Ended
	notices   []approval.Prompt
	alarms    []approval.Alarm
	summaries [][]approval.GrantInfo
	alarmErr  error
	askErr    error
	notifyErr error
	endErr    error
	auto      audit.Answer
	stop      chan error
	changed   chan struct{} // closed and made new on each change
	next      int
}

var _ approval.Approver = (*Approver)(nil)

// NewApprover returns a fake approver. Its taps come from the Telegram
// user userID; give it the cfg.Telegram.UserID of the core's config, so
// they count.
func NewApprover(userID int64) *Approver {
	return &Approver{userID: userID, stop: make(chan error, 1), changed: make(chan struct{})}
}

// changedLocked wakes the goroutines in WaitAsked and WaitEnded. a.mu must
// be held.
func (a *Approver) changedLocked() {
	close(a.changed)
	a.changed = make(chan struct{})
}

// Ask keeps p and returns a new message ID, unless FailAsk set an error.
// With Auto, it also starts a tap for the request. As a real approver,
// it returns ctx.Err() and sends nothing once ctx has ended.
func (a *Approver) Ask(ctx context.Context, p approval.Prompt) (approval.Shown, error) {
	if err := ctx.Err(); err != nil {
		return approval.Shown{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.askErr != nil {
		return approval.Shown{}, a.askErr
	}
	a.next++
	shown := approval.Shown{ID: approval.MessageID("message-" + strconv.Itoa(a.next)), Text: Text(p)}
	a.asked = append(a.asked, Asked{Prompt: p, Message: shown.ID, Text: shown.Text})
	a.changedLocked()
	if a.auto != "" {
		action := a.auto
		go func() { _ = a.Tap(p.RequestID, action) }() // as the person; the result shows in the core
	}
	return shown, nil
}

// End keeps the update, and returns the error that FailEnd set.
func (a *Approver) End(_ context.Context, m approval.MessageID, p approval.Prompt, e approval.Ending) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ended = append(a.ended, Ended{Message: m, Prompt: p, Ending: e})
	a.changedLocked()
	return a.endErr
}

// Notify keeps the notice, unless FailNotify set an error. As a real
// approver, it returns ctx.Err() and sends nothing once ctx has ended.
func (a *Approver) Notify(ctx context.Context, p approval.Prompt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.notifyErr != nil {
		return a.notifyErr
	}
	a.notices = append(a.notices, p)
	a.changedLocked()
	return nil
}

// Run passes the taps of Tap and Answer to answer, until ctx ends or Stop
// is called.
func (a *Approver) Run(ctx context.Context, answer func(approval.Answer) error) error {
	a.mu.Lock()
	if a.answer != nil {
		a.mu.Unlock()
		return errors.New("approvaltest: Run is already running")
	}
	a.answer = answer
	a.changedLocked()
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.answer = nil
		a.changedLocked()
		a.mu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-a.stop:
		return err
	}
}

// Stop makes Run return err, as an approver that cannot get answers any
// more.
func (a *Approver) Stop(err error) {
	select {
	case a.stop <- err:
	default: // Stop was called before
	}
}

// Running reports whether Run runs, so that answers reach the core.
func (a *Approver) Running() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.answer != nil
}

// FailAsk makes Ask fail with err, as when Telegram cannot be reached. nil
// makes it work again.
func (a *Approver) FailAsk(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.askErr = err
}

// FailNotify makes Notify fail with err. nil makes it work again. An err
// that wraps approval.ErrLimit acts as a limit of the approver itself:
// Notify keeps nothing, as it sent nothing.
func (a *Approver) FailNotify(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.notifyErr = err
}

// FailAlarm makes Alarm fail with err. nil makes it work again.
func (a *Approver) FailAlarm(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.alarmErr = err
}

// FailEnd makes End return err. nil makes it work again.
func (a *Approver) FailEnd(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.endErr = err
}

// Auto makes the fake tap action on each new message at once:
// audit.AnswerApproveOnce, audit.AnswerApproveWindow or audit.AnswerDeny.
// "" turns it off, so requests wait for Tap or expire.
func (a *Approver) Auto(action audit.Answer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.auto = action
}

// Tap presses the button action on the message of the request id, as the
// person, and returns what the core said: nil when the tap counted. The
// core takes answers for a request only after Ask returned. So, as a
// person would, Tap taps again for a while when the core says
// ErrTooEarly, or when Run has not started yet.
func (a *Approver) Tap(id string, action audit.Answer) error {
	msg, ok := a.messageOf(id)
	if !ok {
		return errNoMessage
	}
	ans := approval.Answer{RequestID: id, Action: action, Message: msg, UserID: a.userID}
	until := time.Now().Add(tapPatience)
	for {
		err := a.Answer(ans)
		early := errors.Is(err, approval.ErrTooEarly) || errors.Is(err, errNotRunning)
		if !early || !time.Now().Before(until) {
			return err
		}
		time.Sleep(time.Millisecond)
	}
}

// Answer passes ans to the core once, as it is, and returns what the core
// said. Tests of answers that must not count use it: from another user, on
// another message, with a button the request does not have.
func (a *Approver) Answer(ans approval.Answer) error {
	a.mu.Lock()
	answer := a.answer
	a.mu.Unlock()
	if answer == nil {
		return errNotRunning
	}
	return answer(ans)
}

// Asked returns the messages that the core asked for, oldest first.
func (a *Approver) Asked() []Asked {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Asked(nil), a.asked...)
}

// Ended returns the updates of messages whose request ended, oldest first.
func (a *Approver) Ended() []Ended {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Ended(nil), a.ended...)
}

// Alarm keeps the alarm, unless FailAlarm set an error.
func (a *Approver) Alarm(ctx context.Context, al approval.Alarm) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.alarmErr != nil {
		return a.alarmErr
	}
	a.alarms = append(a.alarms, al)
	a.changedLocked()
	return nil
}

// Alarms returns the alarms, oldest first.
func (a *Approver) Alarms() []approval.Alarm {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]approval.Alarm(nil), a.alarms...)
}

// Notices returns the notices of "never ask" uses, oldest first.
func (a *Approver) Notices() []approval.Prompt {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]approval.Prompt(nil), a.notices...)
}

// WaitAsked waits until the core has asked for at least n messages, and
// returns them. It fails after timeout.
func (a *Approver) WaitAsked(n int, timeout time.Duration) ([]Asked, error) {
	err := a.wait(func() bool { return len(a.asked) >= n }, timeout)
	return a.Asked(), err
}

// WaitEnded waits until at least n messages have ended, and returns the
// updates. It fails after timeout.
func (a *Approver) WaitEnded(n int, timeout time.Duration) ([]Ended, error) {
	err := a.wait(func() bool { return len(a.ended) >= n }, timeout)
	return a.Ended(), err
}

// WaitRunning waits until Run runs. It fails after timeout.
func (a *Approver) WaitRunning(timeout time.Duration) error {
	return a.wait(func() bool { return a.answer != nil }, timeout)
}

// wait waits until ok, which runs with a.mu held, is true.
func (a *Approver) wait(ok func() bool, timeout time.Duration) error {
	t := time.NewTimer(timeout)
	defer t.Stop()
	for {
		a.mu.Lock()
		done, changed := ok(), a.changed
		a.mu.Unlock()
		if done {
			return nil
		}
		select {
		case <-changed:
		case <-t.C:
			return fmt.Errorf("approvaltest: waited %s in vain", timeout)
		}
	}
}

// messageOf returns the message that the core asked for the request id.
func (a *Approver) messageOf(id string) (approval.MessageID, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, x := range a.asked {
		if x.Prompt.RequestID == id {
			return x.Message, true
		}
	}
	return "", false
}

// Text returns the text that the fake approver shows for p: a title, then
// one line for each field that is set, the verified fields first. The
// real approver has its own format.
func Text(p approval.Prompt) string {
	var b strings.Builder
	line := func(name, value string) {
		if value != "" {
			b.WriteString(name + ": " + value + "\n")
		}
	}
	b.WriteString(string(p.Kind) + " · request " + p.ShortCode + "\n")
	line("machine", p.Client)
	line("secrets", strings.Join(p.Secrets, ", "))
	line("key", p.Key)
	line("hosts", strings.Join(p.Hosts, ", "))
	line("host key", p.HostKey)
	line("remote user", p.RemoteUser)
	if !p.GrantEnds.IsZero() {
		line("grant ends", p.GrantEnds.Format(time.DateTime))
	}
	b.WriteString("— claimed by the agent —\n")
	line("as", p.Claim.Vars)
	line("command", p.Claim.Command)
	line("in", p.Claim.Dir)
	line("reason", p.Claim.Reason)
	var buttons []string
	if p.Once {
		buttons = append(buttons, "[Approve once]")
	}
	if p.WindowMinutes > 0 {
		buttons = append(buttons, "[Approve "+strconv.Itoa(p.WindowMinutes)+" min]")
	}
	buttons = append(buttons, "[Deny]")
	b.WriteString(strings.Join(buttons, " "))
	return b.String()
}

// Summary keeps the list of a weekly summary.
func (a *Approver) Summary(ctx context.Context, grants []approval.GrantInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.summaries = append(a.summaries, append([]approval.GrantInfo(nil), grants...))
	a.changedLocked()
	return nil
}

// Summaries returns the lists of the weekly summaries, oldest first.
func (a *Approver) Summaries() [][]approval.GrantInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([][]approval.GrantInfo(nil), a.summaries...)
}
