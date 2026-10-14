package approval

import (
	"context"
	"errors"
	"time"

	"github.com/code6x/nodkey/internal/audit"
)

// Approver shows requests to the person and gets the person's answers.
// Telegram is one approver (DESIGN.md section 7). The core calls Ask, End
// and Notify from many goroutines at once, so they must be safe for that.
type Approver interface {
	// Ask sends a message for the request p, with the buttons that p
	// allows, and returns when the message is out. ctx ends when the
	// request ends: when it expires or the client hangs up, and also when
	// Run returns. Ask may try again until then. If Ask returns an error,
	// the core denies the request (audit cause error, code
	// approver_failed). An answer that comes before Ask returns gets
	// ErrTooEarly.
	Ask(ctx context.Context, p Prompt) (Shown, error)

	// End updates the message m when its request has ended: it removes
	// the buttons and shows how the request ended. p is the prompt that
	// Ask got. The core calls End once for each message that Ask sent.
	// An error does not change the decision; the core logs it.
	End(ctx context.Context, m MessageID, p Prompt, e Ending) error

	// Notify sends a silent notice that a "never ask" rule allowed the
	// request p without a tap (DESIGN.md section 12). The prompt has no
	// buttons. ctx ends as for Ask. If Notify returns an error, the core
	// denies the request, so a use without a tap is never unseen.
	Notify(ctx context.Context, p Prompt) error

	// Run gets the person's answers and passes each one to answer, until
	// ctx ends or the approver cannot get answers any more. It returns
	// why it stopped. While the approver's service cannot be reached for a
	// while, Run keeps trying; requests then expire and are denied.
	//
	// answer returns nil when the answer counted. Otherwise it returns one
	// of the Err values of this package, and the answer changed nothing.
	// The approver must answer every button press in its own way, so the
	// phone never shows a spinning button. It marks a message as expired
	// only on ErrUnknownRequest; on ErrTooEarly the person may tap again.
	Run(ctx context.Context, answer func(Answer) error) error
}

// MessageID names a message that an approver sent. The approver chooses
// its form: for Telegram it holds the chat and the message number. An
// answer counts only on the message of its own request, so the core
// compares the whole value. It is never empty.
type MessageID string

// Shown is a message that Ask sent.
type Shown struct {
	// ID names the message. An answer must name the same message.
	ID MessageID
	// Text is the exact text the person sees. It goes into the audit log.
	Text string
}

// Claim is what the client says about a request. The agent can write
// anything here, so a message shows it after the verified lines, under
// the "claimed by the agent" line (DESIGN.md section 7).
//
// The caller makes each field safe with package claim before it calls
// Decide: claim.Line(claim.Mask(s), n) for free text, and
// claim.Command(argv, n) for a command line. So each field is one clean
// line, and values that look like secrets are masked. The core checks
// that each field is one clean line and denies the request if not. It
// cannot check the masking. The approver must still escape the text for
// its own format, such as with claim.HTML for Telegram.
type Claim struct {
	// Vars are the names of the environment variables of a secrets
	// request, such as "GH_TOKEN".
	Vars string
	// Command is the command line: the command of nodkey run, or the
	// ssh command and its parents for an SSH login.
	Command string
	// Dir is the working directory of a secrets request.
	Dir string
	// Reason is the reason the agent gives.
	Reason string
}

// Prompt is what the approver shows for one request: a message with
// buttons, or for Notify a notice without buttons (DESIGN.md section 7).
// The approver gets its own copy and must not keep slices of it past the
// call.
type Prompt struct {
	// RequestID is the request's random ID. The buttons carry it, and an
	// answer must name it.
	RequestID string
	// ShortCode is the code for people, such as "k3f9". The client prints
	// it too, so a person can match the message with the terminal.
	ShortCode string
	// Kind says what the request asks for.
	Kind audit.Kind

	// The verified part: names from the broker config and its
	// known_hosts file, and data the broker checked.

	// Client is the client name.
	Client string
	// Secrets are the secret names of a secrets request.
	Secrets []string
	// Key is the key name of an SSH request.
	Key string
	// Hosts are host names from the broker's known_hosts: the one host of
	// an SSH login, or the hosts of an SSH grant.
	Hosts []string
	// HostKey is the SHA256 fingerprint of the host key of an SSH login.
	HostKey string
	// RemoteUser is the remote user name of an SSH request.
	RemoteUser string
	// GrantEnds is when the grants of an SSH grant end, if the person
	// approves it (DESIGN.md section 13).
	GrantEnds time.Time

	// Claim is the claimed part.
	Claim Claim

	// Expires is when the request ends without an answer, and TimeLeft is
	// how much time it had left when the message was made. They are zero
	// in a notice.
	Expires  time.Time
	TimeLeft time.Duration

	// The buttons. "Deny" is always there, except in a notice.

	// Once says that the message has "Approve once".
	Once bool
	// WindowMinutes is N in the "Approve N min" button. 0 means the
	// message has no such button. For an SSH grant, this button makes the
	// grants that end at GrantEnds.
	WindowMinutes int
}

// Ending says how a request with a message ended, so the approver can
// update the message (DESIGN.md section 7).
type Ending struct {
	// Answer is the person's answer, or "" if the person did not answer.
	Answer audit.Answer
	// WindowMinutes is the length of the grants of an approve_window
	// answer.
	WindowMinutes int
	// Cause says why the request was denied. It is empty for an approval.
	Cause audit.Cause
	// At is when the request ended.
	At time.Time
}

// Answer is a button press that the approver passes to the core.
type Answer struct {
	// RequestID is the request ID from the button.
	RequestID string
	// Action is the button: audit.AnswerApproveOnce,
	// audit.AnswerApproveWindow or audit.AnswerDeny.
	Action audit.Answer
	// Message is the message the button is on.
	Message MessageID
	// UserID is the Telegram user ID of the person who pressed it.
	UserID int64
}

// Why an answer did not count. An answer that did not count changes
// nothing: the request still waits, or it had already ended.
var (
	// ErrUnknownRequest: no request with this ID waits for an answer. The
	// request was answered before, it ended, it is from before a restart,
	// or the ID was never made. The approver may mark the message as
	// expired.
	ErrUnknownRequest = errors.New("approval: no request with this ID waits for an answer")
	// ErrTooEarly: the message of the request is still being sent, so the
	// core does not know it yet. The request still waits: the approver must
	// not mark the message as expired, and the person may tap again.
	ErrTooEarly = errors.New("approval: the message of this request is still being sent; tap again")
	// ErrNotApprover: the answer is not from the configured approver.
	ErrNotApprover = errors.New("approval: the answer is not from the approver")
	// ErrWrongMessage: the answer is not on the message of its request.
	ErrWrongMessage = errors.New("approval: the answer is not on the message of its request")
	// ErrExpired: the request's time is up.
	ErrExpired = errors.New("approval: the request has expired")
	// ErrNotAllowed: the request does not offer this button.
	ErrNotAllowed = errors.New("approval: the request does not allow this answer")
	// ErrStopped: the core no longer takes answers, because Run returned.
	// A request that needed the person then ended with this error.
	ErrStopped = errors.New("approval: the approver has stopped")
)
