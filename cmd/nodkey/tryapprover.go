package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
)

// tryUserID is the approver user ID of the trial's config. Only the
// terminal approver sends it; there is no Telegram in the trial.
const tryUserID = 1

// maxTryLine caps a line that the person types.
const maxTryLine = 256

// An answer that comes before the broker knows the message is tried again
// up to tryEarlyRetries times, tryEarlyWait apart.
const (
	tryEarlyRetries = 50
	tryEarlyWait    = 20 * time.Millisecond
)

// errTryInputClosed is the error of tryApprover.Run when its input ends:
// no answer can come any more.
var errTryInputClosed = errors.New("the input of the terminal ended, so no answer can come")

// tryApprover is the approver of nodkey try: it shows each request in the
// terminal of nodkey try and reads the answers there. It exists only in
// the code of nodkey try. nodkey broker has no way to use it: a terminal
// on the agent machine is a place where the agent can type (THREAT-MODEL.md,
// "Try mode").
type tryApprover struct {
	in io.Reader

	outMu sync.Mutex
	out   io.Writer

	mu      sync.Mutex
	waiting map[string]approval.Prompt // the requests with a message, by short code
}

// newTryApprover returns a terminal approver that reads answers from in
// and writes its messages to out.
func newTryApprover(in io.Reader, out io.Writer) *tryApprover {
	return &tryApprover{in: in, out: out, waiting: make(map[string]approval.Prompt)}
}

// say writes text to the terminal, as one write.
func (a *tryApprover) say(text string) {
	a.outMu.Lock()
	defer a.outMu.Unlock()
	_, _ = io.WriteString(a.out, text)
}

// Ask shows the message of p and its choices.
func (a *tryApprover) Ask(ctx context.Context, p approval.Prompt) (approval.Shown, error) {
	if err := ctx.Err(); err != nil {
		return approval.Shown{}, err
	}
	text := tryMessage(p)
	a.mu.Lock()
	a.waiting[p.ShortCode] = p
	a.mu.Unlock()
	a.say(text)
	return approval.Shown{ID: tryMessageID(p), Text: text}, nil
}

// End says how the request of p ended.
func (a *tryApprover) End(_ context.Context, _ approval.MessageID, p approval.Prompt, e approval.Ending) error {
	a.mu.Lock()
	delete(a.waiting, p.ShortCode)
	a.mu.Unlock()
	var result string
	switch {
	case e.Answer == audit.AnswerApproveOnce:
		result = "approved once"
	case e.Answer == audit.AnswerApproveWindow:
		result = fmt.Sprintf("approved for %d min", e.WindowMinutes)
	case e.Cause == audit.CauseApprover:
		result = "denied"
	case e.Cause == audit.CauseExpired:
		result = "expired without an answer, so denied"
	default:
		result = "denied (" + tryClean(string(e.Cause)) + ")"
	}
	a.say(fmt.Sprintf("nodkey try: TRY MODE: request %s: %s\n\n", tryClean(p.ShortCode), result))
	return nil
}

// Notify says that a request was allowed without a question. The rules of
// the trial always ask, so it only shows the notice.
func (a *tryApprover) Notify(_ context.Context, p approval.Prompt) error {
	a.say(fmt.Sprintf("nodkey try: TRY MODE: notice: request %s was allowed without a question\n",
		tryClean(p.ShortCode)))
	return nil
}

// Run reads the answers, one a line, until ctx ends or the input ends.
func (a *tryApprover) Run(ctx context.Context, answer func(approval.Answer) error) error {
	lines := make(chan string)
	readDone := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(a.in)
		sc.Buffer(make([]byte, 0, maxTryLine), maxTryLine)
		for sc.Scan() {
			select {
			case lines <- sc.Text():
			case <-ctx.Done():
				return
			}
		}
		readDone <- errTryInputClosed
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-readDone:
			return err
		case line := <-lines:
			a.answerLine(line, answer)
		}
	}
}

// answerLine passes the answer that line holds to answer: "1", "2" or "3",
// with the short code before it when more than one request waits.
func (a *tryApprover) answerLine(line string, answer func(approval.Answer) error) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return
	}
	a.mu.Lock()
	var p approval.Prompt
	found := false
	switch len(fields) {
	case 1:
		if len(a.waiting) == 1 {
			for _, w := range a.waiting {
				p, found = w, true
			}
		}
	case 2:
		p, found = a.waiting[fields[0]]
	}
	a.mu.Unlock()
	if !found {
		a.say("nodkey try: TRY MODE: no such request; type 1, 2 or 3, and with more than one request, " +
			"the code before it, such as \"k3f9 1\"\n")
		return
	}
	var action audit.Answer
	switch fields[len(fields)-1] {
	case "1":
		action = audit.AnswerApproveOnce
	case "2":
		action = audit.AnswerApproveWindow
	case "3":
		action = audit.AnswerDeny
	default:
		a.say("nodkey try: TRY MODE: type 1 (Approve once), 2 (Approve N min) or 3 (Deny)\n")
		return
	}
	ans := approval.Answer{RequestID: p.RequestID, Action: action, Message: tryMessageID(p), UserID: tryUserID}
	err := answer(ans)
	// The terminal shows the message before Ask returns, so an answer can
	// come before the broker knows the message. Try again for a short time.
	for i := 0; i < tryEarlyRetries && errors.Is(err, approval.ErrTooEarly); i++ {
		time.Sleep(tryEarlyWait)
		err = answer(ans)
	}
	switch {
	case err == nil:
	case errors.Is(err, approval.ErrTooEarly):
		a.say("nodkey try: TRY MODE: the message is not ready yet; type it again\n")
	case errors.Is(err, approval.ErrNotAllowed):
		a.say("nodkey try: TRY MODE: this request does not offer that answer\n")
	default:
		a.say("nodkey try: TRY MODE: the answer did not count: the request has ended\n")
	}
}

// tryMessageID is the message ID of the request of p.
func tryMessageID(p approval.Prompt) approval.MessageID {
	return approval.MessageID("try-" + p.RequestID)
}

// tryMessage is the text of the message of p in the terminal.
func tryMessage(p approval.Prompt) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\nnodkey try: TRY MODE: request %s from client %s\n", tryClean(p.ShortCode), tryClean(p.Client))
	if len(p.Secrets) > 0 {
		fmt.Fprintf(&b, "  secrets: %s\n", tryClean(strings.Join(p.Secrets, ", ")))
	}
	b.WriteString("  claimed by the agent:\n")
	for _, f := range []struct{ name, value string }{
		{"variables", p.Claim.Vars}, {"command", p.Claim.Command}, {"in", p.Claim.Dir}, {"reason", p.Claim.Reason},
	} {
		if f.value != "" {
			fmt.Fprintf(&b, "    %s: %s\n", f.name, tryClean(f.value))
		}
	}
	fmt.Fprintf(&b, "  it expires in %s, at %s\n", p.TimeLeft.Round(time.Second), p.Expires.Format(time.TimeOnly))
	b.WriteString("  type:")
	if p.Once {
		b.WriteString(" 1 = Approve once,")
	}
	if p.WindowMinutes > 0 {
		fmt.Fprintf(&b, " 2 = Approve %d min,", p.WindowMinutes)
	}
	b.WriteString(" 3 = Deny\n")
	return b.String()
}

// tryClean replaces each control character and each other character that
// is not printable, so text from the agent cannot move the cursor or
// change the terminal.
func tryClean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return '?'
	}, s)
}
