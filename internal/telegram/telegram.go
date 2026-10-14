// Package telegram is the Telegram approver of the broker (DESIGN.md
// section 7). It sends each request to the approver as a message with
// buttons, and passes the approver's button presses to the approval core.
//
// It has its own small client for the Telegram Bot API: long polling with
// getUpdates, sendMessage, editMessageText and answerCallbackQuery. There
// is no webhook, so the broker needs no open port to the internet.
//
// The bot token is in the URL of every call, and Go's HTTP errors hold the
// URL. So no error and no log line of this package holds Go's error text
// or the URL: an error names the Bot API method and a fixed reason
// (THREAT-MODEL.md T19).
//
// A button press counts only if all of these are true (DESIGN.md section
// 7): it is from the configured user ID, in the private chat with that
// user, on the message of its request, which nobody else changed, for a
// request that waits, before it expires, with a button that the request
// offers. This package checks the user, the chat, the button data, and
// that the message is as Ask sent it. Then the approval core checks the
// user, the message, the request, the time and the button again.
package telegram

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// NoticesPerMinute is the most notices of "never ask" uses that Notify
// sends in any 60 seconds, for all clients together. Telegram allows about
// 20 messages per minute in a group. The core has its own, smaller limit
// for each client (approval.MaxNoticesPerMinute).
const NoticesPerMinute = 20

// maxRemembered is the most messages whose state the approver keeps, for
// taps that come after their request ended.
const maxRemembered = 1024

// refusedTapsPerMinute is the most button presses that did not count that
// the approver logs and reports for the audit log in one minute. It
// counts the others, and logs how many it dropped. So a holder of the bot
// token cannot fill the journal or the disk with forged buttons.
const refusedTapsPerMinute = 20

const (
	// alertTimeout bounds Alert, also when its context has no deadline.
	alertTimeout = 30 * time.Second
	// changedAlertEvery is the shortest time between two alerts about a
	// message that someone else changed.
	changedAlertEvery = 10 * time.Minute
)

// changedAlert is the alert message when someone else changed a message
// of the broker whose request may still wait.
const changedAlert = "Someone else changed a message of the broker while its request waited for an answer. " +
	"The bot token may be stolen. Taps on that message do not count. Make a new token with @BotFather, put it " +
	"in the token file, and restart the broker."

var (
	// ErrPollConflict: getUpdates failed with a conflict. Another program
	// polls with the bot token, or a webhook is set, so the token may be
	// stolen (THREAT-MODEL.md T6). Run returns it after it sent an alert.
	// The broker writes an error entry with code poll_conflict, and stops.
	ErrPollConflict = errors.New("telegram: another program polls with the bot token, or a webhook is set; " +
		"the bot token may be stolen")
	// ErrNoticeLimit: Notify sent NoticesPerMinute notices in the last 60
	// seconds, so it sends no more. The core then denies the use.
	ErrNoticeLimit = errors.New("telegram: too many notices in the last minute")
)

// Options are the optional parts of an Approver.
type Options struct {
	// Logger gets refused button presses and problems with Telegram. The
	// default drops them. No line holds the bot token or message text.
	Logger *slog.Logger
	// ForeignTap, if set, gets each button press that did not count,
	// except one that came too early (approval.ErrTooEarly): from another
	// user or chat, on an inline message, with button data that is not
	// valid, on a message that someone else changed, on another message,
	// or for a request that no longer waits. Its Cause says which. It
	// gets at most refusedTapsPerMinute in a minute; Run logs how many
	// more it dropped. The broker writes each to the audit log as a
	// foreign_tap entry (DESIGN.md section 9). Run calls it from its own
	// goroutine, so it must not block for long.
	ForeignTap func(audit.ForeignTap)
}

// Approver is the Telegram approver: an approval.Approver. Make it with
// New. Ask, End, Notify and Alert are safe for use by many goroutines.
// Run runs once at a time.
type Approver struct {
	api        *client
	userID     int64 // the approver; the private chat with the approver has the same ID
	noticeChat int64
	log        *slog.Logger
	foreignTap func(audit.ForeignTap)
	now        func() time.Time // the clock of the notice limit; tests replace it

	running atomic.Bool // Run runs

	mu sync.Mutex
	// sent holds the messages that Ask sent. order holds its keys, oldest
	// first; there are at most maxRemembered.
	sent  map[approval.MessageID]*sentMessage
	order []approval.MessageID
	// notices holds when the newest notices were sent.
	notices []time.Time
	// reports counts the reports of refused taps in the current minute.
	reports reportWindow
	// changedAlertAt is when the last alert about a changed message went
	// out.
	changedAlertAt time.Time
}

// sentMessage is what the approver knows about a message that Ask sent.
type sentMessage struct {
	// keyboard is the buttons that Ask sent. A tap on the message counts
	// only while the message has exactly these buttons.
	keyboard [][]inlineButton
	// final is the HTML text that End gave the message, or "" before End.
	final string
}

// reportWindow counts the reports of refused taps in one minute.
type reportWindow struct {
	start   time.Time // when the minute began; zero before the first report
	n       int       // the reports let through
	dropped int       // the reports dropped
}

var _ approval.Approver = (*Approver)(nil)

// New returns the Telegram approver for the [telegram] section cfg. It
// reads the bot token from cfg.TokenFile with config.ReadPrivateFile. Only
// button presses of cfg.UserID count; notices go to cfg.NoticeChatID.
// Errors never show the token.
func New(cfg config.Telegram, opts Options) (*Approver, error) {
	return newApprover(cfg, opts, config.ReadPrivateFile, defaultBaseURL)
}

// newApprover is New with the token reader and the address of the Bot API.
// Tests use a fake reader and a fake Telegram server.
func newApprover(cfg config.Telegram, opts Options, read func(string) ([]byte, error), base string) (*Approver, error) {
	if cfg.UserID <= 0 {
		return nil, errors.New("telegram: the approver's user ID must be more than 0")
	}
	if cfg.NoticeChatID == 0 {
		return nil, errors.New("telegram: the notice chat ID must not be 0")
	}
	data, err := read(cfg.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("telegram: cannot read the bot token: %w", err) // the error names the path, never the content
	}
	token, err := parseToken(data)
	clear(data)
	if err != nil {
		return nil, err
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	switch proxy, ok := proxyFor(base); {
	case !ok:
		logger.LogAttrs(context.Background(), slog.LevelWarn,
			"telegram: the proxy setting in the environment is not valid, so no call to Telegram can work")
	case proxy != nil:
		// Only the host: the setting may hold a user name and a password.
		logger.LogAttrs(context.Background(), slog.LevelInfo,
			"telegram: calls to Telegram go through a proxy from the environment; a proxy that inspects TLS sees the bot token",
			slog.String("proxy_host", proxy.Host))
	}
	return &Approver{
		api:        newClient(token, base),
		userID:     cfg.UserID,
		noticeChat: cfg.NoticeChatID,
		log:        logger,
		foreignTap: opts.ForeignTap,
		now:        time.Now,
		sent:       make(map[approval.MessageID]*sentMessage),
	}, nil
}

// Format shows only the type, never the token: fmt does not call the
// methods of unexported fields, so it would print the token's text.
func (*Approver) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "telegram.Approver") }

// String returns only the type, never the token.
func (*Approver) String() string { return "telegram.Approver" }

// Ask sends the message of p to the approver's private chat, with the
// buttons that p allows, and returns its ID and its text. It sends nothing
// when ctx has ended. It tries again after a server error or a network
// error until ctx ends (approval.Approver). It fails if p is not a prompt
// that the core makes, or if the message does not fit in one Telegram
// message; the core then denies the request.
//
// The text in Shown is the plain text that the person sees, with the
// buttons as a last line, as in DESIGN.md section 7. It goes into the
// audit log.
func (a *Approver) Ask(ctx context.Context, p approval.Prompt) (approval.Shown, error) {
	if err := ctx.Err(); err != nil {
		return approval.Shown{}, err
	}
	t, kb, err := promptMessage(p)
	if err != nil {
		return approval.Shown{}, err
	}
	var sent message
	err = a.api.call(ctx, "sendMessage", sendMessageParams{
		ChatID:             a.userID,
		Text:               t.html.String(),
		ParseMode:          "HTML",
		LinkPreviewOptions: noPreview,
		ReplyMarkup:        &kb,
	}, &sent)
	if err != nil {
		return approval.Shown{}, err
	}
	if sent.MessageID <= 0 || sent.Chat.ID != a.userID {
		return approval.Shown{}, errors.New("telegram: sendMessage: the answer names another chat, or no message")
	}
	m := messageID(sent.Chat.ID, sent.MessageID)
	a.remember(m, kb.InlineKeyboard)
	return approval.Shown{ID: m, Text: t.plain.String() + "\n" + buttonsLine(kb)}, nil
}

// End updates the message m after its request ended: the same lines, with
// the result instead of the expiry, and no buttons. It always sends an
// empty keyboard: leaving the keyboard out would keep the buttons.
func (a *Approver) End(ctx context.Context, m approval.MessageID, p approval.Prompt, e approval.Ending) error {
	chatID, msgID, ok := parseMessageID(m)
	if !ok || chatID != a.userID {
		return errors.New("telegram: End: the message ID is not one that Ask returned")
	}
	html := endingText(p, e).html.String()
	// First, so that a tap that comes now sees that the broker itself
	// changes this message, and leaves the result as it is.
	a.setFinal(m, html)
	return a.edit(ctx, chatID, msgID, html)
}

// Notify sends a silent notice of the "never ask" use p to the notice
// chat. It sends nothing when ctx has ended, and nothing when it sent
// NoticesPerMinute notices in the last 60 seconds: then it returns
// ErrNoticeLimit, and the core denies the use.
func (a *Approver) Notify(ctx context.Context, p approval.Prompt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	t, err := noticeText(p)
	if err != nil {
		return err
	}
	if !a.takeNotice() {
		a.log.LogAttrs(ctx, slog.LevelWarn, "telegram: too many notices in the last minute; the use is denied",
			slog.String("request_id", p.RequestID), slog.Int("limit", NoticesPerMinute))
		return ErrNoticeLimit
	}
	return a.api.call(ctx, "sendMessage", sendMessageParams{
		ChatID:              a.noticeChat,
		Text:                t.html.String(),
		ParseMode:           "HTML",
		LinkPreviewOptions:  noPreview,
		DisableNotification: true,
	}, nil)
}

// Alert sends msg to the approver's private chat, with a sound, for a
// problem the person must see, such as a polling conflict or a torn line
// in the audit log. msg is the broker's own text, never claimed text. It
// is HTML-escaped and cut to maxAlertUnits. Alert takes at most
// alertTimeout, also when ctx has no deadline: it does not wait long when
// Telegram asks to wait.
func (a *Approver) Alert(ctx context.Context, msg string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, alertTimeout)
	defer cancel()
	var t text
	t.write("⚠️ nodkey: " + cutUnits(strings.ToValidUTF8(msg, "�"), maxAlertUnits))
	return a.api.call(ctx, "sendMessage", sendMessageParams{
		ChatID:             a.userID,
		Text:               t.html.String(),
		ParseMode:          "HTML",
		LinkPreviewOptions: noPreview,
	}, nil)
}

// edit replaces the text of a message with html, and removes its buttons.
func (a *Approver) edit(ctx context.Context, chatID, msgID int64, html string) error {
	err := a.api.call(ctx, "editMessageText", editMessageTextParams{
		ChatID:             chatID,
		MessageID:          msgID,
		Text:               html,
		ParseMode:          "HTML",
		LinkPreviewOptions: noPreview,
		ReplyMarkup:        emptyKeyboard(),
	}, nil)
	if errors.Is(err, errNotModified) {
		return nil // it shows this text already, without buttons
	}
	return err
}

// remember notes the message m that Ask sent with these buttons.
func (a *Approver) remember(m approval.MessageID, keyboard [][]inlineButton) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entryLocked(m).keyboard = keyboard
}

// setFinal notes the text that End gives the message m.
func (a *Approver) setFinal(m approval.MessageID, html string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entryLocked(m).final = html
}

// entryLocked returns the entry of m, and makes it if needed. When the
// approver holds maxRemembered messages, it forgets the oldest one whose
// request ended, so a message whose request waits stays known; only if
// none ended, it forgets the oldest. a.mu must be held.
func (a *Approver) entryLocked(m approval.MessageID) *sentMessage {
	if e := a.sent[m]; e != nil {
		return e
	}
	if len(a.order) >= maxRemembered {
		i := slices.IndexFunc(a.order, func(k approval.MessageID) bool { return a.sent[k].final != "" })
		i = max(i, 0)
		delete(a.sent, a.order[i])
		a.order = slices.Delete(a.order, i, i+1)
	}
	e := &sentMessage{}
	a.sent[m] = e
	a.order = append(a.order, m)
	return e
}

// lookup returns what the approver knows about the message m. known is
// false when the approver did not send m, or forgot it.
func (a *Approver) lookup(m approval.MessageID) (e sentMessage, known bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if p := a.sent[m]; p != nil {
		return *p, true
	}
	return sentMessage{}, false
}

// takeReport reports whether a refused tap may be logged and reported now,
// and counts it. dropped is the number of reports dropped in the minute
// before, when that minute has just ended, so the caller logs it.
func (a *Approver) takeReport() (ok bool, dropped int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if a.reports.start.IsZero() || now.Sub(a.reports.start) >= time.Minute {
		dropped = a.reports.dropped
		a.reports = reportWindow{start: now}
	}
	if a.reports.n >= refusedTapsPerMinute {
		a.reports.dropped++
		return false, dropped
	}
	a.reports.n++
	return true, dropped
}

// endReports returns the number of reports dropped in the last minute,
// when that minute has ended, and starts a new count. Run calls it after
// each getUpdates, so the count is logged even when no tap comes.
func (a *Approver) endReports() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.reports.dropped == 0 || a.now().Sub(a.reports.start) < time.Minute {
		return 0
	}
	dropped := a.reports.dropped
	a.reports = reportWindow{}
	return dropped
}

// takeChangedAlert reports whether an alert about a changed message may go
// out now: at most one in changedAlertEvery.
func (a *Approver) takeChangedAlert() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if !a.changedAlertAt.IsZero() && now.Sub(a.changedAlertAt) < changedAlertEvery {
		return false
	}
	a.changedAlertAt = now
	return true
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
