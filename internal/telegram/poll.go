package telegram

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
)

const (
	// pollFirstBackoff and pollMaxBackoff bound the wait before the next
	// getUpdates after an error.
	pollFirstBackoff = time.Second
	pollMaxBackoff   = 30 * time.Second
	// tapTimeout bounds the calls to Telegram for one button press: the
	// answer to it, and an update of its message.
	tapTimeout = 10 * time.Second
	// maxTapData is the most bytes of button data in a foreign_tap entry,
	// as Telegram allows.
	maxTapData = 64
)

// conflictAlert is the alert message after a polling conflict.
const conflictAlert = "Telegram reports a conflict: another program reads the updates of this bot, " +
	"or a webhook is set. The bot token may be stolen. The broker no longer takes answers, so it denies " +
	"every request that needs a tap. Make a new token with @BotFather, put it in the token file, and " +
	"restart the broker."

// errPanic: Run stopped because handling an update panicked.
var errPanic = errors.New("telegram: polling stopped after a panic; no answers can come any more")

// The short texts that the phone shows after a button press.
const (
	tapCountedApprove = "Approved."
	tapCountedDeny    = "Denied."
	tapCountedRevoke  = "Revoked."
	tapTooEarly       = "Not ready yet. Tap again in a moment."
	tapEnded          = "This request has ended."
	tapExpired        = "This request has expired."
	tapRefused        = "This button does not count."
	tapChanged        = "Someone else changed this message. This tap does not count."
	tapChangedDenied  = "Denied. Someone else changed this message."
)

// Run gets the button presses with long polling (getUpdates) and passes
// each valid one to answer, until ctx ends or no answer can come any
// more. It always returns why it stopped, and never panics.
//
//   - Every button press gets answerCallbackQuery, so the phone never
//     shows a spinning button.
//   - A press that is not from the approver, not in the private chat with
//     the approver, on an inline message, or with button data that is not
//     valid never reaches answer. It is logged and goes to
//     Options.ForeignTap, and so does every press that answer refuses,
//     except one that came too early on a message that nobody else
//     changed.
//   - An Approve on a message that is not as Ask sent it, because someone
//     edited it (edit_date) or its buttons differ, never reaches answer.
//     The broker never edits a message while its request waits. If its
//     request may still wait, Run also sends an alert, at most one in
//     changedAlertEvery: the bot token may be stolen. A Deny is safe
//     whatever the message shows: while the request may wait, the Deny
//     button that Ask sent on such a message still reaches answer. So the
//     pause and the end of grants after a Deny still work. Like every
//     press on that message, it is reported with cause edited_message,
//     also when it counts, and the alert goes out after it.
//   - On approval.ErrTooEarly, the message stays as it is, so the person
//     can tap again. Only when no request waits on the message does Run
//     update it: if this approver ended it, it shows its result again; if
//     not, such as a message from before a restart, only its buttons are
//     removed, and its text stays.
//   - At most refusedTapsPerMinute refused presses of the approver in a
//     minute are logged and reported, and as many of other users. So
//     forged presses cannot crowd out the reports of the approver's own,
//     such as a press on a message that someone else changed. Run logs
//     how many more it dropped.
//   - While Telegram cannot be reached, Run keeps trying, with a growing
//     wait of at most pollMaxBackoff, and never shorter than Telegram asks
//     for with code 429.
//   - On a conflict (another program polls with the token, or a webhook
//     is set), it logs an alert, sends an alert message, and returns
//     ErrPollConflict. When Telegram refuses getUpdates in another way,
//     such as for a token that is no longer valid, it returns that error.
//     After 401 or 404, that error wraps ErrTokenRefused.
func (a *Approver) Run(ctx context.Context, answer func(approval.Answer) error) (err error) {
	if answer == nil {
		return errors.New("telegram: Run needs a function for the answers")
	}
	if !a.running.CompareAndSwap(false, true) {
		return errors.New("telegram: Run is running already; only one may poll with a bot token")
	}
	defer a.running.Store(false)
	defer func() {
		if r := recover(); r != nil {
			err = errPanic
			a.logPanic(ctx)
		}
	}()
	return a.poll(ctx, answer)
}

// logPanic logs that Run stopped after a panic. The panic value may hold
// text from an update, so it is not logged. A panic of the logger itself
// is dropped, so Run still returns.
func (a *Approver) logPanic(ctx context.Context) {
	defer func() { _ = recover() }()
	a.log.LogAttrs(context.WithoutCancel(ctx), slog.LevelError, "telegram: polling stopped after a panic")
}

// poll is the loop of Run.
func (a *Approver) poll(ctx context.Context, answer func(approval.Answer) error) error {
	var offset int64
	backoff := pollFirstBackoff
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("telegram: polling stopped: %w", err)
		}
		updates, e := a.api.getUpdates(ctx, offset)
		if e != nil {
			switch {
			case ctx.Err() != nil:
				return fmt.Errorf("telegram: polling stopped: %w", ctx.Err())
			case errors.Is(e, ErrPollConflict):
				return a.conflict(ctx)
			case e.code >= 400 && e.code < 500 && e.code != http.StatusTooManyRequests:
				a.log.LogAttrs(ctx, slog.LevelError, "telegram: Telegram refused getUpdates; no answers can come any more",
					slog.String("error", e.Error()))
				return fmt.Errorf("telegram: polling stopped: %w", e)
			}
			// Never shorter than Telegram asks, and longer each time.
			wait := max(e.retryAfter, backoff)
			backoff = min(2*backoff, pollMaxBackoff)
			a.endedReports(ctx)
			a.log.LogAttrs(ctx, slog.LevelWarn, "telegram: getUpdates failed; trying again",
				slog.String("error", e.Error()), slog.Duration("wait", wait))
			if err := a.api.sleep(ctx, wait); err != nil {
				return fmt.Errorf("telegram: polling stopped: %w", err)
			}
			continue
		}
		backoff = pollFirstBackoff
		a.endedReports(ctx)
		for _, u := range updates {
			if u.UpdateID < offset || u.UpdateID < 0 || u.UpdateID == math.MaxInt64 {
				continue // handled before, or not a valid ID
			}
			// The next getUpdates confirms this update: Telegram then
			// forgets it.
			offset = u.UpdateID + 1
			a.handle(ctx, u, answer)
		}
	}
}

// conflict alerts after a polling conflict, and returns ErrPollConflict.
func (a *Approver) conflict(ctx context.Context) error {
	a.log.LogAttrs(ctx, slog.LevelError, "telegram: ALERT: Telegram reports a polling conflict: another program "+
		"polls with the bot token, or a webhook is set. The bot token may be stolen. No answer counts any more.")
	// The alert goes out even when ctx ends now. Alert has its own limit.
	if err := a.Alert(context.WithoutCancel(ctx), conflictAlert); err != nil {
		a.log.LogAttrs(ctx, slog.LevelError, "telegram: cannot send the alert message", slog.String("error", err.Error()))
	}
	return ErrPollConflict
}

// handle handles one update.
func (a *Approver) handle(ctx context.Context, u update, answer func(approval.Answer) error) {
	if u.malformed {
		a.log.LogAttrs(ctx, slog.LevelWarn, "telegram: skipped an update that does not have the expected form",
			slog.Int64("update_id", u.UpdateID))
		return
	}
	q := u.CallbackQuery
	if q == nil {
		if u.Message != nil {
			a.command(ctx, u.Message)
		}
		return
	}
	tctx, cancel := context.WithTimeout(ctx, tapTimeout)
	defer cancel()

	ans, cause := a.check(q)
	if cause != "" {
		text := tapRefused
		if q.From.ID != a.userID {
			text = "" // say nothing to other users
		}
		a.answerTap(tctx, q, text)
		a.report(ctx, q, cause)
		return
	}
	handled, changedDeny := a.changed(tctx, q, ans)
	if handled {
		return
	}
	err := answer(ans)
	text, cause := tapResult(ans.Action, err)
	if changedDeny {
		// A Deny on a message that someone else changed (see changed).
		// Like every tap on that message, it is reported with cause
		// edited_message, also when it counted. So the audit log shows
		// the edit next to the decision entry of the Deny.
		cause = audit.TapEditedMessage
		if err == nil {
			text = tapChangedDenied
		}
	}
	a.answerTap(tctx, q, text)
	switch {
	case changedDeny && err == nil:
		a.reportAs(ctx, q, cause, "telegram: a Deny counted on a message that someone else changed")
	case cause != "":
		a.report(ctx, q, cause)
	case errors.Is(err, approval.ErrTooEarly):
		// The message is still being sent. It stays as it is, so the
		// person can tap again. That is no foreign tap.
		a.log.LogAttrs(ctx, slog.LevelInfo, "telegram: a button press came before its message was sent; the person may tap again",
			slog.String("request_id", ans.RequestID))
	}
	if errors.Is(err, approval.ErrUnknownRequest) {
		a.ended(tctx, q.Message)
	}
	if changedDeny {
		// After the core, so that a slow alert cannot delay the Deny.
		a.alertChanged(ctx, q)
	}
}

// tapResult returns what the phone shows after the core's answer err to a
// press of the button action, and why the press did not count: "" when it
// counted, or when it came too early (approval.ErrTooEarly), so that it is
// not reported.
func tapResult(action audit.Answer, err error) (string, audit.TapCause) {
	switch {
	case err == nil && action == audit.AnswerDeny:
		return tapCountedDeny, ""
	case err == nil && action == audit.AnswerRevoke:
		return tapCountedRevoke, ""
	case err == nil:
		return tapCountedApprove, ""
	case errors.Is(err, approval.ErrTooEarly):
		return tapTooEarly, ""
	case errors.Is(err, approval.ErrUnknownRequest):
		return tapEnded, audit.TapUnknownRequest
	case errors.Is(err, approval.ErrExpired):
		return tapExpired, audit.TapExpired // the core ends it, and End updates the message
	}
	return tapRefused, refusalCause(err)
}

// check makes the checks of the Telegram code: the user, the chat, the
// message and the button data. It returns the answer for the core, or why
// the press does not count.
func (a *Approver) check(q *callbackQuery) (approval.Answer, audit.TapCause) {
	switch {
	case q.From.ID != a.userID:
		return approval.Answer{}, audit.TapOtherUser
	case q.InlineMessageID != "":
		return approval.Answer{}, audit.TapInlineMessage
	case q.Message == nil || q.Message.MessageID <= 0:
		return approval.Answer{}, audit.TapNoMessage
	case q.Message.Chat.Type != "private" || q.Message.Chat.ID != a.userID:
		return approval.Answer{}, audit.TapOtherChat
	}
	action, id, ok := parseData(q.Data)
	if !ok || q.GameShortName != "" {
		return approval.Answer{}, audit.TapBadData
	}
	return approval.Answer{
		RequestID: id,
		Action:    action,
		Message:   messageID(q.Message.Chat.ID, q.Message.MessageID),
		UserID:    q.From.ID,
	}, ""
}

// changed handles a press on a message that is not as Ask sent it: it was
// edited (edit_date), or its buttons are not the ones Ask sent. The broker
// never edits a message while its request waits. It reports whether it
// handled the press; if not, the press goes to the core. deny says that
// the press is a Deny on a message that someone else changed.
//
//   - If this approver sent the message and End has not changed it, its
//     request may still wait: someone else changed it, so the bot token
//     may be stolen (THREAT-MODEL.md T6). An Approve on it never counts:
//     it is refused and reported, and the approver gets an alert, at most
//     one in changedAlertEvery. End later writes the whole text again,
//     with the result. A Deny is safe whatever the message shows, so the
//     Deny button that Ask sent on that message goes to the core, as on
//     any message (THREAT-MODEL.md T8). Then handle reports it with cause
//     edited_message, also when it counted, and sends the alert.
//   - Else End changed it, or this approver does not know it, such as a
//     message from before a restart. No request of this approver waits on
//     it, so this is a late press.
func (a *Approver) changed(ctx context.Context, q *callbackQuery, ans approval.Answer) (handled, deny bool) {
	sent, known := a.lookup(ans.Message)
	if ans.Action == audit.AnswerRevoke {
		// A Revoke only takes a right away, so a changed message is no
		// reason to refuse it on the message of a grant (held), on one that
		// ended, or on one that this approver does not know (too old). The
		// other checks stay: the user, the chat, the data, and in the core
		// the grant of the request ID on this very message. But a message
		// whose request may still wait has no Revoke button: such a button
		// was put there by someone else, as a changed message.
		if known && sent.final == "" && !sent.held {
			a.answerTap(ctx, q, tapChanged)
			a.report(ctx, q, audit.TapEditedMessage)
			a.alertChanged(ctx, q)
			return true, false
		}
		return false, false
	}
	if known && sent.final == "" && sent.held {
		// The request of this message is decided; End gave it a Revoke
		// button. Only a Revoke can count on it. A button of its request is
		// a late tap, such as the second tap of a double tap. A button of
		// another request is not on this message by the broker's doing.
		if ans.RequestID != sent.heldID {
			a.answerTap(ctx, q, tapChanged)
			a.report(ctx, q, audit.TapEditedMessage)
			a.alertChanged(ctx, q)
			return true, false
		}
		a.answerTap(ctx, q, tapEnded)
		a.report(ctx, q, audit.TapUnknownRequest)
		return true, false
	}
	edited := q.Message.EditDate != 0
	if known && sent.final == "" && !sameKeyboard(sent.keyboard, q.Message.ReplyMarkup) {
		edited = true
	}
	switch {
	case !edited:
		return false, false
	case known && sent.final == "" && ans.Action == audit.AnswerDeny && sentData(sent.keyboard, q.Data):
		return false, true
	case known && sent.final == "":
		a.answerTap(ctx, q, tapChanged)
		a.report(ctx, q, audit.TapEditedMessage)
		a.alertChanged(ctx, q)
		return true, false
	}
	a.answerTap(ctx, q, tapEnded)
	a.report(ctx, q, audit.TapUnknownRequest)
	a.ended(ctx, q.Message)
	return true, false
}

// alertChanged alerts that someone else changed a message of the broker
// whose request may still wait: it logs an alert, and sends an alert
// message, at most one in changedAlertEvery.
func (a *Approver) alertChanged(ctx context.Context, q *callbackQuery) {
	if !a.takeChangedAlert() {
		return
	}
	a.log.LogAttrs(ctx, slog.LevelError, "telegram: ALERT: someone else changed a message of the broker "+
		"while its request waited; the bot token may be stolen", slog.Int64("message_id", q.Message.MessageID))
	if err := a.Alert(context.WithoutCancel(ctx), changedAlert); err != nil {
		a.log.LogAttrs(ctx, slog.LevelError, "telegram: cannot send the alert message", slog.String("error", err.Error()))
	}
}

// sentData reports whether one of kb, the buttons that Ask sent, has the
// button data data.
func sentData(kb [][]inlineButton, data string) bool {
	return slices.ContainsFunc(kb, func(row []inlineButton) bool {
		return slices.ContainsFunc(row, func(b inlineButton) bool { return b.CallbackData == data })
	})
}

// sameKeyboard reports whether got, the buttons of a message as Telegram
// has them, are exactly want, the buttons that Ask sent: the same rows,
// labels and data.
func sameKeyboard(want [][]inlineButton, got *inlineKeyboard) bool {
	if got == nil || len(got.InlineKeyboard) != len(want) {
		return false
	}
	for i, row := range want {
		if !slices.Equal(row, got.InlineKeyboard[i]) {
			return false
		}
	}
	return true
}

// refusalCause says why the core refused an answer.
func refusalCause(err error) audit.TapCause {
	switch {
	case errors.Is(err, approval.ErrExpired):
		return audit.TapExpired
	case errors.Is(err, approval.ErrWrongMessage):
		return audit.TapWrongMessage
	case errors.Is(err, approval.ErrNotAllowed):
		return audit.TapNotAllowed
	}
	return audit.TapRefused
}

// answerTap answers the button press q, so the phone stops the spinning
// button. text is shown for a moment; "" shows nothing.
func (a *Approver) answerTap(ctx context.Context, q *callbackQuery, text string) {
	if q.ID == "" {
		a.log.LogAttrs(ctx, slog.LevelWarn, "telegram: a button press has no ID, so it cannot be answered")
		return
	}
	err := a.api.call(ctx, "answerCallbackQuery", answerCallbackQueryParams{CallbackQueryID: q.ID, Text: text}, nil)
	if err != nil {
		a.log.LogAttrs(ctx, slog.LevelWarn, "telegram: cannot answer a button press", slog.String("error", err.Error()))
	}
}

// report logs a button press that did not count, and passes it to
// Options.ForeignTap, at most refusedTapsPerMinute in a minute for each
// budget: the presses of the approver, and those of other users. So
// forged presses cannot crowd out the reports of the approver's own. It
// counts the others, and logs how many it dropped.
func (a *Approver) report(ctx context.Context, q *callbackQuery, cause audit.TapCause) {
	a.reportAs(ctx, q, cause, "telegram: refused a button press")
}

// reportAs is report with the log message msg. handle uses it for a Deny
// that counted on a message that someone else changed: it is reported
// with cause edited_message too, but it was not refused.
func (a *Approver) reportAs(ctx context.Context, q *callbackQuery, cause audit.TapCause, msg string) {
	// A press on a message that someone else changed is always the
	// approver's, as check runs first. It is named here too, so that its
	// report can never move to the budget of other users.
	own := q.From.ID == a.userID || cause == audit.TapEditedMessage
	ok, dropped := a.takeReport(own)
	a.logDropped(ctx, dropped, own)
	if !ok {
		return
	}
	tap := audit.ForeignTap{UserID: q.From.ID, Data: cutData(q.Data), Cause: cause}
	if q.Message != nil {
		tap.ChatID = q.Message.Chat.ID
		tap.MessageID = q.Message.MessageID
	}
	a.log.LogAttrs(ctx, slog.LevelWarn, msg,
		slog.String("cause", string(cause)), slog.Int64("user_id", tap.UserID), slog.Int64("chat_id", tap.ChatID),
		slog.Int64("message_id", tap.MessageID), slog.String("data", tap.Data))
	if a.foreignTap != nil {
		a.foreignTap(tap)
	}
}

// endedReports logs how many reports of each budget were dropped in the
// last minute, if that minute has ended.
func (a *Approver) endedReports(ctx context.Context) {
	others, own := a.endReports()
	a.logDropped(ctx, others, false)
	a.logDropped(ctx, own, true)
}

// logDropped logs how many reports of one budget were dropped: of the
// approver's own presses (own), or of other users.
func (a *Approver) logDropped(ctx context.Context, dropped int, own bool) {
	if dropped <= 0 {
		return
	}
	from := "other_users"
	if own {
		from = "approver"
	}
	a.log.LogAttrs(ctx, slog.LevelWarn, "telegram: dropped reports of refused button presses, to keep the log small",
		slog.Int("dropped", dropped), slog.Int("limit_per_minute", refusedTapsPerMinute), slog.String("from", from))
}

// cutData cuts button data to maxTapData bytes, at the start of a
// character. Telegram allows no more, so only a broken update has more.
func cutData(s string) string {
	if len(s) <= maxTapData {
		return s
	}
	n := maxTapData
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// ended updates the message m after a tap when no request waits on it
// (approval.ErrUnknownRequest, or a late tap on a changed message):
//
//   - The approver sent m, and End has not updated it yet: nothing. End
//     will. This is the second tap of a double tap.
//   - The approver sent m, and End updated it: m gets that text again. A
//     tap that left the phone before the update must not change the
//     result it shows, and if End's update failed, this tries again.
//   - The approver does not know m, such as a message from before a
//     restart: only its buttons are removed. Its text stays, because it
//     may show a result, and the tap may be one that Telegram sent again
//     after the restart.
func (a *Approver) ended(ctx context.Context, m *message) {
	chatID, msgID := m.Chat.ID, m.MessageID
	a.editMu.Lock()
	defer a.editMu.Unlock()
	sent, known := a.lookup(messageID(chatID, msgID))
	switch {
	case known && sent.final == "":
		return
	case known:
		if err := a.edit(ctx, chatID, msgID, sent.final); err != nil {
			a.log.LogAttrs(ctx, slog.LevelWarn, "telegram: cannot update the message of a request that ended",
				slog.String("error", err.Error()))
		}
		return
	}
	err := a.api.call(ctx, "editMessageReplyMarkup", editMessageReplyMarkupParams{
		ChatID: chatID, MessageID: msgID, ReplyMarkup: emptyKeyboard(),
	}, nil)
	if err != nil && !errors.Is(err, errNotModified) {
		a.log.LogAttrs(ctx, slog.LevelWarn, "telegram: cannot remove the buttons of a message", slog.String("error", err.Error()))
	}
}
