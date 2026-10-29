package telegram

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/code6x/nodkey/internal/approval"
)

// renewKeyboard returns the one Renew button of the warning before the end
// of the standing grant of the request id.
func renewKeyboard(id string) inlineKeyboard {
	return inlineKeyboard{InlineKeyboard: [][]inlineButton{{{Text: "Renew", CallbackData: dataRenew + id}}}}
}

// warningText returns the text of the warning before the end of a
// standing grant (DESIGN.md section 8). It holds names from the config,
// the windows, the grant ID and the end; no token and no claimed text.
func warningText(w approval.Warning) (*text, error) {
	bad := func(what string) error { return errors.New("telegram: the warning is not valid: " + what) }
	switch {
	case !validRequestID(w.RequestID):
		return nil, bad("the request ID")
	case !shortCodePattern.MatchString(w.ShortCode):
		return nil, bad("the short code")
	case !namePattern.MatchString(w.Client):
		return nil, bad("the client name")
	case len(w.Secrets) == 0 || !allNames(w.Secrets):
		return nil, bad("the secrets")
	case len(w.Windows) == 0 || len(w.Windows) > 7:
		return nil, bad("the windows")
	case !validRequestID(w.GrantID):
		return nil, bad("the grant ID")
	case w.Uses < 1 || w.End.IsZero():
		return nil, bad("the uses or the end")
	}
	for _, x := range w.Windows {
		if !windowPattern.MatchString(x) {
			return nil, bad("the windows")
		}
	}
	t := &text{}
	t.write("⏳ Standing grant ends soon · request " + w.ShortCode)
	t.write("\n✅ machine: " + w.Client)
	t.write("\n✅ secrets: " + strings.Join(w.Secrets, ", "))
	t.write("\n✅ windows: " + strings.Join(w.Windows, ", ") + ", " + strconv.Itoa(w.Uses) + " use(s) in each")
	t.write("\n✅ grant: " + w.GrantID)
	t.write("\n✅ ends: " + w.End.Format(dateTimeFormat))
	t.write("\nRenew makes a new grant of the same length from now. The next use of the job's token gets a token of the new grant.")
	return t, nil
}

// Warn sends the warning before the end of a standing grant to the
// approver's private chat, with a sound and one Renew button, and returns
// its message. A Renew counts only on this message, as Ask sent it.
func (a *Approver) Warn(ctx context.Context, w approval.Warning) (approval.MessageID, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	t, err := warningText(w)
	if err != nil {
		return "", err
	}
	kb := renewKeyboard(w.RequestID)
	var sent message
	err = a.api.call(ctx, "sendMessage", sendMessageParams{
		ChatID:             a.userID,
		Text:               t.html.String(),
		ParseMode:          "HTML",
		LinkPreviewOptions: noPreview,
		ReplyMarkup:        &kb,
	}, &sent)
	if err != nil {
		return "", err
	}
	if sent.MessageID <= 0 || sent.Chat.ID != a.userID {
		return "", errors.New("telegram: sendMessage: the answer names another chat, or no message")
	}
	m := messageID(sent.Chat.ID, sent.MessageID)
	a.remember(m, kb.InlineKeyboard)
	return m, nil
}
