package telegram

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"

	"github.com/code6x/nodkey/internal/approval"
)

// GrantsPerMinute is the most answers to /grants that the approver sends
// in one minute. More commands in that minute get no answer.
const GrantsPerMinute = 3

// dateLayout is how the list shows the end date and the last use.
const dateLayout = "2006-01-02 15:04"

// SetGrantSource sets the function that lists the standing grants, for
// /grants and the weekly summary. The core calls it before Run.
func (a *Approver) SetGrantSource(f func() []approval.GrantInfo) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.source = f
}

// isGrantsCommand reports whether s is the command /grants, also as
// /grants@botname, with nothing after it.
func isGrantsCommand(s string) bool {
	s = strings.TrimSpace(s)
	return s == "/grants" || strings.HasPrefix(s, "/grants@") && !strings.ContainsAny(s, " \t\n")
}

// command handles a message to the bot. Only /grants from the approver in
// the private chat with the approver gets an answer; every other message
// is ignored, and so is a command over the limit. Nothing is said to
// others.
func (a *Approver) command(ctx context.Context, m *message) {
	if m.From.ID != a.userID || m.Chat.Type != "private" || m.Chat.ID != a.userID ||
		!isGrantsCommand(m.Text) {
		return
	}
	a.mu.Lock()
	src := a.source
	a.mu.Unlock()
	if src == nil || !a.take(&a.listed, GrantsPerMinute) {
		return
	}
	t, err := grantsText(src(), false)
	if err != nil {
		a.log.LogAttrs(ctx, slog.LevelWarn, "telegram: cannot show the standing grants", slog.Any("error", err))
		return
	}
	tctx, cancel := context.WithTimeout(ctx, tapTimeout)
	defer cancel()
	err = a.api.call(tctx, "sendMessage", sendMessageParams{
		ChatID:             a.userID,
		Text:               t.html.String(),
		ParseMode:          "HTML",
		LinkPreviewOptions: noPreview,
	}, nil)
	if err != nil {
		a.log.LogAttrs(ctx, slog.LevelWarn, "telegram: cannot send the standing grants", slog.Any("error", err))
	}
}

// Summary sends the weekly summary of the standing grants to the notice
// chat. A week has one, so it does not count toward the notices per
// minute.
func (a *Approver) Summary(ctx context.Context, grants []approval.GrantInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	t, err := grantsText(grants, true)
	if err != nil {
		return err
	}
	return a.api.call(ctx, "sendMessage", sendMessageParams{
		ChatID:              a.noticeChat,
		Text:                t.html.String(),
		ParseMode:           "HTML",
		LinkPreviewOptions:  noPreview,
		DisableNotification: true,
	}, nil)
}

// grantsText returns the list of the standing grants: the client, the
// secrets, the windows, the last use and the end date of each. It has no
// token and no hash. weekly adds the name of the weekly summary to the
// title. A list that is too long is cut, with the count of the grants
// left out.
func grantsText(list []approval.GrantInfo, weekly bool) (*text, error) {
	title := "Standing grants"
	if weekly {
		title = "Weekly summary · standing grants"
	}
	t := &text{}
	if len(list) == 0 {
		t.write("📋 " + title + "\nNo standing grants.")
		return t, nil
	}
	for _, g := range list {
		if !namePattern.MatchString(g.Client) || !allNames(g.Secrets) || len(g.Secrets) == 0 ||
			g.End.IsZero() {
			return nil, errors.New("telegram: a standing grant in the list is not valid")
		}
	}
	t.write("📋 " + title + " · " + strconv.Itoa(len(list)))
	for i, g := range list {
		var e text
		e.write("\n\n✅ machine: " + g.Client)
		e.write("\nsecrets: " + strings.Join(g.Secrets, ", "))
		e.write("\nwindows: " + strings.Join(g.Windows, "; "))
		last := "never"
		if !g.LastUse.IsZero() {
			last = g.LastUse.Format(dateLayout)
		}
		e.write("\nlast use: " + last)
		e.write("\nends: " + g.End.Format(dateLayout))
		if t.units()+e.units() > maxAlertUnits {
			t.write("\n\n… and " + strconv.Itoa(len(list)-i) + " more")
			break
		}
		t.html.WriteString(e.html.String())
		t.plain.WriteString(e.plain.String())
	}
	return t, nil
}
