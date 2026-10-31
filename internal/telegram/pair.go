package telegram

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// pairCodePattern is the form of a pairing code: what Telegram allows in
// the start parameter of a link.
var pairCodePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

// Pairing finds the Telegram user ID of the approver from a /start
// message, so that no one has to look it up by hand. nodkey try uses it.
type Pairing struct {
	api *client
	// Bot is the user name of the bot, without "@".
	Bot string
}

// Paired is the person who sent /start with the code.
type Paired struct {
	UserID int64
	// Name is the first name and the user name, as Telegram has them,
	// with every character that is not printable replaced.
	Name string
}

// NewPairing checks the token with getMe and returns a Pairing for its
// bot. Errors never show the token.
func NewPairing(ctx context.Context, token []byte) (*Pairing, error) {
	return newPairing(ctx, token, defaultBaseURL)
}

func newPairing(ctx context.Context, token []byte, base string) (*Pairing, error) {
	t, err := parseToken(bytes.Clone(token))
	if err != nil {
		return nil, err
	}
	api := newClient(t, base)
	var me struct {
		Username string `json:"username"`
	}
	if err := api.call(ctx, "getMe", struct{}{}, &me); err != nil {
		return nil, err
	}
	if !botNamePattern.MatchString(me.Username) {
		return nil, errors.New("telegram: getMe: the bot has no valid user name")
	}
	return &Pairing{api: api, Bot: me.Username}, nil
}

// botNamePattern is the form of a bot's user name.
var botNamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{5,32}$`)

// Link is the link that opens the bot and sends /start with code.
func (p *Pairing) Link(code string) string {
	return "https://t.me/" + p.Bot + "?start=" + code
}

// Wait waits for the message "/start code" in a private chat with the
// bot, and returns who sent it. Every other message is skipped. It ends
// with ErrPollConflict when another program polls the same bot.
func (p *Pairing) Wait(ctx context.Context, code string) (Paired, error) {
	if !pairCodePattern.MatchString(code) {
		return Paired{}, errors.New("telegram: the pairing code is not valid")
	}
	want := "/start " + code
	var offset int64
	for {
		if err := ctx.Err(); err != nil {
			return Paired{}, err
		}
		updates, e := p.api.getUpdates(ctx, offset)
		if e != nil {
			switch {
			case ctx.Err() != nil:
				return Paired{}, ctx.Err()
			case !e.temporary:
				return Paired{}, e
			}
			if err := p.api.sleep(ctx, pollFirstBackoff); err != nil {
				return Paired{}, err
			}
			continue
		}
		for _, u := range updates {
			offset = max(offset, u.UpdateID+1)
			m := u.Message
			if u.malformed || m == nil || m.Chat.Type != "private" || m.From.ID <= 0 ||
				m.Chat.ID != m.From.ID || m.Text != want {
				continue
			}
			name := cleanName(m.From.FirstName)
			if m.From.Username != "" {
				name += " (@" + cleanName(m.From.Username) + ")"
			}
			return Paired{UserID: m.From.ID, Name: name}, nil
		}
	}
}

// cleanName caps s and replaces each character that is not printable.
func cleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return '?'
	}, s)
	if r := []rune(s); len(r) > 64 {
		s = string(r[:64]) + "…"
	}
	return s
}

// Format hides the Pairing, so that no fmt verb prints the token.
func (*Pairing) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("telegram.Pairing")) }
