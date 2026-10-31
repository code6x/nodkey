package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/code6x/nodkey/internal/telegram"
)

// tryPrefix goes before every Telegram message of the trial.
const tryPrefix = "TRY MODE · "

// tryTelegram is what nodkey try --telegram set up: the bot token, only
// in memory, and the approver's user ID from the /start message.
type tryTelegram struct {
	token  []byte
	userID int64
}

// Format hides the token.
func (tryTelegram) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "tryTelegram") }

// tryConflictText says what to do when Telegram reports that another
// program polls the bot.
const tryConflictText = "Telegram says another program polls this bot, maybe a nodkey broker. " +
	"Use a new bot for the trial, never the broker's bot: with two programs on one bot, " +
	"the real broker stops (exit 76)"

// tryTelegramErr is the text of an error of the Telegram part of the trial.
func tryTelegramErr(err error) string {
	switch {
	case errors.Is(err, telegram.ErrPollConflict):
		return tryConflictText
	case errors.Is(err, telegram.ErrTokenRefused):
		return "Telegram does not accept the bot token"
	}
	return err.Error()
}

// setupTryTelegram asks for the token of a new bot, prints the link that
// sends /start with a random code, and takes the approver's user ID only
// from that message, after the person confirms the name.
func setupTryTelegram(ctx context.Context, in *bufio.Reader, stdin io.Reader, out io.Writer) (*tryTelegram, error) {
	_, _ = io.WriteString(out, `nodkey try: TRY MODE: approval in Telegram.
  1. In Telegram, open @BotFather, send /newbot, and make a NEW bot for this trial.
     Never use the bot of a real broker: the real broker would stop.
  2. Paste the token of the new bot here and press Enter. It is not shown,
     and it is kept only in memory.
Token: `)
	token, err := readTryToken(ctx, in, stdin)
	_, _ = io.WriteString(out, "\n")
	if err != nil {
		return nil, err
	}
	p, err := telegram.NewPairing(ctx, token)
	if err != nil {
		clear(token)
		return nil, errors.New(tryTelegramErr(err))
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	code := base64.RawURLEncoding.EncodeToString(b)
	_, _ = fmt.Fprintf(out, "nodkey try: TRY MODE: on your phone, open this link and tap Start:\n\n  %s\n\n", p.Link(code))
	who, err := p.Wait(ctx, code)
	if err != nil {
		clear(token)
		return nil, errors.New(tryTelegramErr(err))
	}
	_, _ = fmt.Fprintf(out, "nodkey try: TRY MODE: Telegram user %s (ID %d) sent the code.\n"+
		"Only this user can answer. Is this you? Type yes and Enter: ", who.Name, who.UserID)
	answer, err := readTryLine(ctx, in)
	if err != nil || strings.TrimSpace(string(answer)) != "yes" {
		clear(token)
		return nil, errors.New("not confirmed, so the trial does not start")
	}
	return &tryTelegram{token: token, userID: who.UserID}, nil
}

// readTryToken reads the token, with the echo of the terminal off when
// stdin is a terminal.
func readTryToken(ctx context.Context, in *bufio.Reader, stdin io.Reader) ([]byte, error) {
	if f, ok := stdin.(*os.File); ok && isTerminal(f) {
		restore, err := echoOff(f)
		if err != nil {
			return nil, fmt.Errorf("cannot hide the input: %w", err)
		}
		defer restore()
	}
	line, err := readTryLine(ctx, in)
	if err != nil {
		return nil, err
	}
	token := []byte(strings.TrimSpace(string(line)))
	clear(line)
	return token, nil
}

// readTryLine reads one line of at most maxTryLine bytes, until ctx ends.
func readTryLine(ctx context.Context, in *bufio.Reader) ([]byte, error) {
	type result struct {
		line []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		line, err := in.ReadSlice('\n')
		if err == nil || (errors.Is(err, io.EOF) && len(line) > 0) {
			done <- result{line: append([]byte(nil), line...)}
			clear(line)
			return
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			err = errors.New("the line is too long")
		}
		done <- result{err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-done:
		return r.line, r.err
	}
}
