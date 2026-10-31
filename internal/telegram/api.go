package telegram

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// This file is the small Bot API client (https://core.telegram.org/bots/api).
//
// The bot token is part of the URL of every call, and Go's HTTP errors
// (*url.Error) hold the URL. So no error of this file holds Go's error
// text: an error names the Bot API method and a fixed reason, and at most
// a number, such as Telegram's error code (THREAT-MODEL.md T19). Telegram's
// own description of an error is never shown either, because it can quote
// the message text.

// defaultBaseURL is the address of the Bot API. Only tests change it.
const defaultBaseURL = "https://api.telegram.org"

const (
	// pollTimeout is how long one getUpdates call waits for an update
	// (long polling, DESIGN.md section 7).
	pollTimeout = 50 * time.Second
	// pollMargin is how much longer than pollTimeout the HTTP call of
	// getUpdates may take.
	pollMargin = 15 * time.Second
	// callTimeout bounds one try of any other method.
	callTimeout = 15 * time.Second
	// pollLimit is the most updates in one getUpdates answer. A small
	// number keeps each answer small.
	pollLimit = 10
	// maxResponseSize is the largest answer the client reads. pollLimit
	// updates are far smaller.
	maxResponseSize = 4 << 20
	// maxTries is the most tries of one call of a method other than
	// getUpdates.
	maxTries = 5
	// firstBackoff and maxBackoff bound the wait before the next try after
	// a server error or a network error.
	firstBackoff = 500 * time.Millisecond
	maxBackoff   = 8 * time.Second
	// maxRetryAfter caps the wait that Telegram asks for with code 429.
	maxRetryAfter = 10 * time.Minute
)

// tokenPattern is the form of a bot token: the bot's user ID, ":", and a
// secret part. The token goes into the path of every URL, so it must hold
// no "/", "?", "#", "%" or space.
var tokenPattern = regexp.MustCompile(`^[0-9]{1,20}:[A-Za-z0-9_-]{30,64}$`)

// redacted is what a botToken shows instead of the token.
const redacted = "[bot token]"

// botToken holds the bot token. It hides the token in String, Format and
// LogValue, so a log line or an error that prints it by mistake shows
// "[bot token]".
type botToken struct{ value string }

func (botToken) String() string                   { return redacted }
func (botToken) GoString() string                 { return redacted }
func (botToken) Format(f fmt.State, _ rune)       { _, _ = io.WriteString(f, redacted) }
func (botToken) LogValue() slog.Value             { return slog.StringValue(redacted) }
func (botToken) MarshalText() ([]byte, error)     { return []byte(redacted), nil }
func (t botToken) url(base, method string) string { return base + "/bot" + t.value + "/" + method }

// parseToken reads the bot token from the content of the token file. Space
// around it, such as a newline at the end, is removed. The error never
// shows the content.
func parseToken(data []byte) (botToken, error) {
	s := strings.TrimSpace(string(data))
	if !tokenPattern.MatchString(s) {
		return botToken{}, errors.New("telegram: the token file does not hold a bot token: " +
			"the bot's ID in digits, \":\", and 30 to 64 letters, digits, \"_\" or \"-\"")
	}
	return botToken{value: s}, nil
}

// apiError is an error of one Bot API call. Its text names the method and
// a fixed reason, never Go's error text, the URL, the token or Telegram's
// description.
type apiError struct {
	method     string
	reason     string        // a fixed text
	code       int           // Telegram's error code or the HTTP status; 0 if no answer came
	retryAfter time.Duration // for code 429: how long Telegram asks to wait
	temporary  bool          // another try may work, and is safe
	err        error         // a sentinel of this package or a context error; never an error of net/http
}

func (e *apiError) Error() string {
	s := "telegram: " + e.method + ": " + e.reason
	if e.code != 0 {
		s += " (" + strconv.Itoa(e.code) + ")"
	}
	return s
}

func (e *apiError) Unwrap() error { return e.err }

// errNotModified: editMessageText found the message as it should be.
var errNotModified = errors.New("telegram: the message is not modified")

// client calls the Bot API. It is safe for use by many goroutines.
type client struct {
	http  *http.Client
	base  string
	token botToken
	// prefix is HTML that goes before the text of every message that
	// the client sends or edits; "" for none.
	prefix string

	// The times and the sleep are fields, so tests can make them short.
	timeout     time.Duration // one try of a method other than getUpdates
	pollTimeout time.Duration // the HTTP call of getUpdates
	sleep       func(ctx context.Context, d time.Duration) error
}

// Format hides the client, so that no fmt verb prints the token: fmt does
// not call the methods of unexported fields such as token.
func (*client) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "telegram.client") }

func newClient(token botToken, base string) *client {
	return &client{
		http:        newHTTPClient(),
		base:        base,
		token:       token,
		timeout:     callTimeout,
		pollTimeout: pollTimeout + pollMargin,
		sleep:       sleep,
	}
}

// newHTTPClient returns the HTTP client for the Bot API.
//
//   - Every call has a time limit from its context; the transport adds
//     limits for each step of a connection.
//   - It follows no redirect, so no other server gets the URL.
//   - It speaks only HTTP/1.1. Go's HTTP/2 debug output (GODEBUG
//     http2debug) would print the path of each request, which holds the
//     token.
//   - It uses the proxy from the environment, as Go reads it: HTTPS_PROXY
//     or https_proxy, except for the hosts in NO_PROXY or no_proxy. The
//     proxy sees only the host name: the URL with the token is inside
//     TLS. A proxy that inspects TLS, with its own CA in the system's
//     store, sees the token (DESIGN.md section 7).
//   - Closing a connection resets it at once (resetOnClose).
func newHTTPClient() *http.Client {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		Proxy:                  http.ProxyFromEnvironment,
		DialContext:            resetOnClose(dialer.DialContext),
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  pollTimeout + pollMargin,
		MaxResponseHeaderBytes: 64 << 10,
		IdleConnTimeout:        90 * time.Second,
		MaxIdleConns:           4,
		Protocols:              protocols,
	}
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// resetOnClose wraps dial so that closing one of its TCP connections
// resets the connection at once (SO_LINGER 0): the kernel drops the bytes
// that it has not sent yet, and sends no more. When the broker stops, Run
// cancels the getUpdates call that waits, and net/http closes its
// connection. Without the reset, the kernel would still try to send a
// getUpdates request that it had not sent yet, also after the broker
// ended. That late request could reach Telegram after a new broker started
// to poll, and Telegram would end the new poll with a conflict: a false
// alert that the token may be stolen (DESIGN.md section 7). Setting the
// option is best effort: if it fails, the connection still works.
func resetOnClose(dial func(ctx context.Context, network, addr string) (net.Conn, error),
) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetLinger(0) // best effort, see above
		}
		return c, nil
	}
}

// proxyFor returns the proxy that the client uses for base, as Go reads
// it from the environment (HTTPS_PROXY or https_proxy, and NO_PROXY or
// no_proxy), or nil for none. ok is false when the setting is not valid;
// then every call fails.
func proxyFor(base string) (proxy *url.URL, ok bool) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, base+"/", nil)
	if err != nil {
		return nil, true // calls fail anyway; New does not need to say it
	}
	proxy, err = http.ProxyFromEnvironment(req)
	if err != nil {
		return nil, false
	}
	return proxy, true
}

// sleep waits for d, or until ctx ends.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// call calls method with params and decodes its result into result (nil:
// the result is not needed). It tries again after code 429, a server error
// or a network error: at most maxTries times, and only while ctx leaves
// time for the wait. The wait grows from firstBackoff to maxBackoff, and
// is never shorter than Telegram asks for with code 429 (retryAfter: 1
// second to 10 minutes). A network error may come after Telegram did the
// call, so a try again can send a message twice. That is safe: the core
// takes an answer only on the message that Ask returned.
func (c *client) call(ctx context.Context, method string, params, result any) error {
	backoff := firstBackoff
	for try := 1; ; try++ {
		e := c.callOnce(ctx, method, params, result, c.timeout)
		if e == nil {
			return nil
		}
		if !e.temporary || try >= maxTries {
			return e
		}
		wait := max(e.retryAfter, backoff)
		backoff = min(2*backoff, maxBackoff)
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= wait {
			return e // no time to wait and try again
		}
		if c.sleep(ctx, wait) != nil {
			return e
		}
	}
}

// withPrefix returns params with c.prefix before the text of a message.
func (c *client) withPrefix(params any) any {
	if c.prefix == "" {
		return params
	}
	switch v := params.(type) {
	case sendMessageParams:
		v.Text = c.prefix + v.Text
		return v
	case editMessageTextParams:
		v.Text = c.prefix + v.Text
		return v
	}
	return params
}

// callOnce makes one call of method. timeout bounds the whole call.
func (c *client) callOnce(ctx context.Context, method string, params, result any, timeout time.Duration) *apiError {
	params = c.withPrefix(params)
	if err := ctx.Err(); err != nil {
		return &apiError{method: method, reason: "stopped before the call", err: err}
	}
	body, err := json.Marshal(params)
	if err != nil {
		return &apiError{method: method, reason: "cannot encode the request"}
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, c.token.url(c.base, method), bytes.NewReader(body))
	if err != nil {
		// The error holds the URL, so it is left out.
		return &apiError{method: method, reason: "cannot make the request"}
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return &apiError{method: method, reason: "stopped during the call", err: ctx.Err()}
		}
		return &apiError{method: method, reason: netReason(err), temporary: true}
	}
	defer func() { _ = resp.Body.Close() }() // a close error adds nothing
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		if ctx.Err() != nil {
			return &apiError{method: method, reason: "stopped during the call", err: ctx.Err()}
		}
		return &apiError{method: method, reason: "cannot read the answer", temporary: true}
	}
	if len(data) > maxResponseSize {
		return &apiError{method: method, reason: "the answer is too large"}
	}
	return decodeAnswer(method, resp.StatusCode, data, result)
}

// netReason returns a fixed reason for an error of http.Client.Do. It
// looks only at the types in err, never at its text: the text holds the
// URL, and the URL holds the token.
func netReason(err error) string {
	var dnsErr *net.DNSError
	var certErr *tls.CertificateVerificationError
	var netErr net.Error
	var opErr *net.OpError
	switch {
	case errors.As(err, &dnsErr):
		return "cannot find the address of the server"
	case errors.As(err, &certErr):
		return "the TLS certificate of the server is not valid"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "the call timed out"
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return "cannot connect to the server"
	}
	return "the connection failed"
}

// apiResponse is the answer of every Bot API method.
type apiResponse struct {
	OK          bool                `json:"ok"`
	Result      json.RawMessage     `json:"result"`
	ErrorCode   int                 `json:"error_code"`
	Description string              `json:"description"`
	Parameters  *responseParameters `json:"parameters"`
}

type responseParameters struct {
	RetryAfter      int64 `json:"retry_after"`
	MigrateToChatID int64 `json:"migrate_to_chat_id"`
}

// decodeAnswer reads the answer of method with the HTTP status.
func decodeAnswer(method string, status int, data []byte, result any) *apiError {
	var r apiResponse
	if err := json.Unmarshal(data, &r); err != nil {
		switch {
		case status >= http.StatusInternalServerError:
			return &apiError{method: method, reason: "the server has an error", code: status, temporary: true}
		case status == http.StatusTooManyRequests:
			// Such as the page of a proxy: wait as for a 429 of Telegram
			// without retry_after.
			return &apiError{method: method, reason: "the server asks to wait", code: status,
				retryAfter: time.Second, temporary: true}
		}
		// With status 200 the call may have worked, so it is not tried
		// again.
		return &apiError{method: method, reason: "the answer is not valid JSON", code: status}
	}
	if !r.OK {
		code := r.ErrorCode
		if code == 0 {
			code = status
		}
		return refused(method, code, r)
	}
	if status != http.StatusOK {
		return &apiError{method: method, reason: "the answer says ok with a wrong HTTP status", code: status}
	}
	if result != nil {
		if len(r.Result) == 0 {
			return &apiError{method: method, reason: "the answer has no result"}
		}
		if err := json.Unmarshal(r.Result, result); err != nil {
			return &apiError{method: method, reason: "the result has a wrong form"}
		}
	}
	return nil
}

// refused returns the error for an answer with ok false and the error
// code. Telegram's description picks a reason in a few known cases, but
// it never goes into the error, because it can quote the message text.
func refused(method string, code int, r apiResponse) *apiError {
	e := &apiError{method: method, code: code}
	desc := strings.ToLower(r.Description)
	switch {
	case code == http.StatusTooManyRequests:
		e.reason = "Telegram asks to wait"
		e.retryAfter = time.Second
		if r.Parameters != nil {
			e.retryAfter = retryAfter(r.Parameters.RetryAfter)
		}
		e.temporary = true
	case code >= http.StatusInternalServerError:
		e.reason = "Telegram has a server error"
		e.temporary = true
	case code == http.StatusConflict:
		e.reason = "another program polls with the bot token, or a webhook is set"
		e.err = ErrPollConflict
	case code == http.StatusUnauthorized:
		e.reason = "Telegram does not accept the bot token"
		e.err = ErrTokenRefused
	case code == http.StatusForbidden:
		e.reason = "the bot may not send to this chat: the person did not start the bot, blocked it, or removed it"
	case code == http.StatusNotFound:
		e.reason = "Telegram does not know the method or the bot token"
		e.err = ErrTokenRefused
	case strings.Contains(desc, "message is not modified"):
		e.reason = "the message is not modified"
		e.err = errNotModified
	case r.Parameters != nil && r.Parameters.MigrateToChatID != 0:
		e.reason = "the group has a new chat ID; put it in the config"
	case strings.Contains(desc, "chat not found"):
		e.reason = "Telegram does not know the chat"
	case strings.Contains(desc, "message to edit not found"):
		e.reason = "the message is gone"
	case strings.Contains(desc, "query is too old"), strings.Contains(desc, "query id is invalid"):
		e.reason = "the button press is too old to answer"
	default:
		e.reason = "Telegram refused the request"
	}
	return e
}

// retryAfter returns the wait of a 429 answer: s seconds, at least 1
// second and at most maxRetryAfter.
func retryAfter(s int64) time.Duration {
	switch {
	case s < 1:
		return time.Second
	case s > int64(maxRetryAfter/time.Second):
		return maxRetryAfter
	}
	return time.Duration(s) * time.Second
}

// The parameters of the methods this package calls.
type (
	getUpdatesParams struct {
		Offset         int64    `json:"offset"`
		Limit          int      `json:"limit"`
		Timeout        int      `json:"timeout"`
		AllowedUpdates []string `json:"allowed_updates"`
	}

	sendMessageParams struct {
		ChatID              int64              `json:"chat_id"`
		Text                string             `json:"text"`
		ParseMode           string             `json:"parse_mode"`
		LinkPreviewOptions  linkPreviewOptions `json:"link_preview_options"`
		DisableNotification bool               `json:"disable_notification,omitempty"`
		ReplyMarkup         *inlineKeyboard    `json:"reply_markup,omitempty"`
	}

	editMessageTextParams struct {
		ChatID             int64              `json:"chat_id"`
		MessageID          int64              `json:"message_id"`
		Text               string             `json:"text"`
		ParseMode          string             `json:"parse_mode"`
		LinkPreviewOptions linkPreviewOptions `json:"link_preview_options"`
		// ReplyMarkup is always sent, as an empty keyboard: that removes
		// the buttons. An edit without it removes them too, as the manual
		// test of issue #17 showed on 2026-10-15 (DESIGN.md section 7).
		// The broker still sends the empty keyboard, so that it does not
		// depend on this behaviour of Telegram.
		ReplyMarkup inlineKeyboard `json:"reply_markup"`
	}

	// editMessageReplyMarkupParams change only the buttons of a message.
	editMessageReplyMarkupParams struct {
		ChatID      int64          `json:"chat_id"`
		MessageID   int64          `json:"message_id"`
		ReplyMarkup inlineKeyboard `json:"reply_markup"`
	}

	answerCallbackQueryParams struct {
		CallbackQueryID string `json:"callback_query_id"`
		Text            string `json:"text,omitempty"`
	}

	linkPreviewOptions struct {
		IsDisabled bool `json:"is_disabled"`
	}

	inlineKeyboard struct {
		InlineKeyboard [][]inlineButton `json:"inline_keyboard"`
	}

	inlineButton struct {
		Text         string `json:"text"`
		CallbackData string `json:"callback_data"`
	}
)

// noPreview turns link previews off, so a URL in claimed text does not
// become a preview card (DESIGN.md section 7).
var noPreview = linkPreviewOptions{IsDisabled: true}

// emptyKeyboard removes the buttons of a message. It is an empty list, not
// a missing one.
func emptyKeyboard() inlineKeyboard {
	return inlineKeyboard{InlineKeyboard: [][]inlineButton{}}
}

// The parts of updates that this package reads. Other fields are ignored.
type (
	// update is one update from getUpdates. Button presses
	// (callback_query) and messages (for /grants) are asked for.
	update struct {
		UpdateID      int64          `json:"update_id"`
		CallbackQuery *callbackQuery `json:"callback_query"`
		// Message is a message to the bot. Only the command /grants is
		// read from it.
		Message *message `json:"message"`
		// malformed: the update does not have the expected form. Only its
		// ID is kept.
		malformed bool
	}

	// callbackQuery is a press of a button with callback data.
	callbackQuery struct {
		ID   string `json:"id"`
		From user   `json:"from"`
		// Message is the message with the button. It is missing for a
		// button of an inline message, which has InlineMessageID instead.
		Message         *message `json:"message"`
		InlineMessageID string   `json:"inline_message_id"`
		Data            string   `json:"data"`
		GameShortName   string   `json:"game_short_name"`
	}

	user struct {
		ID int64 `json:"id"`
		// FirstName and Username are read only by Pair, to show who sent
		// /start.
		FirstName string `json:"first_name"`
		Username  string `json:"username"`
	}

	message struct {
		MessageID int64 `json:"message_id"`
		Chat      chat  `json:"chat"`
		// From and Text are read only for the command /grants.
		From user   `json:"from"`
		Text string `json:"text"`
		// EditDate is set when the message was edited. The broker edits a
		// message only after its request ended.
		EditDate int64 `json:"edit_date"`
		// ReplyMarkup holds the buttons of the message as Telegram has
		// them.
		ReplyMarkup *inlineKeyboard `json:"reply_markup"`
	}

	chat struct {
		ID   int64  `json:"id"`
		Type string `json:"type"`
	}
)

// getUpdates gets the next updates after offset, with long polling. It
// tries once; Run decides what to do after an error. An update that does
// not have the expected form is returned with only its ID, so that the
// offset still moves past it.
func (c *client) getUpdates(ctx context.Context, offset int64) ([]update, *apiError) {
	params := getUpdatesParams{
		Offset:         offset,
		Limit:          pollLimit,
		Timeout:        int(pollTimeout / time.Second),
		AllowedUpdates: []string{"callback_query", "message"},
	}
	var raws []json.RawMessage
	if e := c.callOnce(ctx, "getUpdates", params, &raws, c.pollTimeout); e != nil {
		return nil, e
	}
	updates := make([]update, 0, len(raws))
	for _, raw := range raws {
		u, ok := decodeUpdate(raw)
		if !ok {
			return nil, &apiError{method: "getUpdates", reason: "an update has no ID", temporary: true}
		}
		updates = append(updates, u)
	}
	return updates, nil
}

// decodeUpdate reads one update of a getUpdates answer. ok is false when
// it has no ID. An update with an ID but another form is returned with
// only its ID, as malformed, so that the offset still moves past it.
func decodeUpdate(raw json.RawMessage) (update, bool) {
	var id struct {
		UpdateID *int64 `json:"update_id"`
	}
	if err := json.Unmarshal(raw, &id); err != nil || id.UpdateID == nil {
		return update{}, false
	}
	var u update
	if err := json.Unmarshal(raw, &u); err != nil {
		u = update{malformed: true}
	}
	u.UpdateID = *id.UpdateID
	return u, true
}
