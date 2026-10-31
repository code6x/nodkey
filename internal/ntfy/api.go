package ntfy

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

// This file is the small client for the ntfy server
// (https://docs.ntfy.sh/publish/ and https://docs.ntfy.sh/subscribe/api/).
//
// No error of this file holds Go's error text or the server's text: an
// error names the call and a fixed reason, and at most the HTTP status.
// The tokens are in a header, never in a URL, and never in an error.

const (
	// callTimeout bounds one try of a publish.
	callTimeout = 15 * time.Second
	// maxTries is the most tries of one publish.
	maxTries = 3
	// firstBackoff and maxBackoff bound the wait before the next try.
	firstBackoff = 500 * time.Millisecond
	maxBackoff   = 4 * time.Second
	// maxResponseSize is the largest answer to a publish that the client
	// reads. The answer is one message, at most a few kilobytes.
	maxResponseSize = 64 << 10
)

// topicPattern is the form of a topic name, as ntfy allows it: 1 to 64
// letters, digits, "_" or "-".
var topicPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// idPattern is the form of an ntfy message ID: the server makes 12
// letters and digits. A few more are allowed.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9]{1,32}$`)

// tokenPattern is the form of an access token: printable ASCII without
// space, so it can go into a header as it is. ntfy's own tokens are
// "tk_" and 29 letters and digits.
var tokenPattern = regexp.MustCompile(`^[\x21-\x7e]{8,256}$`)

// redacted is what a Token shows instead of its value.
const redacted = "[ntfy token]"

// Token is an access token of the ntfy server. It hides its value in
// String, Format and LogValue, so a log line or an error that prints it by
// mistake shows "[ntfy token]". Make it with NewToken.
type Token struct{ value string }

// NewToken returns the token s, after space around it is removed. The
// error never shows s.
func NewToken(s string) (Token, error) {
	s = strings.TrimSpace(s)
	if !tokenPattern.MatchString(s) {
		return Token{}, errors.New("ntfy: the access token is not valid: 8 to 256 printable characters without space")
	}
	return Token{value: s}, nil
}

func (Token) String() string               { return redacted }
func (Token) GoString() string             { return redacted }
func (Token) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, redacted) }
func (Token) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (Token) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// set reports whether the token has a value.
func (t Token) set() bool { return t.value != "" }

// Config says which ntfy server and topics the approver uses.
type Config struct {
	// Server is the base URL of the ntfy server, such as
	// "https://ntfy.example.com". It must use https.
	Server string
	// RequestTopic gets the messages: the requests with their buttons and
	// the notices. The person's phone subscribes to it.
	RequestTopic string
	// AnswerTopic gets the answers that the buttons send. Only the broker
	// may read it.
	AnswerTopic string
	// PublishToken may publish to RequestTopic. ReadToken may read
	// AnswerTopic. They may be the same token.
	PublishToken, ReadToken Token
}

// check checks cfg and returns the server URL without a "/" at the end.
func (cfg Config) check() (string, error) {
	u, err := url.Parse(cfg.Server)
	switch {
	case err != nil:
		return "", errors.New("ntfy: the server URL is not valid")
	case u.Scheme != "https":
		return "", errors.New("ntfy: the server URL must start with https://")
	case u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "":
		return "", errors.New("ntfy: the server URL must be only https://, a host, and an optional path")
	case !topicPattern.MatchString(cfg.RequestTopic) || !topicPattern.MatchString(cfg.AnswerTopic):
		return "", errors.New("ntfy: a topic name must be 1 to 64 letters, digits, \"_\" or \"-\"")
	case cfg.RequestTopic == cfg.AnswerTopic:
		return "", errors.New("ntfy: the request topic and the answer topic must not be the same")
	case !cfg.PublishToken.set() || !cfg.ReadToken.set():
		return "", errors.New("ntfy: the approver needs a token to publish and a token to read")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

// callError is an error of one call to the server. Its text names the
// call and a fixed reason, never Go's error text or the server's text.
type callError struct {
	call      string
	reason    string // a fixed text
	status    int    // the HTTP status; 0 if no answer came
	temporary bool   // another try may work
	err       error  // a context error, or nil
}

func (e *callError) Error() string {
	s := "ntfy: " + e.call + ": " + e.reason
	if e.status != 0 {
		s += " (" + strconv.Itoa(e.status) + ")"
	}
	return s
}

func (e *callError) Unwrap() error { return e.err }

// client calls the ntfy server. It is safe for use by many goroutines.
type client struct {
	http                    *http.Client
	base                    string
	publishToken, readToken Token
	timeout                 time.Duration
	sleep                   func(ctx context.Context, d time.Duration) error
}

// Format hides the client, so that no fmt verb prints a token.
func (*client) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "ntfy.client") }

// newHTTPClient returns the HTTP client for the ntfy server: TLS 1.2 or
// newer, a limit for each step of a connection, and no redirect, so no
// other server gets a token.
func newHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		Proxy:                  http.ProxyFromEnvironment,
		DialContext:            dialer.DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  30 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		IdleConnTimeout:        90 * time.Second,
		MaxIdleConns:           4,
	}
	return &http.Client{Transport: tr, CheckRedirect: noRedirect}
}

// noRedirect makes the client return a redirect as the answer.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

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

// publishMessage is a message in the JSON form of a publish
// (https://docs.ntfy.sh/publish/#publish-as-json).
type publishMessage struct {
	Topic      string   `json:"topic"`
	Title      string   `json:"title,omitempty"`
	Message    string   `json:"message"`
	Priority   int      `json:"priority,omitempty"`
	Actions    []action `json:"actions,omitempty"`
	SequenceID string   `json:"sequence_id,omitempty"`
}

// action is an "http" action button. The phone sends Body to URL with
// Method when the button is pressed, and then clears the notification.
type action struct {
	Action string `json:"action"`
	Label  string `json:"label"`
	URL    string `json:"url"`
	Method string `json:"method"`
	Body   string `json:"body"`
	Clear  bool   `json:"clear"`
}

// published is the part of the server's answer to a publish that the
// client reads.
type published struct {
	ID    string `json:"id"`
	Event string `json:"event"`
	Topic string `json:"topic"`
}

// maxPublishBody is the most bytes that the approver sends as one publish
// body. ntfy refuses a JSON publish body over 8,192 bytes by default; the
// rest is a margin.
const maxPublishBody = 8192 - 1024

// encodeMessage returns the JSON body of the publish of m. It does not
// escape <, > and &: json.Marshal makes each of them 6 bytes, and the
// body would not fit.
func encodeMessage(m publishMessage) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// fitsPublish reports whether the publish of m is within maxPublishBody.
func fitsPublish(m publishMessage) bool {
	b, err := encodeMessage(m)
	return err == nil && len(b) <= maxPublishBody
}

// publish sends m, and returns the ID of the new message. It tries again
// after a server error, code 429 or a network error, at most maxTries
// times, and only while ctx leaves time for the wait; tries > 1 only when
// retry is set. A network error may come after the server took the
// message, so a try again can send it twice. That is safe: an answer
// counts only with the value of its request, and the core takes it only
// on the message that Ask returned.
func (c *client) publish(ctx context.Context, m publishMessage, retry bool) (string, error) {
	body, err := encodeMessage(m)
	if err != nil {
		return "", &callError{call: "publish", reason: "cannot encode the message"}
	}
	backoff := firstBackoff
	for try := 1; ; try++ {
		id, e := c.publishOnce(ctx, body, m.Topic)
		if e == nil {
			return id, nil
		}
		if !retry || !e.temporary || try >= maxTries {
			return "", e
		}
		wait := backoff
		backoff = min(2*backoff, maxBackoff)
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= wait {
			return "", e
		}
		if c.sleep(ctx, wait) != nil {
			return "", e
		}
	}
}

// publishOnce makes one try of a publish of body to topic.
func (c *client) publishOnce(ctx context.Context, body []byte, topic string) (string, *callError) {
	const call = "publish"
	if err := ctx.Err(); err != nil {
		return "", &callError{call: call, reason: "stopped before the call", err: err}
	}
	cctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, c.base+"/", bytes.NewReader(body))
	if err != nil {
		return "", &callError{call: call, reason: "cannot make the request"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.publishToken.value)
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return "", &callError{call: call, reason: "stopped during the call", err: ctx.Err()}
		}
		return "", &callError{call: call, reason: netReason(err), temporary: true}
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	switch {
	case err != nil && ctx.Err() != nil:
		return "", &callError{call: call, reason: "stopped during the call", err: ctx.Err()}
	case err != nil:
		return "", &callError{call: call, reason: "cannot read the answer", temporary: true}
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return "", &callError{call: call, reason: "the server refused the message for now", status: resp.StatusCode, temporary: true}
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return "", &callError{call: call, reason: "the server does not accept the token", status: resp.StatusCode}
	case resp.StatusCode != http.StatusOK:
		return "", &callError{call: call, reason: "the server refused the message", status: resp.StatusCode}
	case len(data) > maxResponseSize:
		return "", &callError{call: call, reason: "the answer is too large"}
	}
	var p published
	if json.Unmarshal(data, &p) != nil || !idPattern.MatchString(p.ID) || p.Event != "message" || p.Topic != topic {
		return "", &callError{call: call, reason: "the answer does not have the expected form"}
	}
	return p.ID, nil
}

// netReason returns a fixed reason for an error of http.Client.Do. It
// looks only at the types in err, never at its text.
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
