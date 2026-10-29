// Package client is the client side of nodkey (DESIGN.md sections 5, 6
// and 10): the requests of a client to the broker, and the commands
// nodkey run and nodkey ssh-agent.
//
// A client reads its config with config.LoadClient and its TLS key with
// transport.LoadKeyFile, and talks to the broker over the pinned mutual
// TLS of transport.NewClient (Load). Post sends one request: one POST on a
// connection of its own, with a deadline, and never again. While the
// broker waits for the person, it sends 102 Processing with the short
// code; Post passes on only that code. Only a final 200 whose body passes
// api.ReadAnswer counts. Every other answer, and every error, is an *Error
// with a fixed text: it never holds an answer body, a header, a value, or
// other text that the other side of the connection chose. Each request
// has the client's version in a header, and each answer the broker's;
// when they differ, the client prints one warning (version.go).
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/transport"
)

// RequestTimeout is the deadline of a request to the broker. The broker
// waits for the person at most its timeout, which is at most
// config.MaxTimeout. The margin covers the rest: the connection, the
// request body, the audit entries, the fetch of the values from the
// stores (a fetch with bw can take more than 2 minutes when bw is slow),
// and the answer. There is no other time limit on the wait for the
// person.
const RequestTimeout = config.MaxTimeout + 5*time.Minute

// maxInformational is the most informational (1xx) answers that Post
// takes for one request. The broker sends one: 102 Processing with the
// short code. Go's HTTP client takes any number of them once the caller
// looks at them, so Post counts them itself.
const maxInformational = 4

// ConfigFile is the client config, in the home directory (DESIGN.md
// section 14).
const ConfigFile = ".config/nodkey/client.toml"

// ConfigPath returns the path of the client config:
// ~/.config/nodkey/client.toml.
func ConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return "", errors.New("the home directory is not known, so the client config ~/" + ConfigFile +
			" cannot be found")
	}
	return filepath.Join(home, ConfigFile), nil
}

// Broker sends requests to the broker of a client config. Make it with
// Load. It is safe for use by many goroutines.
type Broker struct {
	addr    string
	client  *http.Client
	timeout time.Duration // RequestTimeout; tests make it short
	// versions sends this client's version, and warns when the broker
	// runs another (warnVersions).
	versions versions
}

// Load reads the client config at path with config.LoadClient, and the
// client's TLS key with transport.LoadKeyFile. Both check who can read and
// change the key file (DESIGN.md section 14). Then it makes the HTTP
// client with transport.NewClient. It does not connect: each Post makes
// its own connection. Errors never hold a value from the files.
func Load(path string) (*Broker, error) {
	cfg, err := config.LoadClient(path)
	if err != nil {
		return nil, err // the error names the file and the key
	}
	key, err := transport.LoadKeyFile(cfg.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("config %s: tls_key: %w", path, err)
	}
	b, err := newBroker(cfg.Broker, key, cfg.BrokerPin)
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return b, nil
}

// newBroker returns a Broker for the broker at addr (host:port), whose TLS
// key has the pin pin. key is the client's own TLS key.
func newBroker(addr string, key tls.Certificate, pin config.Pin) (*Broker, error) {
	c, err := transport.NewClient(addr, key, pin)
	if err != nil {
		return nil, err
	}
	return &Broker{addr: addr, client: c, timeout: RequestTimeout}, nil
}

// Error is a request that did not get a final 200 with a valid answer.
// Its text is one line: a fixed text, the broker's address from the client
// config, the HTTP status, or an error of the operating system. It never
// holds an answer body, a header, or text that the other side of the
// connection chose.
type Error struct {
	// Status is the HTTP status of the broker's final answer, or 0 when
	// none came.
	Status int
	text   string
}

func (e *Error) Error() string { return e.text }

// Denied reports whether the broker denied the request: 403 (by the
// person, a check or a rule, or because nobody answered in time) or 429
// (by a limit). nodkey run exits with 77 then, and with 69 for every other
// Error (DESIGN.md section 15).
func (e *Error) Denied() bool {
	return e.Status == http.StatusForbidden || e.Status == http.StatusTooManyRequests
}

// statusError returns the Error of a final answer with status, which is
// not 200.
func statusError(status int) *Error {
	switch status {
	case http.StatusForbidden:
		return &Error{Status: status, text: "denied"}
	case http.StatusTooManyRequests:
		return &Error{Status: status, text: "denied by a limit of the broker"}
	}
	text := fmt.Sprintf("the broker answered %d", status)
	if s := http.StatusText(status); s != "" {
		text += " " + s
	}
	return &Error{Status: status, text: text}
}

// errInformational ends a request with too many informational answers.
var errInformational = errors.New("client: too many informational answers")

// trace follows one request: whether it got a connection, and the
// informational answers. Its methods run in goroutines of net/http.
type trace struct {
	mu        sync.Mutex
	connected bool // the TLS handshake ended, so the pin was checked
	count     int  // informational answers so far
	shown     bool // onCode got the short code
	done      bool // Post returns: onCode is not called any more
	onCode    func(string)
}

func (tr *trace) gotConn(httptrace.GotConnInfo) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.connected = true
}

// got1xx counts an informational answer, and passes the short code of the
// first 102 Processing with a valid code to onCode. It never passes on
// another header, or a code that is not a short code.
//
// net/http can still read an informational answer after Do returned, when
// the request was cancelled. So onCode runs under the lock, and not after
// finish: nothing that onCode prints can come after the caller's last
// line.
func (tr *trace) got1xx(status int, h textproto.MIMEHeader) error {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if tr.done {
		return errInformational
	}
	tr.count++
	if tr.count > maxInformational {
		return errInformational
	}
	if code, ok := api.ShortCode(status, h); ok && !tr.shown && tr.onCode != nil {
		tr.shown = true
		tr.onCode(code)
	}
	return nil
}

// finish ends the calls of onCode. It waits for a call that runs.
func (tr *trace) finish() {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.done = true
}

func (tr *trace) isConnected() bool {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return tr.connected
}

// Post sends body, a request in JSON, to path, and returns the broker's
// answer: read with api.ReadAnswer into a new T, so at most api.MaxAnswer
// bytes, decoded strictly. onCode, if not nil, gets the short code of the
// broker's 102 Processing answer once, while the request waits for the
// person.
//
// The request has a deadline (RequestTimeout) and no other time limit.
// It is one POST on a connection of its own, which closes after the
// answer: no other request goes on that connection, so there is no
// pipelining. The request is never sent again. When ctx ends, the
// connection closes, so the broker cancels the request; Post then returns
// context.Cause(ctx). An answer that comes while the connection closes can
// still be returned instead, as Go's HTTP client does: a caller that must
// deny after ctx ends checks ctx after Post.
//
// Every other failure is an *Error: a final answer other than 200, also a
// redirect; a 200 whose body api.ReadAnswer refuses; more than a few
// informational answers; no answer within the deadline; and a failed
// connection.
//
// The request has this client's version in its header, and Post compares
// the version in the header of the final answer with it, whatever its
// status, before it returns (warnVersions).
func Post[T any, P interface {
	*T
	json.Unmarshaler
}](ctx context.Context, b *Broker, path string, body []byte, onCode func(code string)) (*T, error) {
	return postWith[T, P](ctx, b, path, body, onCode, nil)
}

// postWith is Post with more request headers: extra, if not nil, may set
// them. They are secrets: Post never shows them.
func postWith[T any, P interface {
	*T
	json.Unmarshaler
}](ctx context.Context, b *Broker, path string, body []byte, onCode func(code string), extra http.Header) (*T, error) {
	reqCtx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	tr := &trace{onCode: onCode}
	defer tr.finish()
	reqCtx = httptrace.WithClientTrace(reqCtx, &httptrace.ClientTrace{
		GotConn:        tr.gotConn,
		Got1xxResponse: tr.got1xx,
	})
	u := url.URL{Scheme: "https", Host: b.addr, Path: path}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, &Error{text: "cannot make the request for the broker at " + b.addr}
	}
	// Without GetBody, net/http cannot send the body again, so it never
	// sends the request again. With Close, the connection closes after
	// the answer, so no other request goes on it.
	req.GetBody = nil
	req.Close = true
	req.Header.Set("Content-Type", api.ContentType)
	for k, v := range extra {
		req.Header[k] = slices.Clone(v)
	}
	b.versions.setVersion(req.Header)
	defer b.client.CloseIdleConnections()
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, b.requestError(ctx, reqCtx, err, tr.isConnected())
	}
	defer func() { _ = resp.Body.Close() }()
	// Only the pinned broker can send this answer: the TLS handshake
	// checked its key.
	b.versions.check(resp.Header)
	if resp.StatusCode != http.StatusOK {
		// The body of an error answer is never read: it is not needed, and
		// it must never be shown.
		return nil, statusError(resp.StatusCode)
	}
	ans, err := api.ReadAnswer[T, P](resp.Body)
	if err != nil {
		if ctx.Err() != nil || reqCtx.Err() != nil {
			return nil, b.requestError(ctx, reqCtx, err, true)
		}
		return nil, &Error{Status: http.StatusOK, text: "the answer of the broker is not valid"}
	}
	return ans, nil
}

// requestError returns the error of a request that got no final answer,
// or whose answer could not be read: the cause of ctx when ctx ended, or
// an *Error.
func (b *Broker) requestError(ctx, reqCtx context.Context, err error, connected bool) error {
	switch {
	case ctx.Err() != nil:
		return context.Cause(ctx)
	case errors.Is(reqCtx.Err(), context.DeadlineExceeded):
		return &Error{text: fmt.Sprintf("no answer from the broker within %s", b.timeout)}
	case errors.Is(err, errInformational):
		return &Error{text: fmt.Sprintf("the broker sent more than %d informational answers", maxInformational)}
	}
	var op *net.OpError
	isAlert := errors.As(err, &op) && op.Op == "remote error"
	switch {
	case isAlert && connected:
		// A TLS alert from the pinned broker: the client's side of the
		// handshake had ended, with the pin check. In TLS 1.3 the broker
		// checks the client's key only after that, so it refuses an
		// unknown client key with an alert on the first read.
		text := fmt.Sprintf("the broker at %s refused the TLS connection (%s)", b.addr, alertText(op.Err))
		if alertText(op.Err) == "tls: bad certificate" {
			text += "; is the pin of this client's TLS key in the broker config?"
		}
		return &Error{text: text}
	case isAlert:
		// An alert before the pin check: anyone on the network can send
		// it, so it says nothing about the broker.
		return &Error{text: "cannot connect to the broker at " + b.addr +
			": the other side ended the TLS handshake (" + alertText(op.Err) + ")"}
	case connected:
		return &Error{text: "the connection to the broker at " + b.addr + " broke before the answer"}
	}
	return &Error{text: "cannot connect to the broker at " + b.addr + ": " + connectError(err)}
}

// connectError describes an error of a connection before its TLS
// handshake ended. Then anyone on the network can be on the other side,
// so the text holds nothing that the other side chose: a fixed text, an
// error of the operating system, or the pins of the keys.
func connectError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	var op *net.OpError
	var rh tls.RecordHeaderError
	switch {
	case errors.Is(err, transport.ErrBrokerKey):
		// transport's own text, with the pin of the key that the other
		// side has and the pin in broker_pin.
		return strings.TrimPrefix(err.Error(), "nodkey: ")
	case errors.As(err, &rh):
		return "the other side does not speak TLS"
	case errors.As(err, &op) && op.Op == "dial" && op.Err != nil:
		return systemError(op.Err)
	default:
		return "the TLS handshake failed"
	}
}

// systemError returns the text of an error of a network call, such as
// "connect: connection refused", or a fixed text for an error that the
// operating system did not make.
func systemError(err error) string {
	var se *os.SyscallError
	var dns *net.DNSError
	var ne net.Error
	switch {
	case errors.As(err, &se):
		return se.Error()
	case errors.As(err, &dns):
		return "cannot look up the name of the broker"
	case errors.As(err, &ne) && ne.Timeout():
		return "no answer in time"
	default:
		return "the connection failed"
	}
}

// alertText returns the text of a TLS alert, such as "tls: bad
// certificate". crypto/tls takes it from its own table, so the other side
// chooses only its number.
func alertText(err error) string {
	text := err.Error()
	if !strings.HasPrefix(text, "tls: ") || len(text) > 64 {
		return "a TLS alert"
	}
	return text
}
