package transport

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// The broker's log goes to the journal, next to the audit anchors (issue
// #11). Any peer can open a connection, so a log line about a connection
// must be short, rare, and hold no text that the peer chose: no ALPN
// names, no certificate fields, no line breaks. So:
//
//   - A refused TLS handshake gives one short line: the remote address and
//     a fixed reason (handshakeErrorReason). net/http's error text is never
//     logged: it can hold the peer's data.
//   - The pin of an unknown client key is logged by VerifyConnection. A pin
//     is a hash, made by the broker, of the peer's public key.
//   - Any other line from net/http is cut to maxLogLine bytes of printable
//     ASCII (logText).
//   - The server logs at most logLinesPerWindow lines per logWindow, and
//     says how many it dropped (logLimiter): in its next line, or at the
//     end of the window when no line comes. It counts in three parts, each
//     with its own limit: lines that any peer can cause, such as a
//     refused handshake (Server.connLimit); the pin of a key that no
//     [client.*] section pins (Server.pinLimit), which any peer can cause
//     too, with a new key for each connection; and lines about a request
//     of a pinned client: a refused request, or a handler that panicked
//     (Server.keyLimit). So other peers cannot crowd out the lines about
//     the clients.
const (
	// maxLogLine is the most bytes of a line from net/http in the log,
	// and of a value in the server's own lines.
	maxLogLine = 1 << 10
	// logLinesPerWindow and logWindow limit how often the server logs.
	logLinesPerWindow = 60
	logWindow         = time.Minute
)

// logLimiter lets at most logLinesPerWindow lines through in each
// logWindow, and counts the lines it drops. The count is reported by the
// next line, or by a timer at the end of the window when no line comes.
type logLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	start   time.Time // the start of the current window
	lines   int       // the lines let through in the window
	dropped int       // the lines dropped in the window
	// report logs the count of dropped lines when no later line does.
	report func(dropped int)
	// afterFunc is time.AfterFunc; tests replace it.
	afterFunc func(time.Duration, func()) *time.Timer
	timer     *time.Timer // runs flush at the end of a window that dropped lines
	window    uint64      // counts the windows, so a late timer changes nothing
}

// newLogLimiter returns a limiter whose count of dropped lines goes to
// report when no later line reports it.
func newLogLimiter(report func(dropped int)) *logLimiter {
	return &logLimiter{now: time.Now, report: report, afterFunc: time.AfterFunc}
}

// allow reports whether a line may be logged now. At the first call in a
// new window, it also returns how many lines the last window dropped.
func (l *logLimiter) allow() (ok bool, droppedBefore int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// time.Now has a monotonic clock reading, so Sub is not changed by a
	// change of the wall clock.
	now := l.now()
	if l.start.IsZero() || now.Sub(l.start) >= logWindow {
		droppedBefore = l.dropped
		l.start, l.lines, l.dropped = now, 0, 0
		l.window++
		if l.timer != nil {
			l.timer.Stop()
			l.timer = nil
		}
	}
	if l.lines >= logLinesPerWindow {
		l.dropped++
		if l.timer == nil {
			window := l.window
			l.timer = l.afterFunc(logWindow-now.Sub(l.start), func() { l.flush(window) })
		}
		return false, droppedBefore
	}
	l.lines++
	return true, droppedBefore
}

// flush reports the lines that the window dropped, at its end, when no
// later line has reported them, and starts a new window. A timer of an
// older window does nothing.
func (l *logLimiter) flush(window uint64) {
	l.mu.Lock()
	if window != l.window {
		l.mu.Unlock()
		return
	}
	dropped := l.dropped
	l.start, l.lines, l.dropped, l.timer = time.Time{}, 0, 0, nil
	l.mu.Unlock()
	if dropped > 0 {
		l.report(dropped)
	}
}

// reportDropped logs how many lines of a limiter were dropped. what names
// the lines.
func (s *Server) reportDropped(what string, dropped int) {
	s.log.Warn("transport: dropped log lines, to keep the log small", "lines", what, "dropped", dropped,
		"window", logWindow.String())
}

// logLine logs a line through the limiter l. Each string value is cut to
// maxLogLine bytes of printable ASCII, so that no value can make a long
// line or a line break. A message must be a fixed text.
func (s *Server) logLine(l *logLimiter, level slog.Level, msg string, args ...any) {
	ok, dropped := l.allow()
	if dropped > 0 {
		l.report(dropped)
	}
	if !ok {
		return
	}
	for i, a := range args {
		if text, isText := a.(string); isText {
			args[i] = logText(text)
		}
	}
	s.log.Log(context.Background(), level, msg, args...)
}

// logText returns s as at most maxLogLine bytes of printable ASCII. Any
// other byte, such as a line break or a byte of a non-ASCII character,
// becomes "?". A longer text is cut and ends with "...".
func logText(s string) string {
	s = strings.TrimRight(s, "\n")
	cut := len(s) > maxLogLine
	if cut {
		s = s[:maxLogLine-3]
	}
	b := []byte(s)
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			b[i] = '?'
		}
	}
	if cut {
		b = append(b, "..."...)
	}
	return string(b)
}

// remoteText returns the remote address of a connection for the log: an
// IP address and a port, or "unknown".
func remoteText(addr string) string {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return "unknown"
	}
	return ap.String()
}

// netHTTPLog is the writer of the server's ErrorLog. net/http writes each
// of its own log lines with one Write call.
type netHTTPLog struct{ s *Server }

func (w netHTTPLog) Write(p []byte) (int, error) {
	w.s.netHTTPLine(string(p))
	return len(p), nil
}

// handshakeErrorPrefix starts net/http's line for a failed TLS handshake:
// "http: TLS handshake error from <address>: <error>".
const handshakeErrorPrefix = "http: TLS handshake error from "

// netHTTPLine logs a line from net/http.
func (s *Server) netHTTPLine(line string) {
	if rest, ok := strings.CutPrefix(line, handshakeErrorPrefix); ok {
		addr, reason, _ := strings.Cut(rest, ": ")
		why := handshakeErrorReason(reason)
		if why == "" {
			return // VerifyConnection logged it, with the pin
		}
		s.logLine(s.connLimit, slog.LevelWarn, "transport: refused a TLS connection", "remote", remoteText(addr),
			"reason", why)
		return
	}
	s.logLine(s.connLimit, slog.LevelWarn, "transport: a line from net/http", "line", line)
}

// handshakeReasons maps the start of a handshake error's text to a fixed
// reason for the log. The start of the text is fixed by Go or by this
// package; the peer's data, such as its ALPN names or a field of its
// certificate, comes only later in the text. So the reason never holds
// the peer's text, and the peer cannot choose the reason. The first match
// counts.
var handshakeReasons = []struct{ start, reason string }{
	// VerifyConnection logs an unknown key itself, with its pin.
	{ErrUnknownClient.Error(), ""},
	{errCertCount.Error(), "the client sent more than one certificate"},
	{errResumed.Error(), "the client resumed a session"},
	{errVersion.Error(), "the connection is not TLS 1.3"},
	{errNoPeer.Error(), "internal error: the connection has no place for the client name"},
	{errSecondHandshake.Error(), "a second handshake on one connection"},
	{"tls: client offered only unsupported versions", "the client does not offer TLS 1.3"},
	{"tls: client offered TLS version older than TLS 1.3", "the client does not offer TLS 1.3"},
	{"tls: client used the legacy version field", "the client does not offer TLS 1.3"},
	{"tls: unsupported SSLv2 handshake", "the client does not offer TLS 1.3"},
	{"tls: client requested unsupported application protocols", "the client does not offer http/1.1 (ALPN)"},
	{"tls: client didn't provide a certificate", "the client sent no certificate"},
	{"tls: failed to parse client certificate", "the client's certificate cannot be read"},
	{"tls: client sent certificate containing", "the client's certificate cannot be used"},
	{"tls: invalid signature by the client certificate", "the client did not prove that it holds the key of its certificate"},
	{"tls: client certificate used with invalid signature algorithm", "the client did not prove that it holds the key of its certificate"},
	{"tls: no cipher suite supported by both", "the client offers no cipher suite of the broker"},
	{"tls: no key exchanges supported by both", "the client offers no key exchange of the broker"},
	{"tls: first record does not look like a TLS handshake", "the client does not speak TLS"},
	{"tls: oversized record received", "the client does not speak TLS"},
	{"client sent an HTTP request to an HTTPS server", "the client sent plain HTTP"},
	{"remote error: tls: ", "the client ended the handshake; for example, its broker_pin is not the pin of the broker's key"},
	{"tls: ", "another TLS error"},
	{"EOF", "the client closed the connection during the handshake"},
	{"unexpected EOF", "the client closed the connection during the handshake"},
	{"context canceled", "the handshake was stopped"},
	{"context deadline exceeded", "the handshake took too long"},
}

// handshakeErrorReason returns the reason for the log of a failed
// handshake whose error text is text. It returns "" for an error that
// VerifyConnection has logged already.
func handshakeErrorReason(text string) string {
	for _, r := range handshakeReasons {
		if strings.HasPrefix(text, r.start) {
			return r.reason
		}
	}
	// A network error, such as "read tcp 192.0.2.10:7743->192.0.2.20:51234:
	// i/o timeout". Its text comes from Go and the kernel, not from the peer.
	if strings.HasPrefix(text, "read tcp") || strings.HasPrefix(text, "write tcp") {
		if strings.HasSuffix(text, "i/o timeout") {
			return "the handshake took too long"
		}
		return "the connection broke during the handshake"
	}
	return "an unknown error"
}
