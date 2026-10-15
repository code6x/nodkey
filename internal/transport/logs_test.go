package transport

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"log/slog"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/config"
)

// peerCanary is text that a hostile peer puts into its handshake. No log
// line may hold it.
const peerCanary = "made-up-peer-text-5Kd8"

// checkLogLines checks the broker's log after a refused handshake: want
// lines in all, each short, in printable ASCII, and none with peerCanary.
// A line break in the peer's text would make more lines than want.
func checkLogLines(t *testing.T, logs string, want int) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(logs, "\n"), "\n")
	if logs == "" {
		lines = nil
	}
	if len(lines) != want {
		t.Errorf("the log has %d lines, want %d:\n%s", len(lines), want, logs)
	}
	for _, line := range lines {
		if len(line) > 300 {
			t.Errorf("a log line has %d bytes: %.200q...", len(line), line)
		}
		for _, c := range []byte(line) {
			if c < 0x20 || c > 0x7e {
				t.Errorf("a log line holds the byte %#x: %.200q", c, line)
				break
			}
		}
	}
	if strings.Contains(logs, peerCanary) {
		t.Errorf("the log holds the peer's text:\n%.2000s", logs)
	}
}

// hostileText returns n bytes of text with the canary, line breaks,
// control characters and non-ASCII text in it.
func hostileText(n int) string {
	piece := peerCanary + "\n\rtime=x level=ERROR msg=\"audit anchor 1:x\"\x1b[31m\u202e"
	return strings.Repeat(piece, n/len(piece)+1)[:n]
}

func TestHandshakeLogHoldsNoPeerText(t *testing.T) {
	broker, laptop, intruder := newTestKey(t), newTestKey(t), newTestKey(t)
	table := clientTable(map[string]config.Pin{"laptop": laptop.pin})

	t.Run("a hello with 50 KB of ALPN names", func(t *testing.T) {
		b := startBroker(t, broker, table, nil)
		cfg := ClientTLSConfig(laptop.cert, broker.pin)
		cfg.NextProtos = nil
		for range 200 {
			cfg.NextProtos = append(cfg.NextProtos, hostileText(250))
		}
		_, err := ask(t, clientWith(t, cfg), b.addr)
		mustRefuse(t, b, err, "")
		waitForLog(t, b, "the client does not offer http/1.1")
		checkLogLines(t, b.logs.String(), 1)
	})

	t.Run("an unknown key with a long subject", func(t *testing.T) {
		b := startBroker(t, broker, table, nil)
		long := certFor(t, intruder.privateKey(t), func(c *x509.Certificate) {
			c.Subject.CommonName = hostileText(20 << 10)
			c.Subject.Organization = []string{hostileText(10 << 10)}
		})
		_, err := ask(t, clientWith(t, ClientTLSConfig(long, broker.pin)), b.addr)
		mustRefuse(t, b, err, "bad certificate")
		waitForLog(t, b, intruder.pin.String())
		time.Sleep(100 * time.Millisecond) // a second line, if there were one, would come now
		checkLogLines(t, b.logs.String(), 1)
	})

	t.Run("a certificate that cannot be read", func(t *testing.T) {
		b := startBroker(t, broker, table, nil)
		// A URI in the subject alternative names that url.Parse refuses.
		// Go's error repeats the URI.
		uri := "%zz" + strings.NewReplacer("\u202e", "", "\x1b", "").Replace(hostileText(4<<10))
		san, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(uri)}})
		if err != nil {
			t.Fatal(err)
		}
		priv := laptop.privateKey(t)
		tmpl := &x509.Certificate{
			SerialNumber:    big.NewInt(1),
			NotBefore:       time.Now().Add(-time.Hour),
			NotAfter:        time.Now().Add(time.Hour),
			ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: san}},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
		if err != nil {
			t.Fatal(err)
		}
		bad := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
		_, err = ask(t, clientWith(t, ClientTLSConfig(bad, broker.pin)), b.addr)
		mustRefuse(t, b, err, "")
		waitForLog(t, b, "the client's certificate cannot be read")
		checkLogLines(t, b.logs.String(), 1)
	})

	t.Run("a client that refuses the broker's key", func(t *testing.T) {
		b := startBroker(t, broker, table, nil)
		_, err := ask(t, newTestClient(t, b, laptop, intruder.pin), b.addr)
		mustRefuse(t, b, err, "broker_pin")
		waitForLog(t, b, "the client ended the handshake")
		checkLogLines(t, b.logs.String(), 1)
	})
}

func TestHandshakeErrorReason(t *testing.T) {
	for _, tt := range []struct{ text, want string }{
		{"tls: client requested unsupported application protocols ([" + hostileText(100) + "])",
			"the client does not offer http/1.1 (ALPN)"},
		// The peer's text cannot choose the reason: only the start counts.
		{"tls: client requested unsupported application protocols ([EOF remote error: tls: x])",
			"the client does not offer http/1.1 (ALPN)"},
		{"tls: failed to parse client certificate: x509: cannot parse URI \"" + hostileText(100) + "\"",
			"the client's certificate cannot be read"},
		{"tls: client offered only unsupported versions: [303 302]", "the client does not offer TLS 1.3"},
		{"tls: client didn't provide a certificate", "the client sent no certificate"},
		{"tls: invalid signature by the client certificate: ed25519 verification failure",
			"the client did not prove that it holds the key of its certificate"},
		{"remote error: tls: bad certificate", "the client ended the handshake; for example, its broker_pin is not the pin of the broker's key"},
		{"tls: some new error with " + hostileText(100), "another TLS error"},
		{"EOF", "the client closed the connection during the handshake"},
		{"read tcp 192.0.2.10:7743->192.0.2.20:51234: i/o timeout", "the handshake took too long"},
		{"read tcp 192.0.2.10:7743->192.0.2.20:51234: read: connection reset by peer",
			"the connection broke during the handshake"},
		{errCertCount.Error(), "the client sent more than one certificate"},
		{errNoPeer.Error(), "internal error: the connection has no place for the client name"},
		{ErrUnknownClient.Error() + ": the key has the pin sha256:x", ""},
		{hostileText(100), "an unknown error"},
		{"", "an unknown error"},
	} {
		if got := handshakeErrorReason(tt.text); got != tt.want {
			t.Errorf("handshakeErrorReason(%.60q) = %q, want %q", tt.text, got, tt.want)
		}
	}
}

// newLogServer returns a server whose log goes to the returned buffer, with
// a clock that the test sets.
func newLogServer(t *testing.T) (*Server, *syncBuffer, *time.Time) {
	t.Helper()
	broker, laptop := newTestKey(t), newTestKey(t)
	logs := new(syncBuffer)
	srv, err := NewServer(broker.cert, clientTable(map[string]config.Pin{"laptop": laptop.pin}),
		http.NotFoundHandler(), slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, l := range []*logLimiter{srv.connLimit, srv.pinLimit, srv.keyLimit} {
		l.now = func() time.Time { return now }
	}
	return srv, logs, &now
}

func TestNetHTTPLineIsShort(t *testing.T) {
	srv, logs, _ := newLogServer(t)
	// A line that net/http could write with the peer's text in it.
	line := "http: some error: " + hostileText(60<<10) + "\n"
	if n, err := srv.http.ErrorLog.Writer().Write([]byte(line)); n != len(line) || err != nil {
		t.Errorf("Write = %d, %v", n, err)
	}
	got := logs.String()
	checkOneShortLine(t, got)
	if !strings.Contains(got, "...") {
		t.Errorf("the line was not marked as cut: %.200q", got)
	}
	// A handshake error line gives only the remote address and the reason.
	logs2 := new(syncBuffer)
	srv.log = slog.New(slog.NewTextHandler(logs2, nil))
	handshakeLine := "http: TLS handshake error from 192.0.2.20:51234: tls: client requested " +
		"unsupported application protocols ([" + hostileText(1000) + "])\n"
	if _, err := srv.http.ErrorLog.Writer().Write([]byte(handshakeLine)); err != nil {
		t.Fatal(err)
	}
	got2 := logs2.String()
	if !strings.Contains(got2, "remote=192.0.2.20:51234") || !strings.Contains(got2, "ALPN") {
		t.Errorf("the handshake line is %q", got2)
	}
	checkLogLines(t, got2, 1)
}

// checkOneShortLine checks that log holds one line of printable ASCII,
// not much longer than maxLogLine.
func checkOneShortLine(t *testing.T, log string) {
	t.Helper()
	if strings.Count(log, "\n") != 1 || len(log) > maxLogLine+200 {
		t.Errorf("want one short line, got %d bytes in %d lines: %.200q", len(log), strings.Count(log, "\n"), log)
	}
	for _, c := range []byte(strings.TrimSuffix(log, "\n")) {
		if c < 0x20 || c > 0x7e {
			t.Errorf("the line holds the byte %#x", c)
			break
		}
	}
}

func TestLogLimit(t *testing.T) {
	srv, logs, now := newLogServer(t)
	for range 3 * logLinesPerWindow {
		srv.logLine(srv.connLimit, slog.LevelWarn, "transport: a test line", "remote", "192.0.2.20:51234")
	}
	if n := strings.Count(logs.String(), "a test line"); n != logLinesPerWindow {
		t.Errorf("%d lines in one window, want %d", n, logLinesPerWindow)
	}
	// In the next window, the server first says how many it dropped.
	*now = now.Add(logWindow)
	srv.logLine(srv.connLimit, slog.LevelWarn, "transport: a test line")
	got := logs.String()
	if !strings.Contains(got, "dropped log lines") || !strings.Contains(got, "dropped="+strconv.Itoa(2*logLinesPerWindow)) {
		t.Errorf("the log does not say how many lines it dropped:\n%s", got[max(0, len(got)-400):])
	}
	if n := strings.Count(got, "a test line"); n != logLinesPerWindow+1 {
		t.Errorf("%d lines, want %d", n, logLinesPerWindow+1)
	}
}

// TestLogLimitsAreSeparate: lines that any peer can cause, such as refused
// handshakes or the pins of keys that no client has, do not crowd out the
// lines about the requests of pinned clients, such as a handler that
// panicked; and handshakes do not crowd out the pin of a new client.
func TestLogLimitsAreSeparate(t *testing.T) {
	srv, logs, _ := newLogServer(t)
	for range 3 * logLinesPerWindow {
		srv.netHTTPLine("http: TLS handshake error from 192.0.2.20:51234: tls: client didn't provide a certificate\n")
		srv.logLine(srv.pinLimit, slog.LevelWarn, "transport: refused a client key that no [client.*] section pins",
			"pin", "sha256:x")
	}
	srv.logLine(srv.keyLimit, slog.LevelError, "transport: a handler panicked", "where", "x")
	got := logs.String()
	if n := strings.Count(got, "the client sent no certificate"); n != logLinesPerWindow {
		t.Errorf("%d handshake lines, want %d", n, logLinesPerWindow)
	}
	if n := strings.Count(got, "refused a client key"); n != logLinesPerWindow {
		t.Errorf("%d lines about unknown keys, want %d", n, logLinesPerWindow)
	}
	if !strings.Contains(got, "a handler panicked") {
		t.Error("handshakes and unknown keys crowded out the line about a pinned client")
	}
}

// TestDroppedLinesAreReportedWithoutALaterLine: the count of dropped lines
// is written at the end of the window, also when no later line comes, and
// only once.
func TestDroppedLinesAreReportedWithoutALaterLine(t *testing.T) {
	srv, logs, now := newLogServer(t)
	var waits []time.Duration
	var flush func()
	srv.keyLimit.afterFunc = func(d time.Duration, f func()) *time.Timer {
		waits, flush = append(waits, d), f
		return time.NewTimer(time.Hour) // never fires; the test calls flush
	}
	*now = now.Add(time.Second)
	for range logLinesPerWindow + 5 {
		srv.logLine(srv.keyLimit, slog.LevelError, "transport: a handler panicked", "where", "x")
	}
	if len(waits) != 1 || waits[0] != logWindow {
		t.Fatalf("timers %v, want one for the rest of the window", waits)
	}
	flush() // the end of the window
	flush() // a second call, as a late timer, changes nothing
	got := logs.String()
	if !strings.Contains(got, "dropped=5") || !strings.Contains(got, `lines="requests of pinned clients"`) {
		t.Errorf("the log does not say how many lines it dropped:\n%s", got[max(0, len(got)-400):])
	}
	// A new window starts; the count is not reported twice.
	*now = now.Add(logWindow)
	srv.logLine(srv.keyLimit, slog.LevelError, "transport: a handler panicked", "where", "x")
	if n := strings.Count(logs.String(), "dropped log lines"); n != 1 {
		t.Errorf("the count was reported %d times, want 1", n)
	}
}
