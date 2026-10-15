package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/code6x/nodkey/internal/config"
)

// Limits of the broker's HTTP server.
const (
	// readHeaderTimeout is the time a client has to send the request
	// headers. It also limits the TLS handshake: net/http uses the
	// shortest of its timeouts for that.
	readHeaderTimeout = 10 * time.Second
	// readTimeout is the time a client has to send the whole request,
	// with its body. Once the body is read, net/http lifts it and watches
	// the connection for a hang-up, because the answer may wait for the
	// approver for minutes.
	readTimeout = 30 * time.Second
	// idleTimeout closes a connection that has had no request for this
	// long.
	idleTimeout = 60 * time.Second
	// maxHeaderBytes is the most bytes of request headers. A request from
	// the client has a few short headers. (net/http allows 4 KiB more.)
	maxHeaderBytes = 8 << 10
)

// writeTimeout is the time a client has to take an answer, so that a
// client that does not read cannot hold a connection. net/http starts it
// when a request comes, as the server's WriteTimeout. WriteJSON and
// WriteError start it again just before they write, so the wait for the
// approver does not count. It is a variable only so that a test can make
// it short.
var writeTimeout = 30 * time.Second

// errNoPeer is the error of a TLS handshake that did not come through
// Server.Serve. The client name has no place to go then, so the
// handshake fails.
var errNoPeer = errors.New("nodkey: this TLS config works only in transport.Server")

// errSecondHandshake is the error of a second handshake on one connection.
// TLS 1.3 has none, so this is a check for mistakes.
var errSecondHandshake = errors.New("nodkey: a second handshake on one connection")

// Server is the broker's server: mutual TLS 1.3 with pinned client keys,
// and HTTP/1.1.
type Server struct {
	http *http.Server
	tls  *tls.Config
	log  *slog.Logger
	// How often the server logs (see logs.go): lines that any peer can
	// cause, lines with the pin of a key that no client has, and lines
	// about a request of a pinned client.
	connLimit, pinLimit, keyLimit *logLimiter
}

// NewServer returns the broker's server.
//
// key is the broker's own key, from LoadKeyFile. clients are the
// [client.*] sections of the broker config, by name. A client whose key is
// not pinned there cannot connect. A client's pin must not be the pin of
// the broker's own key, and two clients must not have the same pin.
//
// Requests go to handler only after the TLS layer has checked the client's
// pin. A handler gets the client name with ClientName. A request without a
// verified name never reaches handler: the server answers it with 403. If
// handler panics, the server logs where, but not the panic value, which
// can hold anything, and drops the connection. A handler that waits for
// the approver must answer with WriteJSON or WriteError: the server's
// write deadline starts when the request comes, and they start a new one.
//
// logger gets the server's errors, such as a refused handshake: short
// lines with no text that the peer chose, at most logLinesPerWindow of them
// per minute (see logs.go). It may be nil; then nothing is logged.
func NewServer(key tls.Certificate, clients map[string]config.Client, handler http.Handler,
	logger *slog.Logger,
) (*Server, error) {
	if handler == nil {
		return nil, errors.New("transport: NewServer needs a handler")
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	own, err := certificatePin(key)
	if err != nil {
		return nil, fmt.Errorf("the broker's TLS key %w", err)
	}
	byPin, err := clientsByPin(clients, own)
	if err != nil {
		return nil, err
	}
	s := &Server{log: logger}
	s.connLimit = newLogLimiter(func(n int) { s.reportDropped("connections", n) })
	s.pinLimit = newLogLimiter(func(n int) { s.reportDropped("unknown keys", n) })
	s.keyLimit = newLogLimiter(func(n int) { s.reportDropped("requests of pinned clients", n) })
	s.tls = s.tlsConfig(key, byPin)
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	s.http = &http.Server{
		Handler:           s.verified(handler),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		// net/http's own lines can hold the peer's text; netHTTPLog never
		// logs that text (see logs.go).
		ErrorLog: log.New(netHTTPLog{s}, "", 0),
		// Each connection gets an empty peer. The TLS layer fills it in
		// during the handshake (see serverTLSConfig).
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			return context.WithValue(ctx, peerKey{}, new(peer))
		},
		// HTTP/1.1 only. The TLS config offers only "http/1.1" too.
		Protocols: &protocols,
		// Without this, net/http answers "OPTIONS *" itself, without the
		// handler. Every request must go through s.verified.
		DisableGeneralOptionsHandler: true,
	}
	return s, nil
}

// clientsByPin returns the client names by pin. own is the pin of the
// broker's own key.
func clientsByPin(clients map[string]config.Client, own config.Pin) (map[config.Pin]string, error) {
	if len(clients) == 0 {
		return nil, errors.New("the broker config has no [client.*] section; no client could connect")
	}
	byPin := make(map[config.Pin]string, len(clients))
	for _, name := range slices.Sorted(maps.Keys(clients)) {
		c := clients[name]
		// The config package checks the names, so an error may show them.
		if name == "" || c.Name != name {
			return nil, fmt.Errorf("[client.%s]: the name in the section is %q", name, c.Name)
		}
		if c.Pin == own {
			return nil, fmt.Errorf("[client.%s] pin: is the pin of the broker's own TLS key; "+
				"each client needs its own key, made with nodkey keygen on that client", name)
		}
		if other, ok := byPin[c.Pin]; ok {
			return nil, fmt.Errorf("[client.%s] pin: is the same as the pin of [client.%s]; "+
				"each client needs its own TLS key", name, other)
		}
		byPin[c.Pin] = name
	}
	return byPin, nil
}

// tlsConfig returns the broker's TLS config: TLS 1.3 only, a client
// certificate required but not checked against any certificate authority,
// no session tickets, and the pin check in VerifyConnection.
//
// The client name must reach the request, and only the TLS layer may put
// it there. So the config is made again for each connection, in
// GetConfigForClient, with a VerifyConnection that stores the name in the
// connection's peer. net/http passes the connection's context to the
// handshake, and the peer is in that context (see NewServer). A handshake
// without a peer fails. The returned config itself never accepts a client
// on its own: its VerifyConnection always fails.
func (s *Server) tlsConfig(key tls.Certificate, byPin map[config.Pin]string) *tls.Config {
	conn := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{key},
		// Ask every client for a certificate, and refuse a client without
		// one. Do not check it against a certificate authority: there is
		// none, so ClientCAs stays empty. The pin is the check.
		ClientAuth: tls.RequireAnyClientCert,
		// No session tickets, so no connection can skip the full
		// handshake and the pin check.
		SessionTicketsDisabled: true,
		NextProtos:             []string{"http/1.1"},
	}
	base := conn.Clone()
	base.VerifyConnection = func(tls.ConnectionState) error { return errNoPeer }
	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		ctx := hello.Context()
		if ctx == nil {
			return nil, errNoPeer
		}
		p, ok := ctx.Value(peerKey{}).(*peer)
		if !ok || p == nil {
			return nil, errNoPeer
		}
		remote := "unknown"
		if hello.Conn != nil && hello.Conn.RemoteAddr() != nil {
			remote = remoteText(hello.Conn.RemoteAddr().String())
		}
		c := conn.Clone()
		c.VerifyConnection = func(cs tls.ConnectionState) error {
			name, pin, err := verifyClient(cs, byPin)
			if errors.Is(err, ErrUnknownClient) {
				// The pin is the hash of the peer's public key, not text
				// that the peer chose. It helps to add a new client.
				s.logLine(s.pinLimit, slog.LevelWarn, "transport: refused a client key that no [client.*] section pins",
					"remote", remote, "pin", pin.String())
			}
			if err != nil {
				return err
			}
			return p.set(name, pin)
		}
		return c, nil
	}
	return base
}

// peerKey is the context key of a connection's peer.
type peerKey struct{}

// clientKey is the context key of a request's client name.
type clientKey struct{}

// peer is what the TLS layer learned about the client of one connection.
// The server puts an empty peer into the context of each new connection,
// and VerifyConnection fills it in during the handshake.
type peer struct {
	mu   sync.Mutex
	done bool
	name string
	pin  config.Pin
}

// set stores the client's name and pin. A connection has one handshake
// (TLS 1.3 has no renegotiation), so a second call is an error.
func (p *peer) set(name string, pin config.Pin) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done {
		return errSecondHandshake
	}
	p.done, p.name, p.pin = true, name, pin
	return nil
}

// get returns the client's name and pin. ok is false before set.
func (p *peer) get() (name string, pin config.Pin, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.name, p.pin, p.done
}

// ClientName returns the name of the client that sent a request, from the
// context of the request (or a context made from it). The name comes only
// from the pin of the client's TLS key: it is the name of the [client.*]
// section that pins that key. The server puts it into the context of each
// request before the handler sees it; no other code can. In any other
// context, ok is false, and the caller must deny.
func ClientName(ctx context.Context) (name string, ok bool) {
	name, ok = ctx.Value(clientKey{}).(string)
	if !ok || name == "" {
		return "", false
	}
	return name, true
}

// verifiedClient returns the client name that the TLS layer stored for the
// connection of r.
//
// VerifyConnection runs during the handshake, before the client has proved
// that it holds the private key of its certificate. If it does not, the
// handshake fails after VerifyConnection, and net/http serves no request
// on a failed handshake. Still, the name is given only if the state of the
// finished handshake has the same pin. So a mistake in this chain cannot
// give a request a name from another connection, or from a handshake that
// did not finish.
func verifiedClient(r *http.Request) (string, bool) {
	p, ok := r.Context().Value(peerKey{}).(*peer)
	if !ok || p == nil {
		return "", false
	}
	name, pin, ok := p.get()
	if !ok || name == "" {
		return "", false
	}
	cs := r.TLS
	if cs == nil || !cs.HandshakeComplete || cs.DidResume || len(cs.PeerCertificates) != 1 ||
		PinOf(cs.PeerCertificates[0]) != pin {
		return "", false
	}
	return name, true
}

// verified wraps the handler: it passes on only requests with a verified
// client name, with the name in the request's context, and it catches
// panics.
func (s *Server) verified(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				s.handlerPanicked(v)
			}
		}()
		name, ok := verifiedClient(r)
		if !ok {
			s.logLine(s.keyLimit, slog.LevelError, "transport: refused a request without a verified client name",
				"remote", remoteText(r.RemoteAddr))
			WriteError(w, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientKey{}, name)))
	})
}

// handlerPanicked handles the value v of a panic in a handler. net/http
// would log v, and v can hold anything from the request, such as a secret.
// So the server logs only where the panic happened, and then panics with
// http.ErrAbortHandler itself: net/http drops the connection without a log
// line, and the client gets no answer that looks complete. A handler that
// aborts on purpose, with an error that is or wraps http.ErrAbortHandler,
// is not logged; the error it wraps is not passed on either.
func (s *Server) handlerPanicked(v any) {
	if err, ok := v.(error); !ok || !errors.Is(err, http.ErrAbortHandler) {
		s.logLine(s.keyLimit, slog.LevelError, "transport: a handler panicked; the connection is dropped, and the panic value is not logged",
			"where", panicPlace())
	}
	panic(http.ErrAbortHandler)
}

// panicPlace returns where a panic happened: the function, file and line
// of the frames below the panic, without any values. It must be called by
// the function that recovered the panic, from its deferred function.
func panicPlace() string {
	pcs := make([]uintptr, 64)
	n := runtime.Callers(1, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	var places []string
	below := false // past runtime.gopanic: in the frames that panicked
	for {
		f, more := frames.Next()
		switch {
		case f.Function == "runtime.gopanic":
			below = true
		case below && !strings.HasPrefix(f.Function, "runtime."):
			places = append(places, f.Function+" "+f.File+":"+strconv.Itoa(f.Line))
		}
		if !more || len(places) == 8 {
			break
		}
	}
	if len(places) == 0 {
		return "unknown"
	}
	return strings.Join(places, " < ")
}

// Serve accepts connections on ln and serves them until Shutdown or Close.
// Each connection gets a TLS handshake with the broker's key and the pin
// check, and then HTTP/1.1. Serve returns http.ErrServerClosed after
// Shutdown or Close.
func (s *Server) Serve(ln net.Listener) error {
	return s.http.Serve(tls.NewListener(ln, s.tls))
}

// Shutdown stops the server: it stops accepting connections, closes idle
// ones, and waits for the requests that run until ctx ends.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

// Close stops the server at once and closes all its connections.
func (s *Server) Close() error {
	return s.http.Close()
}
