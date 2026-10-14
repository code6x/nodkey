package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/config"
)

// startTLSServer starts a plain HTTPS server with cfg, for tests that need
// a broker with another config: an impostor, or an old TLS version. It
// returns the address and a counter of the requests that reached it.
func startTLSServer(t *testing.T, cfg *tls.Config) (string, *atomic.Int32) {
	t.Helper()
	calls := new(atomic.Int32)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			_ = WriteJSON(w, http.StatusOK, whoAmI{Client: "impostor"})
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ErrorLog:          discardLog(),
	}
	addr := listenAndServe(t, func(ln net.Listener) error {
		return srv.Serve(tls.NewListener(ln, cfg))
	}, func() { _ = srv.Close() })
	return addr, calls
}

func TestRightPinsConnect(t *testing.T) {
	broker, laptop, web := newTestKey(t), newTestKey(t), newTestKey(t)
	b := startBroker(t, broker, clientTable(map[string]config.Pin{"laptop": laptop.pin, "web-1": web.pin}), nil)
	for name, key := range map[string]testKey{"laptop": laptop, "web-1": web} {
		c := newTestClient(t, b, key, broker.pin)
		got, cs, err := askState(t, c, b.addr, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != name {
			t.Errorf("the key of %s got the client name %q", name, got)
		}
		if cs.Version != tls.VersionTLS13 || cs.DidResume || cs.NegotiatedProtocol != "http/1.1" {
			t.Errorf("%s: version %#x, resumed %v, protocol %q; want TLS 1.3, a full handshake and http/1.1",
				name, cs.Version, cs.DidResume, cs.NegotiatedProtocol)
		}
		if len(cs.PeerCertificates) != 1 || PinOf(cs.PeerCertificates[0]) != broker.pin {
			t.Errorf("%s: the client did not see the broker's key", name)
		}
	}
	if n := b.calls.Load(); n != 2 {
		t.Errorf("the handler ran %d times, want 2", n)
	}
	checkNoKeyMaterial(t, "the broker's log", b.logs.String(), broker, laptop, web)
}

func TestWrongClientPinIsRefused(t *testing.T) {
	broker, laptop, intruder := newTestKey(t), newTestKey(t), newTestKey(t)
	b := startBroker(t, broker, clientTable(map[string]config.Pin{"laptop": laptop.pin}), nil)
	_, err := ask(t, newTestClient(t, b, intruder, broker.pin), b.addr)
	mustRefuse(t, b, err, "bad certificate")
	// The broker's log says why, and names the pin of the key that tried,
	// which is not secret; it holds no key material.
	logs := waitForLog(t, b, "refused a client key that no [client.*] section pins")
	if !strings.Contains(logs, intruder.pin.String()) {
		t.Errorf("the broker's log does not name the unknown key:\n%s", logs)
	}
	if n := strings.Count(logs, "\n"); n != 1 {
		t.Errorf("the broker logged %d lines, want 1:\n%s", n, logs)
	}
	checkNoKeyMaterial(t, "the broker's log", logs, broker, laptop, intruder)
}

func TestWrongBrokerPinIsRefused(t *testing.T) {
	broker, laptop, other := newTestKey(t), newTestKey(t), newTestKey(t)
	b := startBroker(t, broker, clientTable(map[string]config.Pin{"laptop": laptop.pin}), nil)

	t.Run("the client pins another key", func(t *testing.T) {
		_, err := ask(t, newTestClient(t, b, laptop, other.pin), b.addr)
		if !errors.Is(err, ErrBrokerKey) {
			t.Errorf("error = %v, want ErrBrokerKey", err)
		}
		mustRefuse(t, b, err, "broker_pin")
		checkNoKeyMaterial(t, "the error", err.Error(), broker, laptop, other)
	})

	t.Run("another server with its own key", func(t *testing.T) {
		addr, calls := startTLSServer(t, &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{other.cert},
			ClientAuth:   tls.RequireAnyClientCert,
		})
		c, err := NewClient(addr, laptop.cert, broker.pin)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ask(t, c, addr)
		if !errors.Is(err, ErrBrokerKey) {
			t.Errorf("error = %v, want ErrBrokerKey", err)
		}
		if n := calls.Load(); n != 0 {
			t.Errorf("the client sent %d requests to the impostor", n)
		}
	})
}

// TestCopiedCertificateIsRefused shows that a certificate alone is not
// enough: TLS proves that each side holds the private key of its
// certificate. VerifyConnection passes here, because the pin matches, but
// the handshake fails later.
func TestCopiedCertificateIsRefused(t *testing.T) {
	broker, laptop, intruder := newTestKey(t), newTestKey(t), newTestKey(t)
	b := startBroker(t, broker, clientTable(map[string]config.Pin{"laptop": laptop.pin}), nil)

	t.Run("a client with the laptop's certificate and another key", func(t *testing.T) {
		stolen := tls.Certificate{Certificate: laptop.cert.Certificate, PrivateKey: intruder.privateKey(t)}
		_, err := ask(t, clientWith(t, ClientTLSConfig(stolen, broker.pin)), b.addr)
		mustRefuse(t, b, err, "")
		waitForLog(t, b, "did not prove that it holds the key of its certificate")
	})

	t.Run("a server with the broker's certificate and another key", func(t *testing.T) {
		stolen := tls.Certificate{Certificate: broker.cert.Certificate, PrivateKey: intruder.privateKey(t)}
		addr, calls := startTLSServer(t, &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{stolen},
			ClientAuth:   tls.RequireAnyClientCert,
		})
		c, err := NewClient(addr, laptop.cert, broker.pin)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ask(t, c, addr)
		if err == nil || !strings.Contains(err.Error(), "invalid signature") {
			t.Errorf("error = %v, want an invalid signature", err)
		}
		if n := calls.Load(); n != 0 {
			t.Errorf("the client sent %d requests to the impostor", n)
		}
	})
}

func TestTLS12IsRefused(t *testing.T) {
	broker, laptop := newTestKey(t), newTestKey(t)

	t.Run("by the broker", func(t *testing.T) {
		b := startBroker(t, broker, clientTable(map[string]config.Pin{"laptop": laptop.pin}), nil)
		cfg := ClientTLSConfig(laptop.cert, broker.pin)
		cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
		_, err := ask(t, clientWith(t, cfg), b.addr)
		mustRefuse(t, b, err, "protocol version")
	})

	t.Run("by the client", func(t *testing.T) {
		addr, calls := startTLSServer(t, &tls.Config{ //nolint:gosec // G402: a broker on TLS 1.2, which the client must refuse.
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{broker.cert},
			ClientAuth:   tls.RequireAnyClientCert,
		})
		c, err := NewClient(addr, laptop.cert, broker.pin)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ask(t, c, addr)
		if err == nil || !strings.Contains(err.Error(), "protocol version") {
			t.Errorf("error = %v, want a refused protocol version", err)
		}
		if n := calls.Load(); n != 0 {
			t.Errorf("the client sent %d requests over TLS 1.2", n)
		}
	})
}

func TestNoClientCertificateIsRefused(t *testing.T) {
	broker, laptop, other := newTestKey(t), newTestKey(t), newTestKey(t)
	b := startBroker(t, broker, clientTable(map[string]config.Pin{"laptop": laptop.pin}), nil)

	t.Run("no certificate", func(t *testing.T) {
		cfg := ClientTLSConfig(laptop.cert, broker.pin)
		cfg.Certificates = nil
		_, err := ask(t, clientWith(t, cfg), b.addr)
		mustRefuse(t, b, err, "certificate required")
	})

	t.Run("two certificates", func(t *testing.T) {
		// The pinned certificate, with one more after it: a chain is
		// refused, because there is no certificate authority.
		chain := laptop.cert
		chain.Certificate = [][]byte{laptop.cert.Certificate[0], other.cert.Certificate[0]}
		chain.Leaf = nil
		_, err := ask(t, clientWith(t, ClientTLSConfig(chain, broker.pin)), b.addr)
		mustRefuse(t, b, err, "bad certificate")
		waitForLog(t, b, "the client sent more than one certificate")
	})
}

// recordingCache is a TLS client session cache that counts the sessions it
// gets from servers (puts) and gives out (hits).
type recordingCache struct {
	tls.ClientSessionCache
	puts, hits atomic.Int32
}

func (c *recordingCache) Get(key string) (*tls.ClientSessionState, bool) {
	s, ok := c.ClientSessionCache.Get(key)
	if ok && s != nil {
		c.hits.Add(1)
	}
	return s, ok
}

func (c *recordingCache) Put(key string, s *tls.ClientSessionState) {
	if s != nil {
		c.puts.Add(1)
	}
	c.ClientSessionCache.Put(key, s)
}

// TestSecondConnectionCannotSkipThePinCheck shows that the pin is checked
// on every connection: a new connection with another key is refused, and
// no connection resumes an earlier session, which would skip the
// certificate.
func TestSecondConnectionCannotSkipThePinCheck(t *testing.T) {
	broker, laptop, intruder := newTestKey(t), newTestKey(t), newTestKey(t)
	b := startBroker(t, broker, clientTable(map[string]config.Pin{"laptop": laptop.pin}), nil)

	// switching is the config of a hostile client: its certificate can
	// change between connections, and it keeps and offers sessions if
	// cache is not nil.
	switching := func(cache tls.ClientSessionCache) (*tls.Config, *atomic.Pointer[tls.Certificate]) {
		var current atomic.Pointer[tls.Certificate]
		cfg := ClientTLSConfig(laptop.cert, broker.pin)
		cfg.Certificates = nil
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return current.Load(), nil
		}
		cfg.ClientSessionCache = cache
		cfg.SessionTicketsDisabled = cache == nil
		return cfg, &current
	}

	t.Run("a changed certificate on a new connection", func(t *testing.T) {
		cfg, current := switching(nil)
		c := clientWith(t, cfg) // a new connection for each request
		for i, step := range []struct {
			key  testKey
			want string // "" means refused
		}{{laptop, "laptop"}, {intruder, ""}, {laptop, "laptop"}, {intruder, ""}} {
			current.Store(&step.key.cert)
			before := b.calls.Load()
			got, err := ask(t, c, b.addr)
			switch {
			case step.want == "" && err == nil:
				t.Errorf("connection %d with an unknown key went through as %q", i+1, got)
			case step.want == "" && b.calls.Load() != before:
				t.Errorf("connection %d with an unknown key reached the handler", i+1)
			case step.want != "" && (err != nil || got != step.want):
				t.Errorf("connection %d with the laptop's key: %q, %v", i+1, got, err)
			}
		}
	})

	t.Run("the broker sends no session ticket", func(t *testing.T) {
		cache := &recordingCache{ClientSessionCache: tls.NewLRUClientSessionCache(4)}
		cfg, current := switching(cache)
		current.Store(&laptop.cert)
		c := clientWith(t, cfg)
		for i := range 3 {
			_, cs, err := askState(t, c, b.addr, nil)
			if err != nil {
				t.Fatal(err)
			}
			if cs.DidResume {
				t.Errorf("connection %d resumed a session", i+1)
			}
		}
		if n := cache.puts.Load(); n != 0 {
			t.Errorf("the broker gave the client %d sessions to resume, want 0", n)
		}
	})

	t.Run("a session from another server is not resumed", func(t *testing.T) {
		// A server with the broker's key that does send session tickets,
		// like a broker with a weaker config. The client keeps its ticket
		// under the server name, and offers it to the real broker.
		twin := &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{broker.cert},
			ClientAuth:   tls.RequireAnyClientCert,
		}
		twinAddr := listenAndServe(t, func(ln net.Listener) error {
			tl := tls.NewListener(ln, twin)
			for {
				conn, err := tl.Accept()
				if err != nil {
					return err
				}
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				_, _ = conn.Write([]byte("hi")) // the tickets go first
				_, _ = io.Copy(io.Discard, conn)
				_ = conn.Close()
			}
		}, func() {})

		cache := &recordingCache{ClientSessionCache: tls.NewLRUClientSessionCache(4)}
		cfg, current := switching(cache)
		cfg.ServerName = "broker.example" // the key in the cache, the same for both servers
		current.Store(&laptop.cert)
		d := tls.Dialer{Config: cfg}
		conn, err := d.DialContext(t.Context(), "tcp", twinAddr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		if cache.puts.Load() == 0 {
			t.Fatal("the twin server gave no session; the test cannot show anything")
		}

		// The intruder offers that session to the broker. The broker does
		// a full handshake and checks the intruder's certificate.
		current.Store(&intruder.cert)
		hits := cache.hits.Load()
		b.calls.Store(0)
		_, err = ask(t, clientWith(t, cfg), b.addr)
		mustRefuse(t, b, err, "bad certificate")
		if cache.hits.Load() == hits {
			t.Error("the client did not offer the session; the test shows nothing")
		}

		// The laptop gets in, with a full handshake.
		current.Store(&laptop.cert)
		got, cs, err := askState(t, clientWith(t, cfg), b.addr, nil)
		if err != nil || got != "laptop" {
			t.Fatalf("the laptop after the twin: %q, %v", got, err)
		}
		if cs.DidResume {
			t.Error("the broker resumed the twin's session")
		}
	})
}

func TestPeerPin(t *testing.T) {
	key := newTestKey(t)
	other := newTestKey(t)
	good := tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{key.cert.Leaf}}
	pin, err := peerPin(good)
	if err != nil || pin != key.pin {
		t.Fatalf("peerPin of a good connection = %s, %v; want %s", pin, err, key.pin)
	}
	for _, tt := range []struct {
		name string
		edit func(*tls.ConnectionState)
		want error
	}{
		{"TLS 1.2", func(cs *tls.ConnectionState) { cs.Version = tls.VersionTLS12 }, errVersion},
		{"a resumed session", func(cs *tls.ConnectionState) { cs.DidResume = true }, errResumed},
		{"no certificate", func(cs *tls.ConnectionState) { cs.PeerCertificates = nil }, errCertCount},
		{"two certificates", func(cs *tls.ConnectionState) {
			cs.PeerCertificates = []*x509.Certificate{key.cert.Leaf, other.cert.Leaf}
		}, errCertCount},
	} {
		cs := good
		tt.edit(&cs)
		if _, err := peerPin(cs); !errors.Is(err, tt.want) {
			t.Errorf("%s: peerPin = %v, want %v", tt.name, err, tt.want)
		}
		// Both sides use peerPin, so both refuse it.
		if _, _, err := verifyClient(cs, map[config.Pin]string{key.pin: "laptop"}); !errors.Is(err, tt.want) {
			t.Errorf("%s: verifyClient = %v, want %v", tt.name, err, tt.want)
		}
		if err := verifyBroker(cs, key.pin); !errors.Is(err, tt.want) {
			t.Errorf("%s: verifyBroker = %v, want %v", tt.name, err, tt.want)
		}
	}
}

func TestTLSConfigs(t *testing.T) {
	broker, laptop := newTestKey(t), newTestKey(t)
	srv, err := NewServer(broker.cert, clientTable(map[string]config.Pin{"laptop": laptop.pin}),
		http.NotFoundHandler(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := srv.tls
	if s.MinVersion != tls.VersionTLS13 || s.MaxVersion != tls.VersionTLS13 || s.ClientAuth != tls.RequireAnyClientCert ||
		s.ClientCAs != nil || !s.SessionTicketsDisabled || len(s.Certificates) != 1 || s.GetConfigForClient == nil {
		t.Errorf("the broker's TLS config is not strict: %+v", s)
	}
	if err := s.VerifyConnection(tls.ConnectionState{}); !errors.Is(err, errNoPeer) {
		t.Errorf("the broker's base config accepts a connection: %v", err)
	}
	// Without the connection's peer in the handshake's context, there is
	// no config for the client.
	if _, err := s.GetConfigForClient(&tls.ClientHelloInfo{}); !errors.Is(err, errNoPeer) {
		t.Errorf("GetConfigForClient without a peer = %v, want errNoPeer", err)
	}

	c := ClientTLSConfig(laptop.cert, broker.pin)
	if c.MinVersion != tls.VersionTLS13 || c.MaxVersion != tls.VersionTLS13 || c.ClientSessionCache != nil ||
		!c.SessionTicketsDisabled || c.VerifyConnection == nil || c.Renegotiation != tls.RenegotiateNever {
		t.Errorf("the client's TLS config is not strict: %+v", c)
	}
	// InsecureSkipVerify is set only together with the pin check.
	if !c.InsecureSkipVerify {
		t.Error("InsecureSkipVerify is off; the default check would refuse the broker's self-signed certificate")
	}
	if err := c.VerifyConnection(tls.ConnectionState{Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{laptop.cert.Leaf}}); !errors.Is(err, ErrBrokerKey) {
		t.Errorf("the client's VerifyConnection accepts another key: %v", err)
	}
}

// TestBrokerTLSConfigNeedsTheServer shows that the broker's TLS config
// cannot be used without Server: there would be no place for the client
// name, so the handshake fails.
func TestBrokerTLSConfigNeedsTheServer(t *testing.T) {
	broker, laptop := newTestKey(t), newTestKey(t)
	var calls atomic.Int32
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) })
	srv, err := NewServer(broker.cert, clientTable(map[string]config.Pin{"laptop": laptop.pin}), handler, nil)
	if err != nil {
		t.Fatal(err)
	}
	plain := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ErrorLog: discardLog()}
	addr := listenAndServe(t, func(ln net.Listener) error {
		return plain.Serve(tls.NewListener(ln, srv.tls))
	}, func() { _ = plain.Close() })
	c, err := NewClient(addr, laptop.cert, broker.pin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ask(t, c, addr); err == nil || !strings.Contains(err.Error(), "internal error") {
		t.Errorf("error = %v, want a refused handshake", err)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("the handler ran %d times, want 0", n)
	}
}

func TestClientNameComesOnlyFromThePin(t *testing.T) {
	broker, laptop, web, intruder := newTestKey(t), newTestKey(t), newTestKey(t), newTestKey(t)
	b := startBroker(t, broker, clientTable(map[string]config.Pin{"laptop": laptop.pin, "web-1": web.pin}), nil)

	t.Run("the request cannot change it", func(t *testing.T) {
		c := newTestClient(t, b, laptop, broker.pin)
		for what, edit := range map[string]func(*http.Request){
			"headers": func(r *http.Request) {
				r.Header.Set("X-Nodkey-Client", "web-1")
				r.Header.Set("X-Client-Name", "web-1")
				r.Header.Set("Forwarded", "for=web-1")
			},
			"the query": func(r *http.Request) { r.URL.RawQuery = "client=web-1&name=web-1" },
			"the host":  func(r *http.Request) { r.Host = "web-1" },
			"the body": func(r *http.Request) {
				body := `{"client":"web-1","name":"web-1"}`
				r.Body, r.ContentLength = io.NopCloser(strings.NewReader(body)), int64(len(body))
			},
		} {
			got, _, err := askState(t, c, b.addr, edit)
			if err != nil || got != "laptop" {
				t.Errorf("with web-1 in %s: %q, %v; want laptop", what, got, err)
			}
		}
	})

	t.Run("the server name (SNI) cannot change it", func(t *testing.T) {
		cfg := ClientTLSConfig(laptop.cert, broker.pin)
		cfg.ServerName = "web-1"
		if got, err := ask(t, clientWith(t, cfg), b.addr); err != nil || got != "laptop" {
			t.Errorf("with the server name web-1: %q, %v; want laptop", got, err)
		}
	})

	t.Run("the names in the certificate do not count", func(t *testing.T) {
		// A new certificate for the laptop's key, with web-1's names in it.
		renamed := certFor(t, laptop.privateKey(t), func(c *x509.Certificate) {
			c.Subject.CommonName = "web-1"
			c.Subject.Organization = []string{"web-1"}
			c.DNSNames = []string{"web-1", "web-1.example.com"}
		})
		if got, err := ask(t, clientWith(t, ClientTLSConfig(renamed, broker.pin)), b.addr); err != nil || got != "laptop" {
			t.Errorf("the laptop's key with web-1's names: %q, %v; want laptop", got, err)
		}
		// Another key in a certificate that copies the laptop's names and
		// serial number.
		copied := certFor(t, intruder.privateKey(t), func(c *x509.Certificate) {
			c.Subject = laptop.cert.Leaf.Subject
			c.SerialNumber = laptop.cert.Leaf.SerialNumber
			c.NotBefore, c.NotAfter = laptop.cert.Leaf.NotBefore, laptop.cert.Leaf.NotAfter
		})
		before := b.calls.Load()
		if got, err := ask(t, clientWith(t, ClientTLSConfig(copied, broker.pin)), b.addr); err == nil {
			t.Errorf("a key with the laptop's names got in as %q", got)
		}
		if b.calls.Load() != before {
			t.Error("a key with the laptop's names reached the handler")
		}
	})
}

// TestHandlerGetsNoNameWithoutTheTLSLayer calls the server's handler
// directly, without a TLS connection: the name is refused unless the TLS
// layer stored it for the connection, and the finished handshake agrees.
func TestHandlerGetsNoNameWithoutTheTLSLayer(t *testing.T) {
	broker, laptop, web := newTestKey(t), newTestKey(t), newTestKey(t)
	var calls atomic.Int32
	var got string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		got, _ = ClientName(r.Context())
	})
	srv, err := NewServer(broker.cert, clientTable(map[string]config.Pin{"laptop": laptop.pin}), handler, nil)
	if err != nil {
		t.Fatal(err)
	}

	// ClientName needs the server's own key in the context.
	if name, ok := ClientName(context.Background()); ok {
		t.Errorf("ClientName of an empty context = %q", name)
	}
	type clientKey struct{} // a key of another type, with the same name
	if name, ok := ClientName(context.WithValue(context.Background(), clientKey{}, "laptop")); ok {
		t.Errorf("ClientName took a value under a key of another package: %q", name)
	}

	filled := func(name string, pin config.Pin) *peer {
		p := new(peer)
		if err := p.set(name, pin); err != nil {
			t.Fatal(err)
		}
		return p
	}
	done := func(certs ...*x509.Certificate) *tls.ConnectionState {
		return &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, PeerCertificates: certs}
	}
	for _, tt := range []struct {
		name string
		peer *peer
		tls  *tls.ConnectionState
		want string // "" means refused
	}{
		{"no peer, no TLS", nil, nil, ""},
		{"no peer", nil, done(laptop.cert.Leaf), ""},
		{"an empty peer", new(peer), done(laptop.cert.Leaf), ""},
		{"no TLS state", filled("laptop", laptop.pin), nil, ""},
		{"an unfinished handshake", filled("laptop", laptop.pin),
			&tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{laptop.cert.Leaf}}, ""},
		{"another key in the handshake", filled("laptop", laptop.pin), done(web.cert.Leaf), ""},
		{"no certificate in the handshake", filled("laptop", laptop.pin), done(), ""},
		{"a resumed session", filled("laptop", laptop.pin), &tls.ConnectionState{Version: tls.VersionTLS13,
			HandshakeComplete: true, DidResume: true, PeerCertificates: []*x509.Certificate{laptop.cert.Leaf}}, ""},
		{"all right", filled("laptop", laptop.pin), done(laptop.cert.Leaf), "laptop"},
	} {
		calls.Store(0)
		got = ""
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/whoami", strings.NewReader("{}"))
		if tt.peer != nil {
			req = req.WithContext(context.WithValue(req.Context(), peerKey{}, tt.peer))
		}
		req.TLS = tt.tls
		rec := httptest.NewRecorder()
		srv.http.Handler.ServeHTTP(rec, req)
		switch {
		case tt.want == "" && (calls.Load() != 0 || rec.Code != http.StatusForbidden):
			t.Errorf("%s: the handler ran %d times, status %d; want 0 and 403", tt.name, calls.Load(), rec.Code)
		case tt.want != "" && (calls.Load() != 1 || got != tt.want):
			t.Errorf("%s: the handler ran %d times with %q; want once with %q", tt.name, calls.Load(), got, tt.want)
		}
	}

	// The TLS layer sets a peer once: a connection has one handshake.
	p := filled("laptop", laptop.pin)
	if err := p.set("web-1", web.pin); err == nil {
		t.Error("a second set on one peer worked")
	}
	if name, _, _ := p.get(); name != "laptop" {
		t.Errorf("after a second set, the peer is %q", name)
	}
}

func TestHTTP2IsNotUsed(t *testing.T) {
	broker, laptop := newTestKey(t), newTestKey(t)
	b := startBroker(t, broker, clientTable(map[string]config.Pin{"laptop": laptop.pin}), nil)
	cfg := ClientTLSConfig(laptop.cert, broker.pin)
	cfg.NextProtos = []string{"h2"}
	d := tls.Dialer{Config: cfg}
	conn, err := d.DialContext(t.Context(), "tcp", b.addr)
	if err == nil {
		_ = conn.Close()
		t.Fatal("a client that speaks only HTTP/2 got a connection")
	}
	if !strings.Contains(err.Error(), "application protocol") {
		t.Errorf("error = %v, want a refused application protocol", err)
	}
}

func TestNewServerRefuses(t *testing.T) {
	broker, laptop, web := newTestKey(t), newTestKey(t), newTestKey(t)
	handler := http.NotFoundHandler()
	ok := clientTable(map[string]config.Pin{"laptop": laptop.pin})
	for _, tt := range []struct {
		name    string
		key     tls.Certificate
		clients map[string]config.Client
		handler http.Handler
		want    string
	}{
		{"no handler", broker.cert, ok, nil, "needs a handler"},
		{"no clients", broker.cert, nil, handler, "no [client.*] section"},
		{"a client with the broker's pin", broker.cert,
			clientTable(map[string]config.Pin{"laptop": broker.pin}), handler, "the broker's own TLS key"},
		{"two clients with one pin", broker.cert,
			clientTable(map[string]config.Pin{"laptop": laptop.pin, "web-1": laptop.pin}), handler, "same as the pin of [client.laptop]"},
		{"a client under another name", broker.cert,
			map[string]config.Client{"laptop": {Name: "web-1", Pin: web.pin}}, handler, "the name in the section"},
		{"a key without a certificate", tls.Certificate{PrivateKey: broker.cert.PrivateKey}, ok, handler,
			"exactly one certificate"},
		{"a key with two certificates", tls.Certificate{
			Certificate: [][]byte{broker.cert.Certificate[0], web.cert.Certificate[0]}, PrivateKey: broker.cert.PrivateKey,
		}, ok, handler, "exactly one certificate"},
		{"a key without a private key", tls.Certificate{Certificate: broker.cert.Certificate}, ok, handler,
			"no private key"},
		{"a broken certificate", tls.Certificate{Certificate: [][]byte{[]byte("made-up")}, PrivateKey: broker.cert.PrivateKey},
			ok, handler, "cannot be read"},
		{"the certificate of another key", tls.Certificate{Certificate: web.cert.Certificate, PrivateKey: broker.cert.PrivateKey},
			ok, handler, "not the key of its certificate"},
	} {
		srv, err := NewServer(tt.key, tt.clients, tt.handler, nil)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: NewServer = %v, %v; want an error with %q", tt.name, srv, err, tt.want)
		}
	}
}

func TestNewClient(t *testing.T) {
	broker, laptop, web := newTestKey(t), newTestKey(t), newTestKey(t)
	for _, tt := range []struct {
		name string
		addr string
		key  tls.Certificate
		pin  config.Pin
		want string
	}{
		{"no port", "192.0.2.10", laptop.cert, broker.pin, "a host and a port"},
		{"empty address", "", laptop.cert, broker.pin, "a host and a port"},
		{"the client's own pin", "192.0.2.10:7743", laptop.cert, laptop.pin, "own TLS key"},
		{"no certificate", "192.0.2.10:7743", tls.Certificate{PrivateKey: laptop.cert.PrivateKey}, broker.pin,
			"exactly one certificate"},
		{"no private key", "192.0.2.10:7743", tls.Certificate{Certificate: laptop.cert.Certificate}, broker.pin,
			"no private key"},
		{"the certificate of another key", "192.0.2.10:7743",
			tls.Certificate{Certificate: web.cert.Certificate, PrivateKey: laptop.cert.PrivateKey}, broker.pin,
			"not the key of its certificate"},
	} {
		c, err := NewClient(tt.addr, tt.key, tt.pin)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: NewClient = %v, %v; want an error with %q", tt.name, c, err, tt.want)
		}
	}

	b := startBroker(t, broker, clientTable(map[string]config.Pin{"laptop": laptop.pin, "web-1": web.pin}), nil)
	c := newTestClient(t, b, laptop, broker.pin)

	t.Run("it connects only to the broker", func(t *testing.T) {
		// A proxy in the environment is not used: the request goes
		// straight to the broker.
		t.Setenv("HTTPS_PROXY", "http://192.0.2.99:3128")
		t.Setenv("https_proxy", "http://192.0.2.99:3128")
		c := newTestClient(t, b, laptop, broker.pin)
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		// Another host in the URL: the client still connects to the
		// broker, and checks its pin.
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://example.com/whoami", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || resp.Proto != "HTTP/1.1" {
			t.Errorf("status %d, %s; want 200 over HTTP/1.1", resp.StatusCode, resp.Proto)
		}
	})

	t.Run("it never speaks plain HTTP", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+b.addr+"/whoami", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		if !errors.Is(err, errPlainHTTP) {
			t.Errorf("error = %v, want errPlainHTTP", err)
		}
	})

	t.Run("it does not follow redirects", func(t *testing.T) {
		redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://example.com/", http.StatusFound)
		})
		rb := (&testBroker{key: broker}).start(t, clientTable(map[string]config.Pin{"laptop": laptop.pin}), redirect, nil)
		c := newTestClient(t, rb, laptop, broker.pin)
		_, _, err := askState(t, c, rb.addr, nil)
		var se *statusError
		if !errors.As(err, &se) || se.status != http.StatusFound {
			t.Errorf("error = %v, want the redirect itself", err)
		}
	})
}
