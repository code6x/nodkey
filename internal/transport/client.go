package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/code6x/nodkey/internal/config"
)

// Limits of the client's connections to the broker.
const (
	// dialTimeout is the time to connect to the broker, with the TLS
	// handshake.
	dialTimeout = 10 * time.Second
	// clientIdleTimeout closes an unused connection. It is shorter than
	// the broker's idleTimeout, so the client does not send a request on
	// a connection that the broker is closing.
	clientIdleTimeout = 30 * time.Second
	// maxResponseHeaderBytes is the most bytes of answer headers.
	maxResponseHeaderBytes = 64 << 10
)

// errPlainHTTP is the client's error for a URL that is not https.
var errPlainHTTP = errors.New("nodkey: the client talks to the broker only over TLS (https)")

// ClientTLSConfig returns the TLS config of a client: TLS 1.3 only, the
// client's own key, and the broker's key pinned. key is the client's key,
// from LoadKeyFile. broker is the pin of the broker's key (broker_pin in
// the client config).
//
// There is no certificate authority, so the usual check of the
// certificate chain and the host name is off (InsecureSkipVerify).
// VerifyConnection checks the pin instead. crypto/tls runs it on every
// connection, also with InsecureSkipVerify, and also on a resumed session.
// The client keeps no session and never offers to resume one (no session
// cache, and session tickets off), and VerifyConnection refuses a resumed
// session anyway.
func ClientTLSConfig(key tls.Certificate, broker config.Pin) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{key},
		InsecureSkipVerify: true, //nolint:gosec // G402: VerifyConnection checks the broker's pinned key on every connection.
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyBroker(cs, broker)
		},
		SessionTicketsDisabled: true,
		NextProtos:             []string{"http/1.1"},
		Renegotiation:          tls.RenegotiateNever,
	}
}

// NewClient returns an HTTP client for the broker at addr ("host:port",
// broker in the client config). key is the client's own key, from
// LoadKeyFile. broker is the pin of the broker's key.
//
// The client connects only to addr, whatever the host in a request's URL,
// only over TLS (ClientTLSConfig), and never through a proxy. It speaks
// HTTP/1.1. It does not follow redirects. It has no overall time limit,
// because the broker answers only after the approver taps a button: give
// each request a context with the time limit you need.
func NewClient(addr string, key tls.Certificate, broker config.Pin) (*http.Client, error) {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, errors.New(`the broker address must be a host and a port, such as "192.0.2.10:7743"`)
	}
	own, err := certificatePin(key)
	if err != nil {
		return nil, fmt.Errorf("the client's TLS key %w", err)
	}
	if own == broker {
		return nil, errors.New("broker_pin is the pin of the client's own TLS key; " +
			"use the pin that nodkey keygen printed for the broker's key")
	}
	dialer := &tls.Dialer{
		// The timeout covers the TLS handshake too.
		NetDialer: &net.Dialer{Timeout: dialTimeout},
		Config:    ClientTLSConfig(key, broker),
	}
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	transport := &http.Transport{
		Proxy: nil, // never a proxy, whatever HTTPS_PROXY says
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errPlainHTTP
		},
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", addr)
		},
		Protocols:              &protocols,
		IdleConnTimeout:        clientIdleTimeout,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
		// The broker sends small JSON answers; do not ask for gzip.
		DisableCompression: true,
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}
