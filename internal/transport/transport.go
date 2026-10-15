// Package transport is the connection between the client and the broker
// (DESIGN.md section 10): mutual TLS 1.3 with pinned keys, and HTTP/1.1
// with JSON on top of it.
//
// There is no certificate authority. Each side has its own Ed25519 key,
// made by nodkey keygen (GenerateKeyFile). Each side pins the other side's
// key: the SHA-256 of its SubjectPublicKeyInfo (PinOf). The certificate only
// carries the key. Its names and dates are not checked.
//
// The broker (NewServer) asks every client for a certificate and checks its
// pin in VerifyConnection, which runs on every connection. The pin gives
// the client name. Nothing else does: not the names in the certificate, and
// not the request. A handler gets the name only from ClientName, which
// reads what the TLS layer stored for the connection. Session tickets are
// off, so no connection skips the check, and both sides refuse a resumed
// session anyway.
//
// The client (NewClient, ClientTLSConfig) pins the broker's key the same
// way.
//
// A request body is strict JSON (ReadJSON): at most MaxRequestBody bytes,
// one object, no unknown or repeated keys, and nothing after it. An error
// answer to the client says only the HTTP status (WriteError). While a
// request waits for the approver, WriteProcessing can tell the client so,
// with an informational answer before the final one. An answer with secret
// values goes through WriteJSONBody, with bytes that the caller clears.
package transport

import (
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/code6x/nodkey/internal/config"
)

// ErrUnknownClient is the broker's error for a client whose key no
// [client.*] section pins.
var ErrUnknownClient = errors.New("nodkey: the client's TLS key is not pinned in the broker config")

// ErrBrokerKey is the client's error for a broker whose key is not the
// key in broker_pin.
var ErrBrokerKey = errors.New("nodkey: the broker's TLS key is not the pinned key")

// Errors of peerPin. They say what was wrong with the connection, never
// anything from a certificate.
var (
	errVersion   = errors.New("nodkey: the connection is not TLS 1.3")
	errResumed   = errors.New("nodkey: a resumed TLS session is not allowed; each connection needs a full handshake")
	errCertCount = errors.New("nodkey: the other side must send exactly one certificate")
)

// PinOf returns the pin of the key in cert: the SHA-256 of its DER
// SubjectPublicKeyInfo. This is the form that config.ParsePin reads and
// config.Pin.String writes.
func PinOf(cert *x509.Certificate) config.Pin {
	return sha256.Sum256(cert.RawSubjectPublicKeyInfo)
}

// peerPin makes the checks that both sides make on every connection, in
// VerifyConnection, and returns the pin of the other side's key. The
// connection must be TLS 1.3 and a full handshake: a resumed session would
// carry a certificate from an earlier connection. The other side must send
// exactly one certificate. Neither side sends a chain, as there is no
// certificate authority.
func peerPin(cs tls.ConnectionState) (config.Pin, error) {
	switch {
	case cs.Version != tls.VersionTLS13:
		return config.Pin{}, errVersion
	case cs.DidResume:
		return config.Pin{}, errResumed
	case len(cs.PeerCertificates) != 1:
		return config.Pin{}, errCertCount
	}
	return PinOf(cs.PeerCertificates[0]), nil
}

// verifyClient is the broker's check of a client in VerifyConnection. It
// returns the client's name and pin. The name comes only from the pin: it
// is the name of the [client.*] section that pins the client's key. With
// ErrUnknownClient, it returns the pin too, for the log.
func verifyClient(cs tls.ConnectionState, byPin map[config.Pin]string) (string, config.Pin, error) {
	pin, err := peerPin(cs)
	if err != nil {
		return "", config.Pin{}, err
	}
	name, ok := byPin[pin]
	if !ok {
		// The pin is not secret: it is the hash of a public key. It helps
		// to add a new client, or to see which key tried to connect.
		return "", pin, fmt.Errorf("%w: the key has the pin %s", ErrUnknownClient, pin)
	}
	return name, pin, nil
}

// verifyBroker is the client's check of the broker in VerifyConnection.
func verifyBroker(cs tls.ConnectionState, want config.Pin) error {
	pin, err := peerPin(cs)
	if err != nil {
		return err
	}
	if pin != want {
		return fmt.Errorf("%w: the broker's key has the pin %s, and broker_pin is %s", ErrBrokerKey, pin, want)
	}
	return nil
}

// certificatePin checks a key from LoadKeyFile or ParseKeyFile, for one
// side of a connection, and returns its pin. The key must hold exactly one
// certificate, and the private key of that certificate.
func certificatePin(key tls.Certificate) (config.Pin, error) {
	if len(key.Certificate) != 1 {
		return config.Pin{}, errors.New("must hold exactly one certificate; make the key file with nodkey keygen")
	}
	signer, ok := key.PrivateKey.(crypto.Signer)
	if !ok {
		return config.Pin{}, errors.New("has no private key; make the key file with nodkey keygen")
	}
	cert, err := x509.ParseCertificate(key.Certificate[0])
	if err != nil {
		return config.Pin{}, errors.New("its certificate cannot be read; make the key file with nodkey keygen")
	}
	pub, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(cert.PublicKey) {
		return config.Pin{}, errors.New("has a private key that is not the key of its certificate; " +
			"make the key file with nodkey keygen")
	}
	return PinOf(cert), nil
}
