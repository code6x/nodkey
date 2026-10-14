// Package sshauth checks an SSH signature request on the broker, and
// signs only a real SSH login to a known host (DESIGN.md section 6,
// THREAT-MODEL.md T12).
//
// The client, nodkey ssh-agent, forwards what ssh sent to the agent: the
// key, the data to sign, the sign flags, and the session-bind@openssh.com
// messages of that agent connection (a Request). The broker trusts none
// of it. Key.Check returns a Login only when all of these hold:
//
//   - The data to sign is an SSH login request with a public key (RFC 4252
//     section 7): the method is publickey or
//     publickey-hostbound-v00@openssh.com, the request has a signature,
//     and the service is ssh-connection. It has no bytes after the last
//     field.
//   - The key in the data is the key asked for, and that is this Key.
//   - The sign flags fit the key: RSA with SHA-256 or SHA-512, never
//     SHA-1. Ed25519 and ECDSA take no flags. The algorithm in the data
//     matches.
//   - The remote user name matches ValidUser.
//   - There is exactly one session-bind, and it is not for forwarding.
//   - The session identifier in the data is the bound one. For the
//     hostbound method, the host key in the data is the bound one too.
//   - The bound host key is in the broker's known_hosts file, which gives
//     the host name, and its signature over the session identifier is
//     valid.
//   - If the key has a hosts list, the host is in it.
//
// The broker shows the Login to the approver, writes the decision to the
// audit log, and only then calls Key.Sign with that Login. Sign takes
// nothing else, so it can sign only data that Check accepted:
//
//	login, err := key.Check(req, knownHosts)
//	if err != nil {
//		// deny
//	}
//	// show login.Host(), login.HostKeyFingerprint(), login.RemoteUser(),
//	// login.KeyName(); ask; write the decision to the audit log
//	sig, err := key.Sign(login)
//
// Errors have fixed texts. They never hold data from the request, so they
// are safe to log.
package sshauth

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/code6x/nodkey/internal/config"
)

// Limits on the data that Check reads. They are far above any valid
// request: with RSA keys of 16384 bits (the largest that OpenSSH and
// golang.org/x/crypto/ssh accept) and a session identifier of 64 bytes, a
// session-bind has about 4.3 KiB and the data to sign about 4.3 KiB.
const (
	// MaxBindLen is the longest content of one session-bind message.
	MaxBindLen = 8 << 10
	// MaxDataLen is the longest data to sign.
	MaxDataLen = 8 << 10
)

// Errors of Check and Sign. Check wraps them, some with a fixed detail, so
// use errors.Is. None holds data from the request.
var (
	// ErrNotLogin: the data to sign is not an SSH login request of the
	// kinds this package signs. Git commit signatures (SSHSIG), for
	// example, are refused with it.
	ErrNotLogin = errors.New("sshauth: the data to sign is not an SSH login request")
	// ErrWrongKey: the key asked for, or the key in the data to sign, is
	// not this Key.
	ErrWrongKey = errors.New("sshauth: the request is for another key")
	// ErrAlgorithm: the sign flags or the algorithm in the data to sign
	// do not fit the key, are unknown, or ask for RSA with SHA-1.
	ErrAlgorithm = errors.New("sshauth: the signature algorithm or the sign flags are not allowed")
	// ErrUser: the remote user name does not match ValidUser.
	ErrUser = errors.New("sshauth: the remote user name is not allowed")
	// ErrNoBind: the request has no session-bind. OpenSSH sends one from
	// version 8.9. Clients without it are not supported.
	ErrNoBind = errors.New("sshauth: the request has no session-bind; ssh must be OpenSSH 8.9 or newer")
	// ErrManyBinds: the agent connection has more than one session-bind,
	// as with agent forwarding, which is not supported.
	ErrManyBinds = errors.New("sshauth: the request has more than one session-bind; agent forwarding is not supported")
	// ErrBadBind: the session-bind does not have the right form.
	ErrBadBind = errors.New("sshauth: the session-bind is not valid")
	// ErrForwarding: the session-bind is for agent forwarding.
	ErrForwarding = errors.New("sshauth: the session-bind is for agent forwarding, which is not supported")
	// ErrBindSignature: the host key's signature over the session
	// identifier is not valid, or uses an algorithm that is not allowed.
	ErrBindSignature = errors.New("sshauth: the host key's signature over the session identifier is not valid")
	// ErrOtherSession: the data to sign is for another session than the
	// bound one.
	ErrOtherSession = errors.New("sshauth: the data to sign is for another session")
	// ErrOtherHost: the host key in hostbound data to sign is not the
	// bound host key.
	ErrOtherHost = errors.New("sshauth: the host key in the data to sign is not the bound host key")
	// ErrHostKeyType: the bound host key is a certificate, or not an
	// Ed25519, ECDSA or RSA key.
	ErrHostKeyType = errors.New("sshauth: the host key type is not allowed; only plain Ed25519, ECDSA and RSA host keys are")
	// ErrUnknownHost: the bound host key is not in the broker's
	// known_hosts file.
	ErrUnknownHost = errors.New("sshauth: the host key is not in the broker's known_hosts")
	// ErrHostNotAllowed: the key has a hosts list, and the host is not in
	// it.
	ErrHostNotAllowed = errors.New("sshauth: the host is not in the hosts list of the key")
	// ErrNotChecked: Sign got a Login that this Key did not check.
	ErrNotChecked = errors.New("sshauth: the login was not checked with this key")
	// ErrSign: the key could not make a valid signature.
	ErrSign = errors.New("sshauth: the key could not sign")
)

// userPattern is the rule for remote user names (DESIGN.md section 6). The
// name is shown as verified, so it holds no space, markup or other text.
var userPattern = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._-]{0,31}$`)

// ValidUser reports whether name is a remote user name that the broker
// accepts: it matches [A-Za-z0-9._][A-Za-z0-9._-]{0,31}.
func ValidUser(name string) bool { return userPattern.MatchString(name) }

// keyNamePattern is the name rule of the config (DESIGN.md section 14).
// The key name is shown as verified, so NewKey checks it again.
var keyNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// minRSABits is the smallest RSA key that NewKey accepts.
const minRSABits = 2048

// Key is one SSH private key of the broker, with its name from the
// config. It signs only a Login that its own Check returned. The zero Key
// has no private key and refuses everything. A Key is a small handle:
// copies share the private key. It is safe for use by many goroutines.
// String and Format show only the name and the fingerprint, and no other
// form of printing reaches the private key.
type Key struct {
	s *keyState
}

// keyState is the content of a Key. Key holds it behind a pointer, so
// that printing a Key, even inside another struct and with any verb,
// never shows the private key.
type keyState struct {
	name   string
	hosts  []string // the hosts it may log in to; empty means any known host
	pub    ssh.PublicKey
	blob   []byte // pub in SSH wire form
	signer ssh.AlgorithmSigner
}

// NewKey makes a Key from a private key and the settings of its [key.*]
// section in the config: its name, and its hosts list. The key may log in
// only to the hosts in that list, by their names in the broker's
// known_hosts file. An empty list means any host in that file.
//
// The key must be Ed25519, ECDSA on P-256, P-384 or P-521, or RSA with at
// least 2048 bits. NewKey signs a fixed text with each algorithm that Sign
// may use, and checks the signatures, so a key that cannot sign is
// refused at start and not after an approval. These signatures never
// leave NewKey. The names must follow the name rule of the config. The
// error never holds key material.
func NewKey(name string, private crypto.Signer, hosts []string) (Key, error) {
	if !keyNamePattern.MatchString(name) {
		return Key{}, errors.New("sshauth: the key name does not follow the name rule of the config")
	}
	for _, h := range hosts {
		if !keyNamePattern.MatchString(h) {
			return Key{}, errors.New("sshauth: a name in the hosts list of the key does not follow the name rule of the config")
		}
	}
	if private == nil {
		return Key{}, errors.New("sshauth: no private key")
	}
	// A wrong Ed25519 key would make Sign panic, after the approval.
	errEd25519 := errors.New("sshauth: the Ed25519 private key does not have 64 bytes")
	switch k := private.(type) {
	case ed25519.PrivateKey:
		if len(k) != ed25519.PrivateKeySize {
			return Key{}, errEd25519
		}
		// An ed25519.PrivateKey is a slice. Behind a pointer, fmt prints
		// it as an address, never as bytes.
		private = &k
	case *ed25519.PrivateKey: // as ssh.ParseRawPrivateKey returns it
		if k == nil || len(*k) != ed25519.PrivateKeySize {
			return Key{}, errEd25519
		}
	}
	if rsaKey, ok := private.Public().(*rsa.PublicKey); ok && rsaKey.N.BitLen() < minRSABits {
		return Key{}, fmt.Errorf("sshauth: the RSA key has fewer than %d bits", minRSABits)
	}
	s, err := ssh.NewSignerFromSigner(private)
	if err != nil {
		return Key{}, errors.New("sshauth: the private key is not an SSH key of a supported type")
	}
	signer, ok := s.(ssh.AlgorithmSigner)
	if !ok {
		return Key{}, errors.New("sshauth: the private key cannot choose a signature algorithm")
	}
	pub := signer.PublicKey()
	switch pub.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSA:
	default:
		return Key{}, errors.New("sshauth: the private key is not an Ed25519, ECDSA or RSA key")
	}
	if !canSign(signer, pub) {
		return Key{}, errors.New("sshauth: the private key cannot make a valid signature; " +
			"its public half may not belong to it")
	}
	return Key{&keyState{name: name, hosts: slices.Clone(hosts), pub: pub, blob: pub.Marshal(), signer: signer}}, nil
}

// checkText is the text that NewKey signs to check a key. It is not an
// SSH login, and the signatures over it never leave NewKey.
const checkText = "nodkey: check that this key can sign"

// signatureAlgorithms returns the signature algorithms that Sign may use
// for a key of this type.
func signatureAlgorithms(keyType string) []string {
	if keyType == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512}
	}
	return []string{keyType}
}

// canSign reports whether signer makes valid signatures for pub with each
// algorithm that Sign may use.
func canSign(signer ssh.AlgorithmSigner, pub ssh.PublicKey) bool {
	for _, algorithm := range signatureAlgorithms(pub.Type()) {
		sig, err := signer.SignWithAlgorithm(rand.Reader, []byte(checkText), algorithm)
		if err != nil || sig.Format != algorithm || len(sig.Rest) != 0 || pub.Verify([]byte(checkText), sig) != nil {
			return false
		}
	}
	return true
}

// Name returns the key's name from the config.
func (k Key) Name() string {
	if k.s == nil {
		return ""
	}
	return k.s.name
}

// PublicKey returns the key's public key.
func (k Key) PublicKey() ssh.PublicKey {
	if k.s == nil {
		return nil
	}
	return k.s.pub
}

// String returns the key's name and fingerprint.
func (k Key) String() string {
	if k.s == nil {
		return "sshauth.Key(none)"
	}
	return "sshauth.Key(" + k.s.name + " " + ssh.FingerprintSHA256(k.s.pub) + ")"
}

// Format writes the same as String for every verb.
func (k Key) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, k.String()) }

// Request is one signature request, as the client forwards it from ssh
// (DESIGN.md section 6, step 5). Nothing in it is trusted.
type Request struct {
	// Key is the public key that ssh asked the agent to sign with, in
	// SSH wire form.
	Key []byte
	// Data is the data that ssh asked the agent to sign.
	Data []byte
	// Flags are the flags of the agent's sign request.
	Flags agent.SignatureFlags
	// Binds are the contents of every session-bind@openssh.com message
	// that ssh sent on that agent connection, in order. Each is the
	// message after the extension name: string hostkey, string session
	// identifier, string signature, bool is_forwarding.
	Binds [][]byte
}

// Login is a sign request that passed every check of Key.Check: an SSH
// login as one remote user, to one host in the broker's known_hosts, in
// one session. Only Check makes a valid Login; the zero Login is not
// valid, and its methods return empty values. It holds only checked data,
// ready to show and to log. String and Format do not show the data to
// sign.
type Login struct {
	c *checked
}

// checked is the content of a valid Login. Login holds it behind a
// pointer, and it holds the data to sign behind one more, so that no form
// of printing shows that data.
type checked struct {
	key         *keyState // the key that checked it
	host        string
	hostKey     string // the host key in SSH wire form: a private copy
	fingerprint string // of hostKey
	user        string
	hostbound   bool
	sign        *toSign
}

// toSign is what Sign signs.
type toSign struct {
	algorithm string // the signature algorithm, from the flags
	data      []byte // a copy of the checked data to sign
}

// KeyName returns the name of the key in the config.
func (l Login) KeyName() string {
	if l.c == nil {
		return ""
	}
	return l.c.key.name
}

// Host returns the host name from the broker's known_hosts file.
func (l Login) Host() string {
	if l.c == nil {
		return ""
	}
	return l.c.host
}

// HostKey returns the host key, which the broker found in its known_hosts
// file. Grants match on it. Each call returns a new copy, so a change to
// it, or to the request after Check, does not change the Login.
func (l Login) HostKey() ssh.PublicKey {
	if l.c == nil {
		return nil
	}
	k, err := ssh.ParsePublicKey([]byte(l.c.hostKey))
	if err != nil {
		return nil // never: Check parsed the same bytes
	}
	return k
}

// HostKeyFingerprint returns the SHA256 fingerprint of the host key, as
// OpenSSH shows it: "SHA256:" and 43 base64 characters.
func (l Login) HostKeyFingerprint() string {
	if l.c == nil {
		return ""
	}
	return l.c.fingerprint
}

// RemoteUser returns the remote user name. It matches ValidUser.
func (l Login) RemoteUser() string {
	if l.c == nil {
		return ""
	}
	return l.c.user
}

// String returns the login as "USER@HOST (host key FINGERPRINT) with key
// NAME". It does not show the data to sign.
func (l Login) String() string {
	if l.c == nil {
		return "sshauth.Login(none)"
	}
	return l.c.user + "@" + l.c.host + " (host key " + l.HostKeyFingerprint() + ") with key " + l.c.key.name
}

// Format writes the same as String for every verb.
func (l Login) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, l.String()) }

// Check checks a sign request for this key against the broker's
// known_hosts file. It returns a Login only if every check in the package
// comment passes; on any failure it returns an error and the zero Login.
// A nil hosts knows no host, so every request fails.
func (k Key) Check(req Request, hosts *config.KnownHosts) (Login, error) {
	if k.s == nil {
		return Login{}, errors.New("sshauth: no key")
	}
	if !bytes.Equal(req.Key, k.s.blob) {
		return Login{}, ErrWrongKey
	}
	d, err := parseData(req.Data)
	if err != nil {
		return Login{}, err
	}
	if !bytes.Equal(d.key, k.s.blob) {
		return Login{}, fmt.Errorf("%w: the key in the data to sign is another key", ErrWrongKey)
	}
	algorithm, err := k.algorithm(d.algorithm, req.Flags)
	if err != nil {
		return Login{}, err
	}
	if !ValidUser(d.user) {
		return Login{}, ErrUser
	}
	switch len(req.Binds) {
	case 0:
		return Login{}, ErrNoBind
	case 1:
	default:
		return Login{}, ErrManyBinds
	}
	b, err := parseBind(req.Binds[0])
	if err != nil {
		return Login{}, err
	}
	if b.forwarding {
		return Login{}, ErrForwarding
	}
	if !bytes.Equal(d.sessionID, b.sessionID) {
		return Login{}, ErrOtherSession
	}
	if d.hostbound() && !bytes.Equal(d.hostKey, b.hostKey) {
		return Login{}, ErrOtherHost
	}
	hostKey, host, err := checkBind(b, hosts)
	if err != nil {
		return Login{}, err
	}
	if len(k.s.hosts) > 0 && !slices.Contains(k.s.hosts, host) {
		return Login{}, ErrHostNotAllowed
	}
	return Login{&checked{
		key:         k.s,
		host:        host,
		hostKey:     string(hostKey.Marshal()),
		fingerprint: ssh.FingerprintSHA256(hostKey),
		user:        d.user,
		hostbound:   d.hostbound(),
		sign:        &toSign{algorithm: algorithm, data: bytes.Clone(req.Data)},
	}}, nil
}

// algorithm checks the public key algorithm name in the data to sign and
// the sign flags against the key. It returns the signature algorithm.
//
// For RSA, the flags pick SHA-256 or SHA-512, and the name in the data
// must be the same algorithm. No flag means SHA-1 ("ssh-rsa"), which is
// refused. Ed25519 and ECDSA keys have one algorithm and take no flags.
func (k Key) algorithm(name string, flags agent.SignatureFlags) (string, error) {
	if k.s.pub.Type() != ssh.KeyAlgoRSA {
		switch {
		case flags != 0:
			return "", fmt.Errorf("%w: this key type takes no sign flags", ErrAlgorithm)
		case name != k.s.pub.Type():
			return "", fmt.Errorf("%w: the algorithm in the data to sign is not the key's", ErrAlgorithm)
		}
		return name, nil
	}
	var want string
	switch flags {
	case agent.SignatureFlagRsaSha256:
		want = ssh.KeyAlgoRSASHA256
	case agent.SignatureFlagRsaSha512:
		want = ssh.KeyAlgoRSASHA512
	case 0:
		return "", fmt.Errorf("%w: RSA signatures with SHA-1 are not allowed", ErrAlgorithm)
	default:
		return "", fmt.Errorf("%w: unknown sign flags", ErrAlgorithm)
	}
	if name != want {
		return "", fmt.Errorf("%w: the algorithm in the data to sign does not match the sign flags", ErrAlgorithm)
	}
	return want, nil
}

// bindSignatureFormats are the signature formats allowed in a session-bind
// for each host key type. RSA is allowed only with SHA-2.
var bindSignatureFormats = map[string][]string{
	ssh.KeyAlgoED25519:  {ssh.KeyAlgoED25519},
	ssh.KeyAlgoECDSA256: {ssh.KeyAlgoECDSA256},
	ssh.KeyAlgoECDSA384: {ssh.KeyAlgoECDSA384},
	ssh.KeyAlgoECDSA521: {ssh.KeyAlgoECDSA521},
	ssh.KeyAlgoRSA:      {ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512},
}

// checkBind checks the host key of a session-bind and the host key's
// signature over the session identifier. It returns the host key and the
// host's name in hosts.
//
// The host key must be a plain key in its usual wire form: a certificate
// is not in the broker's known_hosts file. The broker's own file names the
// host, never anything the client sent.
func checkBind(b *sessionBind, hosts *config.KnownHosts) (ssh.PublicKey, string, error) {
	// Parse a copy: some key types keep the bytes they were parsed from,
	// and the request belongs to the caller.
	hostKey, err := ssh.ParsePublicKey(bytes.Clone(b.hostKey))
	if err != nil {
		return nil, "", fmt.Errorf("%w: the host key is not a valid SSH public key", ErrBadBind)
	}
	if !bytes.Equal(hostKey.Marshal(), b.hostKey) {
		return nil, "", fmt.Errorf("%w: the host key is not in its usual wire form", ErrBadBind)
	}
	if _, ok := hostKey.(*ssh.Certificate); ok {
		return nil, "", fmt.Errorf("%w: it is a host certificate", ErrHostKeyType)
	}
	formats, ok := bindSignatureFormats[hostKey.Type()]
	if !ok {
		return nil, "", ErrHostKeyType
	}
	host, ok := hosts.NameFor(hostKey)
	if !ok {
		return nil, "", ErrUnknownHost
	}
	sig, err := parseSignature(b.signature)
	if err != nil {
		return nil, "", err
	}
	switch {
	case sig.format == ssh.KeyAlgoRSA:
		return nil, "", fmt.Errorf("%w: RSA signatures with SHA-1 are not allowed", ErrBindSignature)
	case !slices.Contains(formats, sig.format):
		return nil, "", fmt.Errorf("%w: the signature type does not match the host key", ErrBindSignature)
	}
	if err := hostKey.Verify(b.sessionID, &ssh.Signature{Format: sig.format, Blob: sig.blob}); err != nil {
		return nil, "", ErrBindSignature
	}
	return hostKey, host, nil
}

// Sign signs a Login that this Key's Check returned, with the algorithm
// that the sign flags chose. It signs nothing else. It checks the new
// signature before it returns it. The result is the signature for the
// agent's sign response.
func (k Key) Sign(l Login) (*ssh.Signature, error) {
	if k.s == nil || l.c == nil || l.c.key != k.s {
		return nil, ErrNotChecked
	}
	ts := l.c.sign
	sig, err := k.s.signer.SignWithAlgorithm(rand.Reader, ts.data, ts.algorithm)
	if err != nil {
		return nil, ErrSign
	}
	if sig.Format != ts.algorithm || len(sig.Rest) != 0 || k.s.pub.Verify(ts.data, sig) != nil {
		return nil, ErrSign
	}
	return sig, nil
}
