package sshauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/code6x/nodkey/internal/config"
)

// keyKind names a type of test key.
type keyKind string

const (
	ed25519Kind keyKind = "ed25519"
	ecdsa256    keyKind = "ecdsa-p256"
	ecdsa384    keyKind = "ecdsa-p384"
	ecdsa521    keyKind = "ecdsa-p521"
	rsaKind     keyKind = "rsa-2048"
)

// testKeys holds the private keys that tests made, by kind and number.
// Making RSA keys is slow, so each key is made once per test binary. The
// keys exist only in memory.
var testKeys = struct {
	sync.Mutex
	m map[keyKind][]crypto.Signer
}{m: make(map[keyKind][]crypto.Signer)}

// privateKey returns test key number n of this kind. The same kind and
// number give the same key; other numbers give other keys.
func privateKey(t testing.TB, kind keyKind, n int) crypto.Signer {
	t.Helper()
	testKeys.Lock()
	defer testKeys.Unlock()
	for len(testKeys.m[kind]) <= n {
		var (
			key crypto.Signer
			err error
		)
		switch kind {
		case ed25519Kind:
			_, key, err = ed25519.GenerateKey(rand.Reader)
		case ecdsa256:
			key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case ecdsa384:
			key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case ecdsa521:
			key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		case rsaKind:
			key, err = rsa.GenerateKey(rand.Reader, 2048)
		default:
			t.Fatalf("unknown key kind %q", kind)
		}
		if err != nil {
			t.Fatal(err)
		}
		testKeys.m[kind] = append(testKeys.m[kind], key)
	}
	return testKeys.m[kind][n]
}

// newKey returns a broker Key named name, with test key n of this kind.
// It may log in to the hosts given, or to any known host if none are.
func newKey(t testing.TB, name string, kind keyKind, n int, hosts ...string) Key {
	t.Helper()
	k, err := NewKey(name, privateKey(t, kind, n), hosts)
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	return k
}

// hostSigner returns test key n of this kind as an SSH host key.
func hostSigner(t testing.TB, kind keyKind, n int) ssh.AlgorithmSigner {
	t.Helper()
	s, err := ssh.NewSignerFromSigner(privateKey(t, kind, n))
	if err != nil {
		t.Fatal(err)
	}
	as, ok := s.(ssh.AlgorithmSigner)
	if !ok {
		t.Fatal("the signer cannot choose an algorithm")
	}
	return as
}

// knownHosts returns a broker known_hosts file with these hosts, made
// with the config package's own parser.
func knownHosts(t testing.TB, hosts map[string]ssh.PublicKey) *config.KnownHosts {
	t.Helper()
	var b strings.Builder
	for name, key := range hosts {
		b.WriteString(name + " " + string(ssh.MarshalAuthorizedKey(key)))
	}
	k, err := config.ParseKnownHosts([]byte(b.String()))
	if err != nil {
		t.Fatalf("ParseKnownHosts: %v", err)
	}
	return k
}

// newSessionID returns a random session identifier of n bytes.
func newSessionID(t testing.TB, n int) []byte {
	t.Helper()
	id := make([]byte, n)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return id
}

// marshalBind returns the content of a session-bind@openssh.com message,
// as OpenSSH writes it.
func marshalBind(hostKey, sessionID, signature []byte, forwarding bool) []byte {
	return ssh.Marshal(struct {
		HostKey    []byte
		SessionID  []byte
		Signature  []byte
		Forwarding bool
	}{hostKey, sessionID, signature, forwarding})
}

// signBind returns a session-bind for host's key and sessionID, with the
// host key's signature over sessionID: what the server sends in the key
// exchange, and what OpenSSH puts in the session-bind. algorithm "" is
// the key's default algorithm.
func signBind(t testing.TB, host ssh.AlgorithmSigner, algorithm string, sessionID []byte, forwarding bool) []byte {
	t.Helper()
	sig, err := host.SignWithAlgorithm(rand.Reader, sessionID, algorithm)
	if err != nil {
		t.Fatal(err)
	}
	return marshalBind(host.PublicKey().Marshal(), sessionID, ssh.Marshal(sig), forwarding)
}

// login holds the fields of the data to sign for a login (RFC 4252
// section 7, and OpenSSH's hostbound method).
type login struct {
	sessionID    []byte
	msg          byte
	user         string
	service      string
	method       string
	hasSignature byte
	algorithm    string
	key          []byte
	hostKey      []byte // written only for the hostbound method
}

// marshal returns the data to sign, as ssh writes it.
func (d login) marshal() []byte {
	b := ssh.Marshal(struct {
		SessionID []byte
		Msg       byte
		User      string
		Service   string
		Method    string
	}{d.sessionID, d.msg, d.user, d.service, d.method})
	b = append(b, d.hasSignature)
	b = append(b, ssh.Marshal(struct {
		Algorithm string
		Key       []byte
	}{d.algorithm, d.key})...)
	if d.method == methodHostbound {
		b = append(b, ssh.Marshal(struct{ HostKey []byte }{d.hostKey})...)
	}
	return b
}

// fixture is a valid sign request and everything needed to check it. A
// test changes one part and checks that Check refuses the request.
type fixture struct {
	key   Key                 // the broker's key "deploy"
	host  ssh.AlgorithmSigner // the host key of web-1
	other ssh.AlgorithmSigner // the host key of db-1
	hosts *config.KnownHosts  // web-1 and db-1
	sid   []byte              // the session identifier
	data  login
	flags agent.SignatureFlags
	binds [][]byte
}

// testUser is the remote user of the fixtures. It is unusual on purpose,
// so a test can check that no error repeats it.
const testUser = "Cx7deploy"

// newFixture returns a valid request to sign with a key of this kind, to
// log in to web-1 with this method. web-1's host key is of hostKind.
func newFixture(t testing.TB, kind keyKind, hostKind keyKind, method string) *fixture {
	t.Helper()
	f := &fixture{
		key:   newKey(t, "deploy", kind, 0),
		host:  hostSigner(t, hostKind, 1),
		other: hostSigner(t, ed25519Kind, 2),
		sid:   newSessionID(t, 32),
	}
	f.hosts = knownHosts(t, map[string]ssh.PublicKey{"web-1": f.host.PublicKey(), "db-1": f.other.PublicKey()})
	algorithm := f.key.PublicKey().Type()
	if algorithm == ssh.KeyAlgoRSA {
		algorithm = ssh.KeyAlgoRSASHA512
		f.flags = agent.SignatureFlagRsaSha512
	}
	f.data = login{
		sessionID:    f.sid,
		msg:          msgUserAuthRequest,
		user:         testUser,
		service:      serviceConnection,
		method:       method,
		hasSignature: 1,
		algorithm:    algorithm,
		key:          f.key.PublicKey().Marshal(),
		hostKey:      f.host.PublicKey().Marshal(),
	}
	hostAlgorithm := ""
	if f.host.PublicKey().Type() == ssh.KeyAlgoRSA {
		hostAlgorithm = ssh.KeyAlgoRSASHA256
	}
	f.binds = [][]byte{signBind(t, f.host, hostAlgorithm, f.sid, false)}
	return f
}

// request returns the fixture's request.
func (f *fixture) request() Request {
	return Request{
		Key:   f.key.PublicKey().Marshal(),
		Data:  f.data.marshal(),
		Flags: f.flags,
		Binds: f.binds,
	}
}

// flagsFor returns the agent's sign flags for a signature algorithm, as
// OpenSSH and golang.org/x/crypto/ssh/agent send them.
func flagsFor(algorithm string) agent.SignatureFlags {
	switch algorithm {
	case ssh.KeyAlgoRSASHA256:
		return agent.SignatureFlagRsaSha256
	case ssh.KeyAlgoRSASHA512:
		return agent.SignatureFlagRsaSha512
	}
	return 0
}
