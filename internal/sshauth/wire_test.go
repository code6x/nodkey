package sshauth

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// TestParseBind checks the form of a session-bind: every field, no bytes
// after the last one, and the lengths of the session identifier.
func TestParseBind(t *testing.T) {
	f := newFixture(t, ed25519Kind, ed25519Kind, methodPublicKey)
	good := f.binds[0]
	b, err := parseBind(good)
	if err != nil {
		t.Fatalf("parseBind: %v", err)
	}
	if !bytes.Equal(b.hostKey, f.host.PublicKey().Marshal()) || !bytes.Equal(b.sessionID, f.sid) || b.forwarding {
		t.Errorf("parseBind read the fields wrong: %+v", b)
	}
	// Every shorter prefix fails, and so does one more byte.
	for n := range len(good) {
		if _, err := parseBind(good[:n]); !errors.Is(err, ErrBadBind) {
			t.Fatalf("parseBind of the first %d bytes: %v; want %v", n, err, ErrBadBind)
		}
	}
	if _, err := parseBind(append(bytes.Clone(good), 0)); !errors.Is(err, ErrBadBind) {
		t.Errorf("parseBind with one more byte: %v; want %v", err, ErrBadBind)
	}
	for _, fwd := range []byte{0, 1, 2, 255} {
		in := bytes.Clone(good)
		in[len(in)-1] = fwd
		b, err := parseBind(in)
		switch {
		case fwd <= 1 && (err != nil || b.forwarding != (fwd == 1)):
			t.Errorf("is_forwarding %d: %+v, %v", fwd, b, err)
		case fwd > 1 && !errors.Is(err, ErrBadBind):
			t.Errorf("is_forwarding %d: %v; want %v", fwd, err, ErrBadBind)
		}
	}
	for _, n := range []int{0, 1, 20, 31, 32, 33, 47, 48, 63, 64, 65, 128} {
		in := marshalBind(b.hostKey, make([]byte, n), b.signature, false)
		_, err := parseBind(in)
		if ok := n == 32 || n == 48 || n == 64; ok != (err == nil) {
			t.Errorf("a session identifier of %d bytes: %v", n, err)
		}
	}
	if _, err := parseBind(make([]byte, MaxBindLen+1)); !errors.Is(err, ErrBadBind) {
		t.Errorf("a bind of %d bytes: %v; want %v", MaxBindLen+1, err, ErrBadBind)
	}
}

// TestParseData checks the form of the data to sign, for both methods.
func TestParseData(t *testing.T) {
	for _, method := range []string{methodPublicKey, methodHostbound} {
		f := newFixture(t, ed25519Kind, ed25519Kind, method)
		good := f.data.marshal()
		d, err := parseData(good)
		if err != nil {
			t.Fatalf("%s: parseData: %v", method, err)
		}
		if !bytes.Equal(d.sessionID, f.sid) || d.user != testUser || d.method != method ||
			d.algorithm != ssh.KeyAlgoED25519 || !bytes.Equal(d.key, f.key.PublicKey().Marshal()) {
			t.Errorf("%s: parseData read the fields wrong: %+v", method, d)
		}
		if method == methodHostbound && !bytes.Equal(d.hostKey, f.host.PublicKey().Marshal()) {
			t.Errorf("%s: the host key is wrong", method)
		}
		if method == methodPublicKey && d.hostKey != nil {
			t.Errorf("%s: a host key in publickey data", method)
		}
		for n := range len(good) {
			if _, err := parseData(good[:n]); !errors.Is(err, ErrNotLogin) {
				t.Fatalf("%s: parseData of the first %d bytes: %v; want %v", method, n, err, ErrNotLogin)
			}
		}
		if _, err := parseData(append(bytes.Clone(good), 0)); !errors.Is(err, ErrNotLogin) {
			t.Errorf("%s: parseData with one more byte: %v; want %v", method, err, ErrNotLogin)
		}
	}
	if _, err := parseData(make([]byte, MaxDataLen+1)); !errors.Is(err, ErrNotLogin) {
		t.Errorf("data of %d bytes: %v; want %v", MaxDataLen+1, err, ErrNotLogin)
	}
}

// TestParseSignature checks that a signature has two fields and nothing
// after them.
func TestParseSignature(t *testing.T) {
	good := ssh.Marshal(&ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: make([]byte, 64)})
	s, err := parseSignature(good)
	if err != nil || s.format != ssh.KeyAlgoED25519 || len(s.blob) != 64 {
		t.Fatalf("parseSignature: %+v, %v", s, err)
	}
	for n := range len(good) {
		if _, err := parseSignature(good[:n]); !errors.Is(err, ErrBadBind) {
			t.Fatalf("parseSignature of the first %d bytes: %v; want %v", n, err, ErrBadBind)
		}
	}
	// A security key signature has flags and a counter after the blob.
	sk := ssh.Marshal(&ssh.Signature{Format: ssh.KeyAlgoSKED25519, Blob: make([]byte, 64), Rest: []byte{1, 0, 0, 0, 7}})
	if _, err := parseSignature(sk); !errors.Is(err, ErrBadBind) {
		t.Errorf("parseSignature of a security key signature: %v; want %v", err, ErrBadBind)
	}
}

// FuzzParseBind checks that parseBind does not panic, and that it accepts
// only the exact form: what it reads, written again, is the input.
func FuzzParseBind(f *testing.F) {
	for _, hostKind := range []keyKind{ed25519Kind, ecdsa256, rsaKind} {
		fx := newFixture(f, ed25519Kind, hostKind, methodPublicKey)
		f.Add(fx.binds[0])
	}
	f.Add([]byte{})
	f.Add(make([]byte, 13))
	f.Fuzz(func(t *testing.T, in []byte) {
		b, err := parseBind(in)
		if err != nil {
			if b != nil || !errors.Is(err, ErrBadBind) {
				t.Fatalf("parseBind: %v, %v", b, err)
			}
			return
		}
		if !validSessionID(b.sessionID) {
			t.Fatalf("a session identifier of %d bytes", len(b.sessionID))
		}
		if out := marshalBind(b.hostKey, b.sessionID, b.signature, b.forwarding); !bytes.Equal(out, in) {
			t.Fatalf("parseBind accepted %x; written again it is %x", in, out)
		}
	})
}

// FuzzParseData checks that parseData does not panic, and that it accepts
// only the exact form: what it reads, written again, is the input.
func FuzzParseData(f *testing.F) {
	for _, method := range []string{methodPublicKey, methodHostbound} {
		fx := newFixture(f, ed25519Kind, ed25519Kind, method)
		f.Add(fx.data.marshal())
		fx = newFixture(f, rsaKind, rsaKind, method)
		f.Add(fx.data.marshal())
	}
	f.Add([]byte("SSHSIG"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, in []byte) {
		d, err := parseData(in)
		if err != nil {
			if d != nil || !errors.Is(err, ErrNotLogin) {
				t.Fatalf("parseData: %v, %v", d, err)
			}
			return
		}
		if !validSessionID(d.sessionID) {
			t.Fatalf("a session identifier of %d bytes", len(d.sessionID))
		}
		if d.method != methodPublicKey && d.method != methodHostbound {
			t.Fatalf("the method %q", d.method)
		}
		out := login{
			sessionID: d.sessionID, msg: msgUserAuthRequest, user: d.user, service: serviceConnection,
			method: d.method, hasSignature: 1, algorithm: d.algorithm, key: d.key, hostKey: d.hostKey,
		}.marshal()
		if !bytes.Equal(out, in) {
			t.Fatalf("parseData accepted %x; written again it is %x", in, out)
		}
	})
}

// FuzzCheck checks that Check does not panic on any request, refuses with
// a known error, and returns a Login only for a request that a person may
// approve: a valid user, a known host, the bound session, and data that
// Sign signs.
func FuzzCheck(f *testing.F) {
	// Both fixtures use the same test keys. The key may log in only to
	// web-1; known_hosts also has db-1.
	fx := newFixture(f, ed25519Kind, ed25519Kind, methodPublicKey)
	hb := newFixture(f, ed25519Kind, ed25519Kind, methodHostbound)
	key, hosts := newKey(f, "deploy", ed25519Kind, 0, "web-1"), fx.hosts
	for _, x := range []*fixture{fx, hb} {
		req := x.request()
		if _, err := key.Check(req, hosts); err != nil {
			f.Fatalf("a seed does not pass: %v", err)
		}
		f.Add(x.data.marshal(), x.binds[0], uint32(0), uint8(1))
		f.Add(x.data.marshal(), x.binds[0], uint32(agent.SignatureFlagRsaSha512), uint8(1))
		f.Add(x.data.marshal(), x.binds[0], uint32(0), uint8(2))
		f.Add(x.data.marshal(), x.binds[0], uint32(0), uint8(0))
	}
	// A valid bind of db-1 in the same session: refused by the hosts list.
	f.Add(fx.data.marshal(), signBind(f, fx.other, "", fx.sid, false), uint32(0), uint8(1))
	known := []error{ErrNotLogin, ErrWrongKey, ErrAlgorithm, ErrUser, ErrNoBind, ErrManyBinds, ErrBadBind,
		ErrForwarding, ErrBindSignature, ErrOtherSession, ErrOtherHost, ErrHostKeyType, ErrUnknownHost,
		ErrHostNotAllowed}
	f.Fuzz(func(t *testing.T, data, bind []byte, flags uint32, nbinds uint8) {
		binds := make([][]byte, int(nbinds%3))
		for i := range binds {
			binds[i] = bind
		}
		req := Request{Key: key.PublicKey().Marshal(), Data: data, Flags: agent.SignatureFlags(flags), Binds: binds}
		l, err := key.Check(req, hosts)
		if err != nil {
			if l != (Login{}) {
				t.Fatalf("a Login with the error %v", err)
			}
			for _, e := range known {
				if errors.Is(err, e) {
					if !strings.HasPrefix(err.Error(), "sshauth: ") {
						t.Fatalf("the error %q", err)
					}
					return
				}
			}
			t.Fatalf("an unknown error: %v", err)
		}
		// Check accepted it: every promise must hold.
		if !ValidUser(l.RemoteUser()) || l.KeyName() != "deploy" {
			t.Fatalf("a Login for %v", l)
		}
		if name, ok := hosts.NameFor(l.HostKey()); !ok || name != l.Host() {
			t.Fatalf("a Login for a host that is not known: %v", l)
		}
		if l.Host() != "web-1" {
			t.Fatalf("a Login for a host that is not in the key's hosts list: %v", l)
		}
		d, err := parseData(data)
		if err != nil {
			t.Fatalf("Check accepted data that parseData refuses: %v", err)
		}
		b, err := parseBind(bind)
		if err != nil || len(binds) != 1 || b.forwarding || !bytes.Equal(b.sessionID, d.sessionID) {
			t.Fatalf("Check accepted a request without one valid bind of its session: %v", err)
		}
		if d.hostbound() && !bytes.Equal(d.hostKey, b.hostKey) {
			t.Fatal("Check accepted hostbound data for another host key")
		}
		if flags != 0 {
			t.Fatalf("Check accepted flags %d for an Ed25519 key", flags)
		}
		sig, err := key.Sign(l)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := key.PublicKey().Verify(data, sig); err != nil {
			t.Fatalf("the signature is not over the data: %v", err)
		}
	})
}

// TestLimitsFitTheLargestRequest checks that MaxBindLen and MaxDataLen
// fit the largest valid session-bind and data to sign: RSA keys of 16384
// bits (the largest that OpenSSH and golang.org/x/crypto/ssh accept) for
// the user and the host, a session identifier of 64 bytes, a user name of
// 32 characters, and the hostbound method. DESIGN.md section 6 says that
// they have less than 5 KiB.
func TestLimitsFitTheLargestRequest(t *testing.T) {
	// The wire form of an RSA public key with a modulus of 16384 bits,
	// its top bit set, so it needs a zero byte in front, and the largest
	// exponent (24 bits). No private key is needed to measure it.
	n := make([]byte, 16384/8)
	for i := range n {
		n[i] = 0xff
	}
	rsaKey := ssh.Marshal(struct {
		Type string
		E    []byte
		N    []byte
	}{ssh.KeyAlgoRSA, []byte{0x00, 0xff, 0xff, 0xff}, append([]byte{0}, n...)})
	if _, err := ssh.ParsePublicKey(rsaKey); err != nil {
		t.Fatalf("the test key does not parse: %v", err)
	}
	sid := make([]byte, 64)
	sig := ssh.Marshal(&ssh.Signature{Format: ssh.KeyAlgoRSASHA512, Blob: n})
	bind := marshalBind(rsaKey, sid, sig, false)
	data := login{
		sessionID: sid, msg: msgUserAuthRequest, user: strings.Repeat("u", 32), service: serviceConnection,
		method: methodHostbound, hasSignature: 1, algorithm: ssh.KeyAlgoRSASHA512, key: rsaKey, hostKey: rsaKey,
	}.marshal()
	for name, b := range map[string][]byte{"session-bind": bind, "data to sign": data} {
		if len(b) >= 5<<10 {
			t.Errorf("the largest %s has %d bytes, not less than 5 KiB", name, len(b))
		}
	}
	if _, err := parseBind(bind); err != nil {
		t.Errorf("parseBind of the largest session-bind: %v", err)
	}
	if _, err := parseData(data); err != nil {
		t.Errorf("parseData of the largest data to sign: %v", err)
	}
	if MaxBindLen < 5<<10 || MaxDataLen < 5<<10 {
		t.Error("a limit is below 5 KiB")
	}
}
