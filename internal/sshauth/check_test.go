package sshauth

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// TestCheckAndSign checks and signs valid requests for every key type,
// with both methods and every host key type, and checks the result.
func TestCheckAndSign(t *testing.T) {
	type keyCase struct {
		kind  keyKind
		flags agent.SignatureFlags
	}
	keys := []keyCase{
		{ed25519Kind, 0},
		{ecdsa256, 0},
		{ecdsa384, 0},
		{ecdsa521, 0},
		{rsaKind, agent.SignatureFlagRsaSha256},
		{rsaKind, agent.SignatureFlagRsaSha512},
	}
	for _, kc := range keys {
		for _, hostKind := range []keyKind{ed25519Kind, ecdsa256, rsaKind} {
			for _, method := range []string{methodPublicKey, methodHostbound} {
				name := fmt.Sprintf("%s flags %d, host %s, %s", kc.kind, kc.flags, hostKind, method)
				t.Run(name, func(t *testing.T) {
					f := newFixture(t, kc.kind, hostKind, method)
					if kc.kind == rsaKind {
						f.flags = kc.flags
						f.data.algorithm = map[agent.SignatureFlags]string{
							agent.SignatureFlagRsaSha256: ssh.KeyAlgoRSASHA256,
							agent.SignatureFlagRsaSha512: ssh.KeyAlgoRSASHA512,
						}[kc.flags]
					}
					req := f.request()
					l, err := f.key.Check(req, f.hosts)
					if err != nil {
						t.Fatalf("Check: %v", err)
					}
					checkLogin(t, l, f, method == methodHostbound)
					sig, err := f.key.Sign(l)
					if err != nil {
						t.Fatalf("Sign: %v", err)
					}
					if sig.Format != f.data.algorithm {
						t.Errorf("the signature has the format %q; want %q", sig.Format, f.data.algorithm)
					}
					if err := f.key.PublicKey().Verify(req.Data, sig); err != nil {
						t.Errorf("the signature does not verify: %v", err)
					}
				})
			}
		}
	}
}

// checkLogin checks the fields of a Login for the fixture f.
func checkLogin(t *testing.T, l Login, f *fixture, hostbound bool) {
	t.Helper()
	if got := l.KeyName(); got != "deploy" {
		t.Errorf("KeyName() = %q; want deploy", got)
	}
	if got := l.Host(); got != "web-1" {
		t.Errorf("Host() = %q; want web-1", got)
	}
	if got := l.RemoteUser(); got != testUser {
		t.Errorf("RemoteUser() = %q; want %q", got, testUser)
	}
	if !bytes.Equal(l.HostKey().Marshal(), f.host.PublicKey().Marshal()) {
		t.Error("HostKey() is not web-1's host key")
	}
	if got, want := l.HostKeyFingerprint(), ssh.FingerprintSHA256(f.host.PublicKey()); got != want {
		t.Errorf("HostKeyFingerprint() = %q; want %q", got, want)
	}
	if l.c.hostbound != hostbound {
		t.Errorf("hostbound = %v; want %v", l.c.hostbound, hostbound)
	}
}

// TestCheckRefuses checks that Check refuses every kind of request that
// DESIGN.md section 6 refuses, and that the error does not repeat the
// request.
func TestCheckRefuses(t *testing.T) {
	tests := []struct {
		name     string
		kind     keyKind // the broker's key; default Ed25519
		hostKind keyKind // web-1's host key; default Ed25519
		method   string  // default publickey
		change   func(t *testing.T, f *fixture, req *Request)
		want     error
	}{
		// The key.
		{
			name: "wrong key asked for",
			change: func(t *testing.T, f *fixture, req *Request) {
				req.Key = newKey(t, "other", ed25519Kind, 3).PublicKey().Marshal()
			},
			want: ErrWrongKey,
		},
		{
			name: "no key asked for",
			change: func(_ *testing.T, _ *fixture, req *Request) {
				req.Key = nil
			},
			want: ErrWrongKey,
		},
		{
			name: "another key in the data to sign",
			change: func(t *testing.T, f *fixture, req *Request) {
				f.data.key = newKey(t, "other", ed25519Kind, 3).PublicKey().Marshal()
				req.Data = f.data.marshal()
			},
			want: ErrWrongKey,
		},
		{
			name: "a certificate of the key in the data to sign",
			change: func(t *testing.T, f *fixture, req *Request) {
				f.data.key = newCert(t, f.key.PublicKey()).Marshal()
				f.data.algorithm = ssh.CertAlgoED25519v01
				req.Data = f.data.marshal()
			},
			want: ErrWrongKey,
		},

		// The session-bind.
		{
			name: "no bind",
			change: func(_ *testing.T, _ *fixture, req *Request) {
				req.Binds = nil
			},
			want: ErrNoBind,
		},
		{
			name: "two binds, the same",
			change: func(_ *testing.T, f *fixture, req *Request) {
				req.Binds = [][]byte{f.binds[0], f.binds[0]}
			},
			want: ErrManyBinds,
		},
		{
			name: "two binds: forwarding to web-1, then a login to db-1",
			change: func(t *testing.T, f *fixture, req *Request) {
				req.Binds = [][]byte{
					signBind(t, f.host, "", newSessionID(t, 32), true),
					signBind(t, f.other, "", f.sid, false),
				}
			},
			want: ErrManyBinds,
		},
		{
			name: "forwarding bind",
			change: func(t *testing.T, f *fixture, req *Request) {
				req.Binds = [][]byte{signBind(t, f.host, "", f.sid, true)}
			},
			want: ErrForwarding,
		},
		{
			name: "is_forwarding is 2",
			change: func(_ *testing.T, f *fixture, req *Request) {
				b := bytes.Clone(f.binds[0])
				b[len(b)-1] = 2
				req.Binds = [][]byte{b}
			},
			want: ErrBadBind,
		},
		{
			name: "bad bind signature: signed by another host key",
			change: func(t *testing.T, f *fixture, req *Request) {
				sig, err := f.other.Sign(rand.Reader, f.sid)
				if err != nil {
					t.Fatal(err)
				}
				req.Binds = [][]byte{marshalBind(f.host.PublicKey().Marshal(), f.sid, ssh.Marshal(sig), false)}
			},
			want: ErrBindSignature,
		},
		{
			name: "bad bind signature: over another session identifier",
			change: func(t *testing.T, f *fixture, req *Request) {
				sig, err := f.host.Sign(rand.Reader, newSessionID(t, 32))
				if err != nil {
					t.Fatal(err)
				}
				req.Binds = [][]byte{marshalBind(f.host.PublicKey().Marshal(), f.sid, ssh.Marshal(sig), false)}
			},
			want: ErrBindSignature,
		},
		{
			name: "bad bind signature: one bit changed",
			change: func(t *testing.T, f *fixture, req *Request) {
				sig, err := f.host.Sign(rand.Reader, f.sid)
				if err != nil {
					t.Fatal(err)
				}
				sig.Blob[10] ^= 1
				req.Binds = [][]byte{marshalBind(f.host.PublicKey().Marshal(), f.sid, ssh.Marshal(sig), false)}
			},
			want: ErrBindSignature,
		},
		{
			name: "bad bind signature: the format of another key type",
			change: func(t *testing.T, f *fixture, req *Request) {
				sig, err := f.host.Sign(rand.Reader, f.sid)
				if err != nil {
					t.Fatal(err)
				}
				sig.Format = ssh.KeyAlgoECDSA256
				req.Binds = [][]byte{marshalBind(f.host.PublicKey().Marshal(), f.sid, ssh.Marshal(sig), false)}
			},
			want: ErrBindSignature,
		},
		{
			name:     "bind signed with RSA and SHA-1",
			hostKind: rsaKind,
			change: func(t *testing.T, f *fixture, req *Request) {
				req.Binds = [][]byte{signBind(t, f.host, ssh.KeyAlgoRSA, f.sid, false)}
			},
			want: ErrBindSignature,
		},
		{
			name: "bind signature with bytes after the blob",
			change: func(t *testing.T, f *fixture, req *Request) {
				sig, err := f.host.Sign(rand.Reader, f.sid)
				if err != nil {
					t.Fatal(err)
				}
				sig.Rest = []byte{0}
				req.Binds = [][]byte{marshalBind(f.host.PublicKey().Marshal(), f.sid, ssh.Marshal(sig), false)}
			},
			want: ErrBadBind,
		},
		{
			name: "other session",
			change: func(t *testing.T, f *fixture, req *Request) {
				f.data.sessionID = newSessionID(t, 32)
				req.Data = f.data.marshal()
			},
			want: ErrOtherSession,
		},
		{
			name: "other session: one more byte in the session identifier",
			change: func(t *testing.T, f *fixture, req *Request) {
				sid := newSessionID(t, 48)
				copy(sid, f.sid)
				req.Binds = [][]byte{signBind(t, f.host, "", sid, false)}
			},
			want: ErrOtherSession,
		},
		{
			name: "unknown host key",
			change: func(t *testing.T, f *fixture, req *Request) {
				req.Binds = [][]byte{signBind(t, hostSigner(t, ed25519Kind, 4), "", f.sid, false)}
			},
			want: ErrUnknownHost,
		},
		{
			name: "host certificate",
			change: func(t *testing.T, f *fixture, req *Request) {
				cert := newCert(t, f.host.PublicKey())
				sig, err := f.host.Sign(rand.Reader, f.sid)
				if err != nil {
					t.Fatal(err)
				}
				req.Binds = [][]byte{marshalBind(cert.Marshal(), f.sid, ssh.Marshal(sig), false)}
			},
			want: ErrHostKeyType,
		},
		{
			name: "host key of a security key type",
			change: func(t *testing.T, f *fixture, req *Request) {
				ck, ok := f.host.PublicKey().(ssh.CryptoPublicKey)
				if !ok {
					t.Fatal("not a crypto key")
				}
				ed, ok := ck.CryptoPublicKey().(ed25519.PublicKey)
				if !ok {
					t.Fatal("not an Ed25519 key")
				}
				sk := ssh.Marshal(struct {
					Type        string
					Key         []byte
					Application string
				}{ssh.KeyAlgoSKED25519, ed, "ssh:"})
				sig, err := f.host.Sign(rand.Reader, f.sid)
				if err != nil {
					t.Fatal(err)
				}
				req.Binds = [][]byte{marshalBind(sk, f.sid, ssh.Marshal(sig), false)}
			},
			want: ErrHostKeyType,
		},
		{
			name:     "host key not in its usual wire form",
			hostKind: rsaKind,
			change: func(t *testing.T, f *fixture, req *Request) {
				blob := paddedRSAKey(t, f.host.PublicKey())
				sig, err := f.host.SignWithAlgorithm(rand.Reader, f.sid, ssh.KeyAlgoRSASHA256)
				if err != nil {
					t.Fatal(err)
				}
				req.Binds = [][]byte{marshalBind(blob, f.sid, ssh.Marshal(sig), false)}
			},
			want: ErrBadBind,
		},
		{
			name: "host key that is not a key",
			change: func(_ *testing.T, f *fixture, req *Request) {
				req.Binds = [][]byte{marshalBind([]byte("not a key"), f.sid, []byte("x"), false)}
			},
			want: ErrBadBind,
		},

		// The host key in hostbound data.
		{
			name:   "hostbound with another host key",
			method: methodHostbound,
			change: func(_ *testing.T, f *fixture, req *Request) {
				f.data.hostKey = f.other.PublicKey().Marshal()
				req.Data = f.data.marshal()
			},
			want: ErrOtherHost,
		},
		{
			name:   "hostbound with another host key that is bound in a valid bind of that session",
			method: methodHostbound,
			change: func(t *testing.T, f *fixture, req *Request) {
				// The bind is valid for db-1 in this session. The data
				// names web-1. A real ssh never sends this.
				req.Binds = [][]byte{signBind(t, f.other, "", f.sid, false)}
			},
			want: ErrOtherHost,
		},

		// The remote user.
		{name: "empty user", change: setUser(""), want: ErrUser},
		{name: "user starts with -", change: setUser("-oProxyCommand=x"), want: ErrUser},
		{name: "user with a space", change: setUser("deploy x"), want: ErrUser},
		{name: "user with a newline", change: setUser("deploy\n✅ host: db-1"), want: ErrUser},
		{name: "user with @", change: setUser("deploy@db-1"), want: ErrUser},
		{name: "user with /", change: setUser("../root"), want: ErrUser},
		{name: "user with a non-ASCII letter", change: setUser("dеploy"), want: ErrUser}, // a Cyrillic е
		{name: "user with HTML", change: setUser("<b>root</b>"), want: ErrUser},
		{name: "user with 33 characters", change: setUser(strings.Repeat("a", 33)), want: ErrUser},
		{name: "user with a NUL byte", change: setUser("root\x00"), want: ErrUser},

		// Data that is not a login.
		{
			name: "SSHSIG data, as for a git commit",
			change: func(_ *testing.T, _ *fixture, req *Request) {
				req.Data = append([]byte("SSHSIG"), ssh.Marshal(struct {
					Namespace, Reserved, Hash string
					Message                   []byte
				}{"git", "", "sha512", make([]byte, 64)})...)
			},
			want: ErrNotLogin,
		},
		{
			name: "random bytes",
			change: func(t *testing.T, _ *fixture, req *Request) {
				req.Data = newSessionID(t, 200)
			},
			want: ErrNotLogin,
		},
		{name: "empty data", change: func(_ *testing.T, _ *fixture, req *Request) { req.Data = nil }, want: ErrNotLogin},
		{name: "another message", change: setData(func(d *login) { d.msg = 51 }), want: ErrNotLogin},
		{name: "another service", change: setData(func(d *login) { d.service = "ssh-userauth" }), want: ErrNotLogin},
		{name: "password method", change: setData(func(d *login) { d.method = "password" }), want: ErrNotLogin},
		{name: "hostbased method", change: setData(func(d *login) { d.method = "hostbased" }), want: ErrNotLogin},
		{name: "hostbound method of another version", change: setData(func(d *login) { d.method = "publickey-hostbound-v01@openssh.com" }), want: ErrNotLogin},
		{name: "no signature flag", change: setData(func(d *login) { d.hasSignature = 0 }), want: ErrNotLogin},
		{name: "signature flag 2", change: setData(func(d *login) { d.hasSignature = 2 }), want: ErrNotLogin},
		{
			name: "session identifier of 20 bytes, as with SHA-1",
			change: func(t *testing.T, f *fixture, req *Request) {
				f.data.sessionID = newSessionID(t, 20)
				req.Data = f.data.marshal()
			},
			want: ErrNotLogin,
		},
		{
			name: "bind with a session identifier of 20 bytes, as with SHA-1",
			change: func(t *testing.T, f *fixture, req *Request) {
				req.Binds = [][]byte{signBind(t, f.host, "", newSessionID(t, 20), false)}
			},
			want: ErrBadBind,
		},

		// Trailing bytes and odd lengths.
		{
			name: "a byte after the data",
			change: func(_ *testing.T, _ *fixture, req *Request) {
				req.Data = append(req.Data, 0)
			},
			want: ErrNotLogin,
		},
		{
			name:   "the host key of publickey data, with the publickey method",
			method: methodPublicKey,
			change: func(_ *testing.T, f *fixture, req *Request) {
				req.Data = append(req.Data, ssh.Marshal(struct{ K []byte }{f.host.PublicKey().Marshal()})...)
			},
			want: ErrNotLogin,
		},
		{
			name:   "hostbound data without the host key",
			method: methodHostbound,
			change: func(_ *testing.T, f *fixture, req *Request) {
				f.data.method = methodPublicKey
				d := f.data.marshal()
				f.data.method = methodHostbound
				req.Data = hostboundWithout(d)
			},
			want: ErrNotLogin,
		},
		{
			name: "the data cut short",
			change: func(_ *testing.T, _ *fixture, req *Request) {
				req.Data = req.Data[:len(req.Data)-1]
			},
			want: ErrNotLogin,
		},
		{
			name: "a string longer than the data",
			change: func(_ *testing.T, _ *fixture, req *Request) {
				d := bytes.Clone(req.Data)
				binary.BigEndian.PutUint32(d, 0xffffffff)
				req.Data = d
			},
			want: ErrNotLogin,
		},
		{
			name: "data longer than MaxDataLen",
			change: func(_ *testing.T, f *fixture, req *Request) {
				f.data.user = strings.Repeat("a", MaxDataLen)
				req.Data = f.data.marshal()
			},
			want: ErrNotLogin,
		},
		{
			name: "a byte after the bind",
			change: func(_ *testing.T, f *fixture, req *Request) {
				req.Binds = [][]byte{append(bytes.Clone(f.binds[0]), 0)}
			},
			want: ErrBadBind,
		},
		{
			name: "the bind cut short",
			change: func(_ *testing.T, f *fixture, req *Request) {
				req.Binds = [][]byte{f.binds[0][:len(f.binds[0])-1]}
			},
			want: ErrBadBind,
		},
		{
			name: "bytes after the host key in the bind",
			change: func(t *testing.T, f *fixture, req *Request) {
				sig, err := f.host.Sign(rand.Reader, f.sid)
				if err != nil {
					t.Fatal(err)
				}
				blob := append(f.host.PublicKey().Marshal(), 0)
				req.Binds = [][]byte{marshalBind(blob, f.sid, ssh.Marshal(sig), false)}
			},
			want: ErrBadBind,
		},
		{
			name: "bind longer than MaxBindLen",
			change: func(t *testing.T, f *fixture, req *Request) {
				sig, err := f.host.Sign(rand.Reader, f.sid)
				if err != nil {
					t.Fatal(err)
				}
				sig.Blob = append(sig.Blob, make([]byte, MaxBindLen)...)
				req.Binds = [][]byte{marshalBind(f.host.PublicKey().Marshal(), f.sid, ssh.Marshal(sig), false)}
			},
			want: ErrBadBind,
		},

		// The sign flags and the algorithm.
		{
			name: "RSA with SHA-1: no flag",
			kind: rsaKind,
			change: func(_ *testing.T, f *fixture, req *Request) {
				f.data.algorithm = ssh.KeyAlgoRSA
				req.Data = f.data.marshal()
				req.Flags = 0
			},
			want: ErrAlgorithm,
		},
		{
			name: "RSA with SHA-1 in the data, SHA-512 in the flags",
			kind: rsaKind,
			change: func(_ *testing.T, f *fixture, req *Request) {
				f.data.algorithm = ssh.KeyAlgoRSA
				req.Data = f.data.marshal()
			},
			want: ErrAlgorithm,
		},
		{
			name: "RSA: SHA-256 in the data, SHA-512 in the flags",
			kind: rsaKind,
			change: func(_ *testing.T, f *fixture, req *Request) {
				f.data.algorithm = ssh.KeyAlgoRSASHA256
				req.Data = f.data.marshal()
			},
			want: ErrAlgorithm,
		},
		{
			name:   "RSA: both SHA-2 flags",
			kind:   rsaKind,
			change: setFlags(agent.SignatureFlagRsaSha256 | agent.SignatureFlagRsaSha512),
			want:   ErrAlgorithm,
		},
		{name: "RSA: the old signature flag", kind: rsaKind, change: setFlags(agent.SignatureFlagReserved), want: ErrAlgorithm},
		{name: "RSA: an unknown flag", kind: rsaKind, change: setFlags(agent.SignatureFlagRsaSha512 | 8), want: ErrAlgorithm},
		{name: "Ed25519 with an RSA flag", change: setFlags(agent.SignatureFlagRsaSha256), want: ErrAlgorithm},
		{name: "Ed25519 with an unknown flag", change: setFlags(1 << 31), want: ErrAlgorithm},
		{name: "ECDSA with an RSA flag", kind: ecdsa256, change: setFlags(agent.SignatureFlagRsaSha512), want: ErrAlgorithm},
		{name: "Ed25519 key with an ECDSA algorithm", change: setData(func(d *login) { d.algorithm = ssh.KeyAlgoECDSA256 }), want: ErrAlgorithm},
		{name: "ECDSA P-256 key with the P-384 algorithm", kind: ecdsa256, change: setData(func(d *login) { d.algorithm = ssh.KeyAlgoECDSA384 }), want: ErrAlgorithm},

		// The hosts list of the key.
		{
			name: "a key that lists web-1, and a bind of db-1",
			change: func(t *testing.T, f *fixture, req *Request) {
				f.key = newKey(t, "deploy", ed25519Kind, 0, "web-1")
				req.Binds = [][]byte{signBind(t, f.other, "", f.sid, false)}
			},
			want: ErrHostNotAllowed,
		},

		// The broker's known_hosts.
		{
			name: "no known_hosts",
			change: func(_ *testing.T, f *fixture, _ *Request) {
				f.hosts = nil
			},
			want: ErrUnknownHost,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kind, hostKind, method := tt.kind, tt.hostKind, tt.method
			if kind == "" {
				kind = ed25519Kind
			}
			if hostKind == "" {
				hostKind = ed25519Kind
			}
			if method == "" {
				method = methodPublicKey
			}
			f := newFixture(t, kind, hostKind, method)
			req := f.request()
			// The fixture must pass before the change.
			if _, err := f.key.Check(req, f.hosts); err != nil {
				t.Fatalf("the request before the change: %v", err)
			}
			tt.change(t, f, &req)
			l, err := f.key.Check(req, f.hosts)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Check: %v; want %v", err, tt.want)
			}
			if l != (Login{}) {
				t.Errorf("Check returned a Login with its error: %v", l)
			}
			if _, err := f.key.Sign(l); !errors.Is(err, ErrNotChecked) {
				t.Errorf("Sign of the refused Login: %v; want %v", err, ErrNotChecked)
			}
			if msg := err.Error(); strings.Contains(msg, testUser) || strings.Contains(msg, "web-1") ||
				strings.Contains(msg, "deploy") || !strings.HasPrefix(msg, "sshauth: ") {
				t.Errorf("the error %q repeats data or does not start with sshauth:", msg)
			}
		})
	}
}

// setUser returns a change that sets the remote user name.
func setUser(user string) func(*testing.T, *fixture, *Request) {
	return setData(func(d *login) { d.user = user })
}

// setData returns a change of the data to sign.
func setData(change func(*login)) func(*testing.T, *fixture, *Request) {
	return func(_ *testing.T, f *fixture, req *Request) {
		change(&f.data)
		req.Data = f.data.marshal()
	}
}

// setFlags returns a change that sets the sign flags.
func setFlags(flags agent.SignatureFlags) func(*testing.T, *fixture, *Request) {
	return func(_ *testing.T, _ *fixture, req *Request) {
		req.Flags = flags
	}
}

// hostboundWithout returns publickey data d with the method name of the
// hostbound method, and without the host key at its end.
func hostboundWithout(d []byte) []byte {
	old := ssh.Marshal(struct{ S string }{methodPublicKey})
	repl := ssh.Marshal(struct{ S string }{methodHostbound})
	return bytes.Replace(d, old, repl, 1)
}

// newCert returns a certificate for key, signed by a new CA.
func newCert(t testing.TB, key ssh.PublicKey) *ssh.Certificate {
	t.Helper()
	ca := hostSigner(t, ed25519Kind, 5)
	cert := &ssh.Certificate{
		Key:             key,
		CertType:        ssh.HostCert,
		ValidPrincipals: []string{"web-1"},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return cert
}

// paddedRSAKey returns the wire form of an RSA public key with one more
// zero byte in front of the modulus than needed. It parses to the same
// key, but it is not the usual form.
func paddedRSAKey(t testing.TB, key ssh.PublicKey) []byte {
	t.Helper()
	ck, ok := key.(ssh.CryptoPublicKey)
	if !ok {
		t.Fatal("not a crypto key")
	}
	rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey)
	if !ok {
		t.Fatal("not an RSA key")
	}
	n := rk.N.Bytes()
	padded := append([]byte{0}, n...)
	if n[0]&0x80 != 0 {
		padded = append([]byte{0, 0}, n...)
	}
	return ssh.Marshal(struct {
		Type string
		E    []byte
		N    []byte
	}{ssh.KeyAlgoRSA, big.NewInt(int64(rk.E)).Bytes(), padded})
}

// TestNewKeyRefusesAKeyThatCannotSign checks that NewKey refuses a key
// that cannot make a valid signature, so the broker refuses it at start,
// and not after the approver tapped Approve: here an Ed25519 key whose
// public half is not the one of its seed.
func TestNewKeyRefusesAKeyThatCannotSign(t *testing.T) {
	good, ok := privateKey(t, ed25519Kind, 0).(ed25519.PrivateKey)
	if !ok {
		t.Fatal("not Ed25519")
	}
	other, ok := privateKey(t, ed25519Kind, 1).(ed25519.PrivateKey)
	if !ok {
		t.Fatal("not Ed25519")
	}
	broken := ed25519.PrivateKey(append(bytes.Clone(good[:ed25519.SeedSize]), other[ed25519.SeedSize:]...))
	k, err := NewKey("deploy", broken, nil)
	if err == nil {
		t.Fatalf("NewKey accepted a key that cannot sign: %v", k)
	}
	if k != (Key{}) {
		t.Errorf("NewKey returned a Key with its error: %v", k)
	}
	for _, form := range []string{fmt.Sprintf("%x", good[:8]), fmt.Sprintf("%x", other[:8])} {
		if strings.Contains(err.Error(), form) {
			t.Errorf("the error shows key material: %v", err)
		}
	}
}

// TestKeyHostsList checks that a key with a hosts list logs in only to
// those hosts, and a key without one to any known host.
func TestKeyHostsList(t *testing.T) {
	f := newFixture(t, ed25519Kind, ed25519Kind, methodPublicKey)
	binds := map[string][]byte{
		"web-1": signBind(t, f.host, "", f.sid, false),
		"db-1":  signBind(t, f.other, "", f.sid, false),
	}
	tests := []struct {
		hosts []string
		allow map[string]bool
	}{
		{nil, map[string]bool{"web-1": true, "db-1": true}},
		{[]string{}, map[string]bool{"web-1": true, "db-1": true}},
		{[]string{"web-1"}, map[string]bool{"web-1": true}},
		{[]string{"db-1"}, map[string]bool{"db-1": true}},
		{[]string{"web-1", "db-1"}, map[string]bool{"web-1": true, "db-1": true}},
		{[]string{"web-2"}, map[string]bool{}}, // a name that known_hosts does not have
	}
	for _, tt := range tests {
		key := newKey(t, "deploy", ed25519Kind, 0, tt.hosts...)
		for host, bind := range binds {
			req := f.request()
			req.Binds = [][]byte{bind}
			l, err := key.Check(req, f.hosts)
			switch {
			case tt.allow[host] && (err != nil || l.Host() != host):
				t.Errorf("hosts %q, a login to %s: %v, %v; want it allowed", tt.hosts, host, l, err)
			case !tt.allow[host] && (!errors.Is(err, ErrHostNotAllowed) || l != (Login{})):
				t.Errorf("hosts %q, a login to %s: %v, %v; want %v", tt.hosts, host, l, err, ErrHostNotAllowed)
			}
		}
	}
	// NewKey keeps its own copy of the list.
	list := []string{"web-1"}
	key := newKey(t, "deploy", ed25519Kind, 0, list...)
	list[0] = "db-1"
	req := f.request()
	req.Binds = [][]byte{binds["db-1"]}
	if _, err := key.Check(req, f.hosts); !errors.Is(err, ErrHostNotAllowed) {
		t.Errorf("a change to the list after NewKey changed the key: %v", err)
	}
}

// TestSignTakesOnlyItsOwnLogin checks that Sign refuses a Login that the
// Key did not check: the zero Login, and a Login of another Key.
func TestSignTakesOnlyItsOwnLogin(t *testing.T) {
	f := newFixture(t, ed25519Kind, ed25519Kind, methodPublicKey)
	l, err := f.key.Check(f.request(), f.hosts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.key.Sign(Login{}); !errors.Is(err, ErrNotChecked) {
		t.Errorf("Sign(Login{}): %v; want %v", err, ErrNotChecked)
	}
	// Another Key with the same private key and name.
	same := newKey(t, "deploy", ed25519Kind, 0)
	if _, err := same.Sign(l); !errors.Is(err, ErrNotChecked) {
		t.Errorf("Sign of a Login that another Key checked: %v; want %v", err, ErrNotChecked)
	}
	var zero Key
	if _, err := zero.Sign(l); !errors.Is(err, ErrNotChecked) {
		t.Errorf("Sign with the zero Key: %v; want %v", err, ErrNotChecked)
	}
	if _, err := zero.Check(f.request(), f.hosts); err == nil {
		t.Error("Check with the zero Key: no error")
	}
	// A copy of the Key is the same key.
	cp := f.key
	if _, err := cp.Sign(l); err != nil {
		t.Errorf("Sign with a copy of the Key: %v", err)
	}
	if _, err := f.key.Sign(l); err != nil {
		t.Errorf("Sign of its own Login: %v", err)
	}
}

// TestSignSignsTheCheckedData checks that a change to the request after
// Check does not change what Sign signs.
func TestSignSignsTheCheckedData(t *testing.T) {
	f := newFixture(t, ed25519Kind, ed25519Kind, methodPublicKey)
	req := f.request()
	checked := bytes.Clone(req.Data)
	l, err := f.key.Check(req, f.hosts)
	if err != nil {
		t.Fatal(err)
	}
	// Make the data a login as root, in the same buffer.
	f.data.user = "root"
	copy(req.Data, f.data.marshal())
	sig, err := f.key.Sign(l)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.key.PublicKey().Verify(checked, sig); err != nil {
		t.Errorf("the signature is not over the checked data: %v", err)
	}
	if l.RemoteUser() != testUser {
		t.Errorf("RemoteUser() = %q after the change; want %q", l.RemoteUser(), testUser)
	}
}

// TestPrintingHidesData checks that printing a Key or a Login shows no
// key material and not the data to sign.
func TestPrintingHidesData(t *testing.T) {
	f := newFixture(t, ed25519Kind, ed25519Kind, methodPublicKey)
	req := f.request()
	l, err := f.key.Check(req, f.hosts)
	if err != nil {
		t.Fatal(err)
	}
	priv, ok := privateKey(t, ed25519Kind, 0).(ed25519.PrivateKey)
	if !ok {
		t.Fatal("not an Ed25519 key")
	}
	rsaPriv, ok := privateKey(t, rsaKind, 0).(*rsa.PrivateKey)
	if !ok {
		t.Fatal("not an RSA key")
	}
	rsaKey := newKey(t, "deploy", rsaKind, 0)
	secrets := map[string][]byte{
		"the Ed25519 private key": priv.Seed(),
		"the RSA private key":     rsaPriv.D.Bytes(),
		"the data to sign":        req.Data,
		"the session identifier":  f.sid,
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%q", "%d"} {
		values := map[string]any{
			"Key":                     f.key,
			"*Key":                    &f.key,
			"an RSA Key":              rsaKey,
			"Login":                   l,
			"*Login":                  &l,
			"a Key in a struct":       struct{ k Key }{f.key},
			"an RSA Key in a struct":  struct{ k Key }{rsaKey},
			"a *Key in a struct":      struct{ k *Key }{&f.key},
			"a Login in a struct":     struct{ l Login }{l},
			"a *Login in a struct":    struct{ l *Login }{&l},
			"Keys in a map":           map[string]Key{"deploy": f.key, "rsa": rsaKey},
			"a Login in a slice":      []Login{l},
			"a Key in an any field":   struct{ v any }{f.key},
			"a Login in an any field": struct{ v any }{l},
		}
		for name, v := range values {
			out := fmt.Sprintf(verb, v)
			for what, b := range secrets {
				// The bytes as they are, in hex, and in decimal ("[12 34 ...]").
				forms := []string{string(b[:8]), fmt.Sprintf("%x", b[:8]), strings.Trim(fmt.Sprintf("%d", b[:8]), "[]")}
				for _, form := range forms {
					if strings.Contains(out, form) {
						t.Errorf("%s of %s shows %s: %s", verb, name, what, out)
					}
				}
			}
		}
	}
	want := testUser + "@web-1 (host key " + ssh.FingerprintSHA256(f.host.PublicKey()) + ") with key deploy"
	if got := l.String(); got != want {
		t.Errorf("String() = %q; want %q", got, want)
	}
	if got := fmt.Sprint(Login{}); got != "sshauth.Login(none)" {
		t.Errorf("the zero Login prints as %q", got)
	}
}

// TestZeroLogin checks that the zero Login has empty fields.
func TestZeroLogin(t *testing.T) {
	var l Login
	if l.KeyName() != "" || l.Host() != "" || l.HostKey() != nil || l.HostKeyFingerprint() != "" || l.RemoteUser() != "" {
		t.Errorf("the zero Login has fields: %q %q %v %q %q", l.KeyName(), l.Host(), l.HostKey(), l.HostKeyFingerprint(), l.RemoteUser())
	}
}

func TestValidUser(t *testing.T) {
	good := []string{"deploy", "root", "a", "A", "0", ".", "_", "git", "ansible-runner", "first.last", "user_1",
		"._-", strings.Repeat("a", 32), "Ab0." + strings.Repeat("-", 28)}
	bad := []string{"", "-", "-user", strings.Repeat("a", 33), "a b", "a\tb", "a\nb", "deploy\n", "\ndeploy", "a\x00", "a@b", "a/b", "a\\b",
		"a:b", "a;b", "a$b", "a*b", "dеploy", "deploy ", " deploy", "<b>", "a&b", "a'b", `a"b`, "日本"}
	for _, u := range good {
		if !ValidUser(u) {
			t.Errorf("ValidUser(%q) = false; want true", u)
		}
	}
	for _, u := range bad {
		if ValidUser(u) {
			t.Errorf("ValidUser(%q) = true; want false", u)
		}
	}
}

func TestNewKey(t *testing.T) {
	for _, kind := range []keyKind{ed25519Kind, ecdsa256, ecdsa384, ecdsa521, rsaKind} {
		k, err := NewKey("deploy", privateKey(t, kind, 0), nil)
		if err != nil {
			t.Errorf("NewKey(%s): %v", kind, err)
			continue
		}
		if k.Name() != "deploy" {
			t.Errorf("Name() = %q", k.Name())
		}
		want := "sshauth.Key(deploy " + ssh.FingerprintSHA256(k.PublicKey()) + ")"
		if got := fmt.Sprintf("%+v", k); got != want {
			t.Errorf("%%+v of the Key = %q; want %q", got, want)
		}

		// The same key from an OpenSSH key file, as the broker may load
		// it. ssh.ParseRawPrivateKey gives an *ed25519.PrivateKey.
		block, err := ssh.MarshalPrivateKey(privateKey(t, kind, 0), "")
		if err != nil {
			t.Fatal(err)
		}
		raw, err := ssh.ParseRawPrivateKey(pem.EncodeToMemory(block))
		if err != nil {
			t.Fatal(err)
		}
		signer, ok := raw.(crypto.Signer)
		if !ok {
			t.Fatalf("%s: %T is not a crypto.Signer", kind, raw)
		}
		fromFile, err := NewKey("deploy", signer, nil)
		if err != nil {
			t.Errorf("NewKey(%s from a key file): %v", kind, err)
		} else if !bytes.Equal(fromFile.PublicKey().Marshal(), k.PublicKey().Marshal()) {
			t.Errorf("%s from a key file: another public key", kind)
		}
	}

	small, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // G403: a small key that NewKey must refuse.
	if err != nil {
		t.Fatal(err)
	}
	ed := privateKey(t, ed25519Kind, 0)
	tests := []struct {
		name, keyName string
		key           crypto.Signer
		hosts         []string
	}{
		{"RSA with 1024 bits", "deploy", small, nil},
		{"no key", "deploy", nil, nil},
		{"empty name", "", ed, nil},
		{"name with a space", "de ploy", ed, nil},
		{"name with a newline", "deploy\n✅ host: db-1", ed, nil},
		{"name that starts with -", "-deploy", ed, nil},
		{"name with 65 characters", strings.Repeat("a", 65), ed, nil},
		{"Ed25519 seed only", "deploy", ed25519.PrivateKey(make([]byte, ed25519.SeedSize)), nil},
		{"nil *ed25519.PrivateKey", "deploy", (*ed25519.PrivateKey)(nil), nil},
		{"short *ed25519.PrivateKey", "deploy", &ed25519.PrivateKey{1, 2, 3}, nil},
		{"empty host name", "deploy", ed, []string{"web-1", ""}},
		{"host name with a space", "deploy", ed, []string{"web 1"}},
		{"host name with a newline", "deploy", ed, []string{"web-1\n✅ host: db-1"}},
	}
	for _, tt := range tests {
		if k, err := NewKey(tt.keyName, tt.key, tt.hosts); err == nil {
			t.Errorf("NewKey with %s: %v, no error", tt.name, k)
		}
	}
}
