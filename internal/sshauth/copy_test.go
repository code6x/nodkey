package sshauth

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestLoginHostKeyIsACopy checks that a Login does not share memory with
// the Request it was checked from. Grants match on Login.HostKey
// (DESIGN.md section 8). If the broker reuses or wipes the request buffer
// after Check, the host key of the Login must not change.
func TestLoginHostKeyIsACopy(t *testing.T) {
	for _, hostKind := range []keyKind{ed25519Kind, ecdsa256, rsaKind} {
		t.Run(string(hostKind), func(t *testing.T) {
			f := newFixture(t, ed25519Kind, hostKind, methodHostbound)
			req := f.request()
			l, err := f.key.Check(req, f.hosts)
			if err != nil {
				t.Fatal(err)
			}
			before := l.HostKey().Marshal()
			fingerprint := l.HostKeyFingerprint()
			// The broker reuses the buffers, for example for the next
			// request, or wipes them.
			for _, b := range append(req.Binds, req.Data) {
				for i := range b {
					b[i] = 0
				}
			}
			if after := l.HostKey().Marshal(); !bytes.Equal(before, after) {
				t.Errorf("Login.HostKey() changed when the request changed after Check; "+
					"Host() still says %q (grants match on HostKey)", l.Host())
			}
			if l.HostKeyFingerprint() != fingerprint {
				t.Error("Login.HostKeyFingerprint() changed when the request changed after Check")
			}
		})
	}
}

// TestLoginHostKeyCannotBeChanged checks that a caller of HostKey cannot
// change the host key inside a Login.
func TestLoginHostKeyCannotBeChanged(t *testing.T) {
	f := newFixture(t, ed25519Kind, ed25519Kind, methodPublicKey)
	l, err := f.key.Check(f.request(), f.hosts)
	if err != nil {
		t.Fatal(err)
	}
	before := l.HostKey().Marshal()
	ck, ok := l.HostKey().(ssh.CryptoPublicKey)
	if !ok {
		t.Fatal("not a crypto key")
	}
	pk, ok := ck.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		t.Fatal("not Ed25519")
	}
	pk[0] ^= 0xff
	if after := l.HostKey().Marshal(); !bytes.Equal(before, after) {
		t.Error("a caller of Login.HostKey() changed the host key inside the Login")
	}
}
