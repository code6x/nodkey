package approval_test

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestSSHGrantKeepsHostKeyBytes: KeysFor of the broker's known_hosts
// returns the keys that it holds, not copies of them, so a caller could
// change them (from the review of issue #9). The core keeps each host key
// of an SSH grant as its SSH wire bytes, made when the request comes. So
// a later change to such a key changes no grant: the grants cover the
// host keys that the person approved. A listed host is covered, and a
// host that is not in the list still asks.
func TestSSHGrantKeepsHostKeyBytes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		h := e.hosts
		e.approveWindow(grantReq("laptop", "deploy", "deploy", 15*time.Minute, "web-1"), 1)

		// Change the Ed25519 host key of web-1 in place, as a careless
		// caller of KeysFor could.
		changed := false
		for _, k := range e.cfg.KnownHosts.KeysFor("web-1") {
			if pub, ok := k.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey); ok {
				pub[0] ^= 0xff
				changed = true
			}
		}
		if !changed {
			t.Fatal("web-1 has no Ed25519 host key to change")
		}
		if bytes.Equal(e.cfg.KnownHosts.KeysFor("web-1")[0].Marshal(), h.web1.Marshal()) {
			t.Fatal("the change did not reach the known_hosts; the test does not test")
		}
		checkAllowed(t, e.now(loginReq("laptop", "deploy", h.web1, "deploy")))
		checkAllowed(t, e.now(loginReq("laptop", "deploy", h.web1ecdsa, "deploy")))
		e.needsTap(loginReq("laptop", "deploy", h.web2, "deploy"), 2)
	})
}
