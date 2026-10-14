package sshauth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/code6x/nodkey/internal/config"
)

// TestKnownHostsOneKeyTwoNames checks that one host key can never
// give two names: also not when the second line writes the same RSA key
// with an extra zero byte in its modulus, which parses to the same key.
func TestKnownHostsOneKeyTwoNames(t *testing.T) {
	host := hostSigner(t, rsaKind, 1)
	plain := "web-1 " + string(ssh.MarshalAuthorizedKey(host.PublicKey()))
	padded := "db-1 ssh-rsa " + base64.StdEncoding.EncodeToString(paddedRSAKey(t, host.PublicKey())) + "\n"
	if _, err := ssh.ParsePublicKey(paddedRSAKey(t, host.PublicKey())); err != nil {
		t.Fatalf("the padded key does not parse: %v", err)
	}
	for name, file := range map[string]string{"plain then padded": plain + padded, "padded then plain": padded + plain} {
		if _, err := config.ParseKnownHosts([]byte(file)); err == nil {
			t.Errorf("%s: known_hosts with one key under two names was accepted", name)
		}
	}
	// The padded line alone is fine: it names the host's key. A bind
	// with the padded form is still refused; the plain form maps to db-1.
	hosts, err := config.ParseKnownHosts([]byte(padded))
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, ed25519Kind, rsaKind, methodPublicKey)
	f.hosts = hosts
	sig, err := f.host.SignWithAlgorithm(rand.Reader, f.sid, ssh.KeyAlgoRSASHA256)
	if err != nil {
		t.Fatal(err)
	}
	req := f.request()
	req.Binds = [][]byte{marshalBind(paddedRSAKey(t, f.host.PublicKey()), f.sid, ssh.Marshal(sig), false)}
	if _, err := f.key.Check(req, hosts); !errors.Is(err, ErrBadBind) {
		t.Errorf("a bind with the padded host key: %v; want %v", err, ErrBadBind)
	}
	req.Binds = f.binds
	l, err := f.key.Check(req, hosts)
	if err != nil || l.Host() != "db-1" {
		t.Errorf("the plain bind: %v, %v; want db-1", l, err)
	}
}

// TestKnownHostsTypeMismatch checks that a line whose key type does
// not match its key is refused, so a key cannot hide under another type.
func TestKnownHostsTypeMismatch(t *testing.T) {
	ed := hostSigner(t, ed25519Kind, 1).PublicKey()
	ec := hostSigner(t, ecdsa256, 1).PublicKey()
	lines := []string{
		"web-1 ssh-rsa " + base64.StdEncoding.EncodeToString(ed.Marshal()),
		"web-1 ecdsa-sha2-nistp384 " + base64.StdEncoding.EncodeToString(ec.Marshal()),
		"web-1 ssh-ed25519-cert-v01@openssh.com " + base64.StdEncoding.EncodeToString(ed.Marshal()),
	}
	for _, line := range lines {
		if _, err := config.ParseKnownHosts([]byte(line + "\n")); err == nil {
			t.Errorf("accepted %q", line[:40])
		}
	}
	// The ECDSA blob that names the P-256 curve under the P-384 type.
	mixed := ssh.Marshal(struct {
		Type, Curve string
		Point       []byte
	}{ssh.KeyAlgoECDSA384, "nistp256", ec.Marshal()[39:]})
	if _, err := ssh.ParsePublicKey(mixed); err == nil {
		t.Error("an ECDSA key with a curve of another type parses")
	}
}
