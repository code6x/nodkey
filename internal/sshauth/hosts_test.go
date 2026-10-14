package sshauth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/code6x/nodkey/internal/config"
)

// TestR2HostsListMatchesKnownHostsNames checks that the hosts list is
// matched against the exact name that known_hosts gives, for every host
// key of that name, and that a name that only looks the same is refused.
func TestHostsListMatchesKnownHostsNames(t *testing.T) {
	f := newFixture(t, ed25519Kind, ed25519Kind, methodPublicKey)
	web1ec := hostSigner(t, ecdsa256, 1) // a second host key of web-1
	file := "web-1 " + string(ssh.MarshalAuthorizedKey(f.host.PublicKey())) +
		"web-1 " + string(ssh.MarshalAuthorizedKey(web1ec.PublicKey())) +
		"db-1 " + string(ssh.MarshalAuthorizedKey(f.other.PublicKey()))
	hosts, err := config.ParseKnownHosts([]byte(file))
	if err != nil {
		t.Fatal(err)
	}
	binds := map[string][]byte{
		"web-1 ed25519": signBind(t, f.host, "", f.sid, false),
		"web-1 ecdsa":   signBind(t, web1ec, "", f.sid, false),
		"db-1":          signBind(t, f.other, "", f.sid, false),
	}
	tests := []struct {
		list  []string
		allow map[string]bool
	}{
		{[]string{"web-1"}, map[string]bool{"web-1 ed25519": true, "web-1 ecdsa": true}},
		{[]string{"Web-1"}, map[string]bool{}},
		{[]string{"web-1."}, map[string]bool{}},
		{[]string{"web-10"}, map[string]bool{}},
		{[]string{"db-1"}, map[string]bool{"db-1": true}},
	}
	for _, tt := range tests {
		key := newKey(t, "deploy", ed25519Kind, 0, tt.list...)
		for name, bind := range binds {
			req := f.request()
			req.Binds = [][]byte{bind}
			l, err := key.Check(req, hosts)
			want := strings.SplitN(name, " ", 2)[0]
			switch {
			case tt.allow[name] && (err != nil || l.Host() != want):
				t.Errorf("list %q, bind %s: %v, %v; want allowed as %s", tt.list, name, l, err, want)
			case !tt.allow[name] && !errors.Is(err, ErrHostNotAllowed):
				t.Errorf("list %q, bind %s: %v; want %v", tt.list, name, err, ErrHostNotAllowed)
			}
		}
	}
}

// TestR2SelfTestTextIsNotALogin checks that the text NewKey signs is not
// data that Check accepts, and is no SSHSIG blob and no certificate.
func TestSelfTestTextIsNotALogin(t *testing.T) {
	if _, err := parseData([]byte(checkText)); !errors.Is(err, ErrNotLogin) {
		t.Errorf("parseData(checkText): %v; want %v", err, ErrNotLogin)
	}
	if strings.HasPrefix(checkText, "SSHSIG") {
		t.Error("checkText starts like an SSHSIG blob")
	}
	if _, err := ssh.ParsePublicKey([]byte(checkText)); err == nil {
		t.Error("checkText parses as a key or a certificate")
	}
}

// TestR2NewKeyRefusesBrokenECDSAAndRSA checks the self-test for the other
// key types: a private key whose public half is another key's.
func TestNewKeyRefusesBrokenECDSAAndRSA(t *testing.T) {
	ec := *privateKey(t, ecdsa256, 0).(*ecdsa.PrivateKey) //nolint:forcetypeassert // test keys
	ec.PublicKey = privateKey(t, ecdsa256, 1).(*ecdsa.PrivateKey).PublicKey
	if _, err := NewKey("deploy", &ec, nil); err == nil {
		t.Error("NewKey accepted an ECDSA key with another key's public half")
	}
	rk := *privateKey(t, rsaKind, 0).(*rsa.PrivateKey) //nolint:forcetypeassert // test keys
	rk.PublicKey = privateKey(t, rsaKind, 1).(*rsa.PrivateKey).PublicKey
	rk.Precomputed = rsa.PrecomputedValues{}
	if _, err := NewKey("deploy", &rk, nil); err == nil {
		t.Error("NewKey accepted an RSA key with another key's public half")
	}
}
