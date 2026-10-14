package config

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestParseKnownHosts(t *testing.T) {
	web1, web2, db1 := newHostKey(t), newHostKey(t), newHostKey(t)
	keyText := func(k ssh.PublicKey) string { return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) }
	data := "# The broker's known hosts. Made up for tests.\n" +
		"\n" +
		knownHostsLine("web-1", web1) + "\n" +
		"   \t\n" +
		"  # an indented comment\n" +
		"\t" + "web-2\t" + keyText(web2) + " a comment with spaces\r\n" +
		"db-1  " + keyText(db1) // no newline at the end
	k, err := ParseKnownHosts([]byte(data))
	if err != nil {
		t.Fatalf("ParseKnownHosts: %v", err)
	}
	for name, key := range map[string]ssh.PublicKey{"web-1": web1, "web-2": web2, "db-1": db1} {
		if got, ok := k.NameFor(key); !ok || got != name {
			t.Errorf("NameFor(key of %s) = %q, %v; want %q, true", name, got, ok, name)
		}
		got := k.KeysFor(name)
		if len(got) != 1 || string(got[0].Marshal()) != string(key.Marshal()) {
			t.Errorf("KeysFor(%q) = %v; want its one key", name, got)
		}
	}
	if name, ok := k.NameFor(newHostKey(t)); ok {
		t.Errorf("NameFor(an unknown key) = %q, true; want false", name)
	}
	if name, ok := k.NameFor(nil); ok {
		t.Errorf("NameFor(nil) = %q, true; want false", name)
	}
	if got := k.KeysFor("web-3"); got != nil {
		t.Errorf("KeysFor(an unknown name) = %v; want nil", got)
	}
	if got := k.KeysFor("WEB-1"); got != nil {
		t.Errorf("KeysFor(a name in another case) = %v; want nil", got)
	}
	// A certificate for a known key is not the key itself.
	if name, ok := k.NameFor(newHostCert(t, web1)); ok {
		t.Errorf("NameFor(a certificate) = %q, true; want false", name)
	}

	var nilHosts *KnownHosts
	if _, ok := nilHosts.NameFor(web1); ok {
		t.Error("nil KnownHosts: NameFor = true; want false")
	}
	if got := nilHosts.KeysFor("web-1"); got != nil {
		t.Errorf("nil KnownHosts: KeysFor = %v; want nil", got)
	}

	for _, empty := range []string{"", "\n", "# only a comment\n"} {
		k, err := ParseKnownHosts([]byte(empty))
		if err != nil {
			t.Errorf("ParseKnownHosts(%q): %v", empty, err)
			continue
		}
		if _, ok := k.NameFor(web1); ok {
			t.Errorf("ParseKnownHosts(%q) knows a host", empty)
		}
	}
}

func TestParseKnownHostsSeveralKeysForOneName(t *testing.T) {
	ecdsaKey := func(c elliptic.Curve) ssh.PublicKey {
		priv, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, err := ssh.NewPublicKey(&priv.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	// Each ECDSA curve is a key type of its own.
	ed, ec, ec384, db := newHostKey(t), ecdsaKey(elliptic.P256()), ecdsaKey(elliptic.P384()), newHostKey(t)
	k, err := ParseKnownHosts([]byte(knownHostsLine("web-1", ed) + "\n" + knownHostsLine("db-1", db) + "\n" +
		knownHostsLine("web-1", ec) + "\n" + knownHostsLine("web-1", ec384) + "\n"))
	if err != nil {
		t.Fatalf("ParseKnownHosts: %v", err)
	}
	keys := k.KeysFor("web-1")
	if len(keys) != 3 || keys[0].Type() != ssh.KeyAlgoED25519 || keys[1].Type() != ssh.KeyAlgoECDSA256 ||
		keys[2].Type() != ssh.KeyAlgoECDSA384 {
		t.Fatalf("KeysFor(web-1) = %v; want the ed25519 key and the two ECDSA keys, in the order of the file", keys)
	}
	for _, key := range []ssh.PublicKey{ed, ec, ec384} {
		if name, ok := k.NameFor(key); !ok || name != "web-1" {
			t.Errorf("NameFor(%s key) = %q, %v; want web-1, true", key.Type(), name, ok)
		}
	}
	if keys := k.KeysFor("db-1"); len(keys) != 1 {
		t.Errorf("KeysFor(db-1) has %d keys, want 1", len(keys))
	}
	// KeysFor returns a copy.
	keys[0] = nil
	if k.KeysFor("web-1")[0] == nil {
		t.Error("changing the result of KeysFor changed KnownHosts")
	}
}

// TestParseKnownHostsOneRSAKeyInTwoEncodings writes one RSA host key for
// two names, the second time with one more zero byte in front of the
// modulus. The check "one key, one name" must still see one key.
func TestParseKnownHostsOneRSAKeyInTwoEncodings(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	str := func(b []byte) []byte {
		out := binary.BigEndian.AppendUint32(nil, uint32(len(b))) //nolint:gosec // G115: test data is far below 4 GiB.
		return append(out, b...)
	}
	// The SSH wire form of an RSA key: the type, e and n as mpints. An mpint
	// has one zero byte in front when the high bit is set; add one more.
	n := priv.N.Bytes()
	padded := append([]byte{0}, n...)
	if n[0]&0x80 != 0 {
		padded = append([]byte{0, 0}, n...)
	}
	blob := slices.Concat(str([]byte(ssh.KeyAlgoRSA)), str(big.NewInt(int64(priv.E)).Bytes()), str(padded))
	data := knownHostsLine("web-1", key) + "\nweb-2 " + ssh.KeyAlgoRSA + " " + base64.StdEncoding.EncodeToString(blob) + "\n"
	k, err := ParseKnownHosts([]byte(data))
	if err == nil {
		name, _ := k.NameFor(key)
		t.Fatalf("one RSA key under two names was accepted; NameFor = %q", name)
	}
	checkError(t, err, "line 2: this host key is already on line 1", "")
}

// newHostCert makes a host certificate for key, signed by a new CA.
func newHostCert(t *testing.T, key ssh.PublicKey) *ssh.Certificate {
	t.Helper()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ssh.NewSignerFromKey(caKey)
	if err != nil {
		t.Fatal(err)
	}
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

func TestParseKnownHostsErrors(t *testing.T) {
	key, other := newHostKey(t), newHostKey(t)
	keyText := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	blob := strings.Fields(keyText)[1]
	good := knownHostsLine("web-1", other) + "\n"
	tests := []struct {
		name string
		line string // the second line; the first is a valid entry
		want string
	}{
		{"name only", "web-2", "must be a host name, a key type and a key"},
		{"no key", "web-2 ssh-ed25519", "must be a host name, a key type and a key"},
		{"cert-authority marker", "@cert-authority web-2 " + keyText, "markers such as @cert-authority and @revoked are not allowed"},
		{"revoked marker", "@revoked web-2 " + keyText, "markers such as @cert-authority and @revoked are not allowed"},
		{"hashed name", "|1|c2FsdHNhbHRzYWx0c2FsdHNhbHQ=|aGFzaGhhc2hoYXNoaGFzaGhhc2g= " + keyText, "hashed host names are not allowed"},
		{"two names", "web-2,192.0.2.12 " + keyText, "only one host name per line"},
		{"port", "[web-2]:2222 " + keyText, "a port ([host]:port) is not allowed"},
		{"wildcard star", "web-* " + keyText, "wildcards (*, ?) and negation (!) are not allowed"},
		{"wildcard question mark", "web-? " + keyText, "wildcards (*, ?) and negation (!) are not allowed"},
		{"negation", "!web-2 " + keyText, "wildcards (*, ?) and negation (!) are not allowed"},
		{"name with a slash", "web/2 " + keyText, "the host name must be 1 to 64 letters"},
		{"name starts with a dash", "-web-2 " + keyText, "the host name must be"},
		{"name too long", strings.Repeat("w", 65) + " " + keyText, "the host name must be"},
		{"name with IPv6", "2001:db8::12 " + keyText, "the host name must be"},
		{"key not base64", "web-2 ssh-ed25519 not*base64", "the key is not valid base64"},
		{"key data not a key", "web-2 ssh-ed25519 " + base64.StdEncoding.EncodeToString([]byte("not a key")), "the key is not a valid SSH public key"},
		{"key with extra data", "web-2 ssh-ed25519 " + base64.StdEncoding.EncodeToString(append(key.Marshal(), 0)), "the key is not a valid SSH public key"},
		{"key type does not match", "web-2 ssh-rsa " + blob, "the key type does not match the key"},
		{"certificate", "web-2 " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(newHostCert(t, key)))), "certificates are not allowed"},
		{"one key for two names", "web-2 " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(other))), "this host key is already on line 1"},
		{"one name for two keys of one type", "web-1 " + keyText, "this host name already has a key of this type on line 1"},
		{"one name for one key twice", "web-1 " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(other))), "this host name already has a key of this type on line 1"},
		{"indented marker", "\t@revoked web-2 " + keyText, "markers such as @cert-authority and @revoked are not allowed"},
		{"byte order mark", "\ufeffweb-2 " + keyText, "the host name must be"},
		{"NUL in the name", "web\x002 " + keyText, "the host name must be"},
		{"vertical tab between the fields", "web-2\v" + keyText, "must be a host name, a key type and a key"},
		{"no-break space between the fields", "web-2\u00a0" + keyText, "must be a host name, a key type and a key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseKnownHosts([]byte(good + tt.line + "\n"))
			checkError(t, err, "line 2: "+tt.want, "")
			// The error must not repeat the line: no name, no key text.
			// (Marker names are part of the message itself.)
			for _, field := range strings.Fields(tt.line) {
				if strings.HasPrefix(field, "@") {
					continue
				}
				if len(field) > 2 && strings.Contains(err.Error(), field) {
					t.Errorf("error = %q, want it not to hold %q from the line", err, field)
				}
			}
		})
	}
}

func TestLoadKnownHosts(t *testing.T) {
	dir := privateTempDir(t)
	key := newHostKey(t)
	path := writeFile(t, dir, "known_hosts", knownHostsLine("web-1", key)+"\n", 0o644)
	k, err := LoadKnownHosts(path)
	if err != nil {
		t.Fatalf("LoadKnownHosts: %v", err)
	}
	if name, ok := k.NameFor(key); !ok || name != "web-1" {
		t.Errorf("NameFor = %q, %v; want web-1, true", name, ok)
	}

	bad := writeFile(t, dir, "bad", "# comment\nweb-1,web-2 "+strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))+"\n", 0o644)
	_, err = LoadKnownHosts(bad)
	checkError(t, err, bad+": line 2: only one host name per line", "")

	writable := writeFile(t, dir, "writable", knownHostsLine("web-1", key)+"\n", 0o664)
	_, err = LoadKnownHosts(writable)
	checkError(t, err, writable+": group or others can write to it (mode 0664)", "")

	missing := filepath.Join(dir, "no-such-file")
	_, err = LoadKnownHosts(missing)
	checkError(t, err, "lstat "+missing+": no such file or directory", "")

	open := mkdir(t, dir, "open", 0o777)
	inOpen := writeFile(t, open, "known_hosts", knownHostsLine("web-1", key)+"\n", 0o644)
	_, err = LoadKnownHosts(inOpen)
	checkError(t, err, open+": group or others can write to this directory (mode 0777)", "")
}
