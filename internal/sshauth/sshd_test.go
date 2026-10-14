package sshauth

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestSSHDMatrix logs in with the real ssh to the real sshd for many user
// key types, host key types and key exchanges, with every signature made
// by Check and Sign. sshd checks each signature. So what the broker signs
// is exactly what sshd accepts.
func TestSSHDMatrix(t *testing.T) {
	sshPath, sshdPath, name := requireOpenSSH(t), requireSSHD(t), sshUser(t)
	tests := []struct {
		name      string
		user      keyKind
		host      keyKind
		sshOpts   []string
		sidLen    int    // the length of the session identifier; 0 = any
		algorithm string // the user signature algorithm; "" = the key type
	}{
		{"ed25519 user, ed25519 host, default kex", ed25519Kind, ed25519Kind, nil, 0, ""},
		{"ecdsa256 user, ecdsa256 host", ecdsa256, ecdsa256, nil, 0, ""},
		{"ecdsa384 user, ecdsa384 host", ecdsa384, ecdsa384, nil, 0, ""},
		{"ecdsa521 user, ecdsa521 host", ecdsa521, ecdsa521, nil, 0, ""},
		{"rsa user sha512, rsa host sha512", rsaKind, rsaKind, []string{"HostKeyAlgorithms=rsa-sha2-512"}, 0, ssh.KeyAlgoRSASHA512},
		{"rsa user sha256, rsa host sha256", rsaKind, rsaKind,
			[]string{"HostKeyAlgorithms=rsa-sha2-256", "PubkeyAcceptedAlgorithms=rsa-sha2-256"}, 0, ssh.KeyAlgoRSASHA256},
		{"kex curve25519-sha256 (32)", ed25519Kind, ed25519Kind, []string{"KexAlgorithms=curve25519-sha256"}, 32, ""},
		{"kex ecdh-sha2-nistp384 (48)", ed25519Kind, ecdsa384, []string{"KexAlgorithms=ecdh-sha2-nistp384"}, 48, ""},
		{"kex ecdh-sha2-nistp521 (64)", ed25519Kind, ed25519Kind, []string{"KexAlgorithms=ecdh-sha2-nistp521"}, 64, ""},
		{"kex sntrup761x25519-sha512 (64)", ed25519Kind, ed25519Kind, []string{"KexAlgorithms=sntrup761x25519-sha512@openssh.com"}, 64, ""},
		{"kex group16-sha512 (64)", rsaKind, rsaKind, []string{"KexAlgorithms=diffie-hellman-group16-sha512"}, 64, ssh.KeyAlgoRSASHA512},
		{"kex group-exchange-sha256 (32)", ed25519Kind, ed25519Kind, []string{"KexAlgorithms=diffie-hellman-group-exchange-sha256"}, 32, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := shortTempDir(t)
			key := newKey(t, "deploy", tt.user, 0)
			host := hostSigner(t, tt.host, 1)
			hosts := knownHosts(t, map[string]ssh.PublicKey{"web-1": host.PublicKey()})
			addr := startSSHD(t, sshdPath, dir, tt.host, key.PublicKey())
			a := startTestAgent(t, key, hosts, dir)
			out, err := runSSH(t, sshPath, a.socket, addr, name, host.PublicKey(), dir, tt.sshOpts...)
			reqs, logins, errs := a.results()
			if err != nil || len(errs) != 1 || errs[0] != nil {
				t.Fatalf("ssh: %v; sign requests %v\n%s", err, errs, out)
			}
			l := logins[0]
			if !l.c.hostbound || l.Host() != "web-1" || l.RemoteUser() != name {
				t.Errorf("Login %v, hostbound %v; want %s@web-1, hostbound", l, l.c.hostbound, name)
			}
			want := tt.algorithm
			if want == "" {
				want = key.PublicKey().Type()
			}
			if l.c.sign.algorithm != want {
				t.Errorf("signed with %s; want %s", l.c.sign.algorithm, want)
			}
			b, err := parseBind(reqs[0].Binds[0])
			if err != nil {
				t.Fatal(err)
			}
			if tt.sidLen != 0 && len(b.sessionID) != tt.sidLen {
				t.Errorf("a session identifier of %d bytes; want %d", len(b.sessionID), tt.sidLen)
			}
		})
	}
}

// TestSSHDRefusals checks the refusals that DESIGN.md section 6 promises,
// with the real ssh and sshd, and that the documented fix for a host
// certificate works.
func TestSSHDRefusals(t *testing.T) {
	sshPath, sshdPath, name := requireOpenSSH(t), requireSSHD(t), sshUser(t)

	t.Run("SHA-1 key exchange", func(t *testing.T) {
		dir := shortTempDir(t)
		key := newKey(t, "deploy", ed25519Kind, 0)
		host := hostSigner(t, ed25519Kind, 1)
		addr := startSSHD(t, sshdPath, dir, ed25519Kind, key.PublicKey(), "KexAlgorithms +diffie-hellman-group14-sha1")
		a := startTestAgent(t, key, knownHosts(t, map[string]ssh.PublicKey{"web-1": host.PublicKey()}), dir)
		out, err := runSSH(t, sshPath, a.socket, addr, name, host.PublicKey(), dir, "KexAlgorithms=diffie-hellman-group14-sha1")
		_, logins, errs := a.results()
		if err == nil || len(errs) != 1 || !errors.Is(errs[0], ErrNotLogin) || logins[0] != (Login{}) {
			t.Fatalf("ssh %v; sign requests %v; want one refused with %v\n%s", err, errs, ErrNotLogin, out)
		}
	})

	t.Run("RSA host key, ssh-rsa (SHA-1) host signature", func(t *testing.T) {
		dir := shortTempDir(t)
		key := newKey(t, "deploy", ed25519Kind, 0)
		host := hostSigner(t, rsaKind, 1)
		addr := startSSHD(t, sshdPath, dir, rsaKind, key.PublicKey(), "HostKeyAlgorithms +ssh-rsa")
		a := startTestAgent(t, key, knownHosts(t, map[string]ssh.PublicKey{"web-1": host.PublicKey()}), dir)
		out, err := runSSH(t, sshPath, a.socket, addr, name, host.PublicKey(), dir, "HostKeyAlgorithms=ssh-rsa")
		_, _, errs := a.results()
		if err == nil || len(errs) != 1 || !errors.Is(errs[0], ErrBindSignature) {
			t.Fatalf("ssh %v; sign requests %v; want one refused with %v\n%s", err, errs, ErrBindSignature, out)
		}
	})

	t.Run("a key that lists web-1, and a login to db-1", func(t *testing.T) {
		dir := shortTempDir(t)
		key := newKey(t, "deploy", ed25519Kind, 0, "web-1")
		db1 := hostSigner(t, ed25519Kind, 1) // the host key of this sshd
		hosts := knownHosts(t, map[string]ssh.PublicKey{
			"web-1": hostSigner(t, ed25519Kind, 2).PublicKey(),
			"db-1":  db1.PublicKey(),
		})
		addr := startSSHD(t, sshdPath, dir, ed25519Kind, key.PublicKey())
		a := startTestAgent(t, key, hosts, dir)
		out, err := runSSH(t, sshPath, a.socket, addr, name, db1.PublicKey(), dir)
		_, logins, errs := a.results()
		if err == nil || len(errs) != 1 || !errors.Is(errs[0], ErrHostNotAllowed) || logins[0] != (Login{}) {
			t.Fatalf("ssh %v; sign requests %v; want one refused with %v\n%s", err, errs, ErrHostNotAllowed, out)
		}
	})

	for _, fix := range []bool{false, true} {
		label := "host certificate, default ssh config"
		var opts []string
		if fix {
			label = "host certificate, HostKeyAlgorithms=ssh-ed25519"
			opts = []string{"HostKeyAlgorithms=ssh-ed25519"}
		}
		t.Run(label, func(t *testing.T) {
			dir := shortTempDir(t)
			key := newKey(t, "deploy", ed25519Kind, 0)
			host := hostSigner(t, ed25519Kind, 1)
			ca := hostSigner(t, ed25519Kind, 5)
			cert := &ssh.Certificate{Key: host.PublicKey(), CertType: ssh.HostCert,
				ValidPrincipals: []string{"web-1"}, ValidBefore: ssh.CertTimeInfinity}
			if err := cert.SignCert(rand.Reader, ca); err != nil {
				t.Fatal(err)
			}
			certFile := filepath.Join(dir, "host_key-cert.pub")
			if err := os.WriteFile(certFile, ssh.MarshalAuthorizedKey(cert), 0o600); err != nil {
				t.Fatal(err)
			}
			addr := startSSHD(t, sshdPath, dir, ed25519Kind, key.PublicKey(), "HostCertificate "+certFile)
			a := startTestAgent(t, key, knownHosts(t, map[string]ssh.PublicKey{"web-1": host.PublicKey()}), dir)
			out, err := runSSH(t, sshPath, a.socket, addr, name, host.PublicKey(), dir, opts...)
			_, _, errs := a.results()
			if fix {
				if err != nil || len(errs) != 1 || errs[0] != nil {
					t.Fatalf("with the documented fix: ssh %v; sign requests %v\n%s", err, errs, out)
				}
				return
			}
			if err == nil || len(errs) != 1 || !errors.Is(errs[0], ErrHostKeyType) {
				t.Fatalf("ssh %v; sign requests %v; want one refused with %v\n%s", err, errs, ErrHostKeyType, out)
			}
		})
	}

	t.Run("bind of host A, login to host B", func(t *testing.T) {
		dirA, dirB := shortTempDir(t), shortTempDir(t)
		key := newKey(t, "deploy", ed25519Kind, 0)
		hostA := hostSigner(t, ed25519Kind, 1)
		addrA := startSSHD(t, sshdPath, dirA, ed25519Kind, key.PublicKey())
		// B has another host key: test key number 1 of another type.
		hostB := hostSigner(t, ecdsa256, 1)
		addrB := startSSHD(t, sshdPath, dirB, ecdsa256, key.PublicKey())
		hosts := knownHosts(t, map[string]ssh.PublicKey{"web-1": hostA.PublicKey(), "db-1": hostB.PublicKey()})
		a := startTestAgent(t, key, hosts, dirA)
		if out, err := runSSH(t, sshPath, a.socket, addrA, name, hostA.PublicKey(), dirA); err != nil {
			t.Fatalf("login to A: %v\n%s", err, out)
		}
		a.setReplay(a.allBinds())
		out, err := runSSH(t, sshPath, a.socket, addrB, name, hostB.PublicKey(), dirB)
		_, logins, errs := a.results()
		if err == nil || len(errs) != 2 || !errors.Is(errs[1], ErrOtherSession) || logins[1] != (Login{}) {
			t.Fatalf("ssh %v; sign requests %v; want the second refused with %v\n%s", err, errs, ErrOtherSession, out)
		}
	})
}
