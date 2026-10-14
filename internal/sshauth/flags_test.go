package sshauth

import (
	"fmt"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// TestFlagsAndAlgorithmMatrix tries every pair of sign flags and
// algorithm name in the data, for every key type. Check must accept only
// the pairs that OpenSSH's ssh sends (authfd.c agent_encode_alg), and the
// signature must then have the format that sshd checks against the
// algorithm name in the data (auth2-pubkey.c: sshkey_verify with pkalg).
func TestFlagsAndAlgorithmMatrix(t *testing.T) {
	names := []string{
		"", ssh.KeyAlgoRSA, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoED25519,
		ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256,
		ssh.CertAlgoRSAv01, ssh.CertAlgoRSASHA256v01, ssh.CertAlgoRSASHA512v01, ssh.CertAlgoED25519v01,
		"RSA-SHA2-256", "rsa-sha2-256 ", "rsa-sha2-256\x00", "ssh-ed25519\x00", "x509v3-rsa2048-sha256",
	}
	flags := []agent.SignatureFlags{0, 1, 2, 3, 4, 5, 6, 7, 8, 1 << 31, 0xffffffff}
	want := map[keyKind]map[agent.SignatureFlags]string{
		ed25519Kind: {0: ssh.KeyAlgoED25519},
		ecdsa256:    {0: ssh.KeyAlgoECDSA256},
		ecdsa384:    {0: ssh.KeyAlgoECDSA384},
		ecdsa521:    {0: ssh.KeyAlgoECDSA521},
		rsaKind:     {agent.SignatureFlagRsaSha256: ssh.KeyAlgoRSASHA256, agent.SignatureFlagRsaSha512: ssh.KeyAlgoRSASHA512},
	}
	for kind, ok := range want {
		f := newFixture(t, kind, ed25519Kind, methodPublicKey)
		for _, fl := range flags {
			for _, name := range names {
				t.Run(fmt.Sprintf("%s/%d/%q", kind, fl, name), func(t *testing.T) {
					f.data.algorithm = name
					req := f.request()
					req.Flags = fl
					l, err := f.key.Check(req, f.hosts)
					accept := ok[fl] == name && name != ""
					if accept != (err == nil) {
						t.Fatalf("Check: %v; want accepted = %v", err, accept)
					}
					if err != nil {
						return
					}
					sig, err := f.key.Sign(l)
					if err != nil {
						t.Fatal(err)
					}
					if sig.Format != name {
						t.Errorf("signature format %q; sshd wants the data's algorithm %q", sig.Format, name)
					}
					if err := f.key.PublicKey().Verify(req.Data, sig); err != nil {
						t.Errorf("verify: %v", err)
					}
				})
			}
		}
	}
}
