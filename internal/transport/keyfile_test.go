package transport

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/code6x/nodkey/internal/config"
)

// noCheck is a file check that passes. Tests use it instead of the real
// checks, which refuse every file below the system temporary directory.
func noCheck(string) error { return nil }

// blocks splits a key file into its PEM blocks.
func blocks(t *testing.T, data []byte) []*pem.Block {
	t.Helper()
	var out []*pem.Block
	for rest := data; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			if len(bytes.TrimSpace(rest)) != 0 {
				t.Fatalf("text after the PEM blocks: %d bytes", len(rest))
			}
			return out
		}
		out = append(out, b)
	}
}

// pemText returns a PEM block of type typ with body as it is, and with
// its end line if end is true. It builds the text at run time, so that no
// text in the source looks like a key.
func pemText(typ, body string, end bool) []byte {
	text := "-----BEGIN " + typ + "-----\n" + body + "\n"
	if end {
		text += "-----END " + typ + "-----\n"
	}
	return []byte(text)
}

func TestNewKeyFile(t *testing.T) {
	data, pin, err := newKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	bs := blocks(t, data)
	if len(bs) != 2 || bs[0].Type != pemPrivateKey || bs[1].Type != pemCertificate {
		t.Fatalf("the key file has %d blocks, want a private key and a certificate", len(bs))
	}
	cert, err := x509.ParseCertificate(bs[1].Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.PublicKeyAlgorithm != x509.Ed25519 || cert.SignatureAlgorithm != x509.PureEd25519 {
		t.Errorf("the certificate has a %v key and a %v signature, want Ed25519", cert.PublicKeyAlgorithm,
			cert.SignatureAlgorithm)
	}
	// Self-signed: its own key signed it. (CheckSignatureFrom would want a
	// certificate authority, and this certificate is not one.)
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Errorf("the certificate is not self-signed: %v", err)
	}
	if cert.IsCA || cert.Subject.CommonName != certCommonName || !cert.NotAfter.Equal(certNotAfter) ||
		len(cert.DNSNames) != 0 || cert.SerialNumber.Sign() <= 0 {
		t.Errorf("unexpected certificate: CA %v, name %q, end %v, DNS %v, serial %v", cert.IsCA,
			cert.Subject.CommonName, cert.NotAfter, cert.DNSNames, cert.SerialNumber)
	}
	// The pin is the SHA-256 of the SubjectPublicKeyInfo, in the form
	// that the config reads.
	if want := config.Pin(sha256.Sum256(cert.RawSubjectPublicKeyInfo)); pin != want {
		t.Errorf("pin %s, want %s", pin, want)
	}
	if parsed, err := config.ParsePin(pin.String()); err != nil || parsed != pin {
		t.Errorf("config.ParsePin(%q) = %s, %v", pin, parsed, err)
	}
	// A new key each time.
	_, pin2, err := newKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	if pin2 == pin {
		t.Error("two keys have the same pin")
	}
}

func TestParseKeyFile(t *testing.T) {
	k, other := newTestKey(t), newTestKey(t)
	kb, ob := blocks(t, k.file), blocks(t, other.file)
	enc := func(bs ...*pem.Block) []byte {
		var out []byte
		for _, b := range bs {
			out = append(out, pem.EncodeToMemory(b)...)
		}
		return out
	}
	key, cert := kb[0], kb[1]

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	encrypted := &pem.Block{Type: pemPrivateKey, Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: key.Bytes}

	for _, tt := range []struct {
		name string
		data []byte
		want string // "" means it parses
	}{
		{"as keygen writes it", k.file, ""},
		{"the certificate first", enc(cert, key), ""},
		{"with CRLF line ends", bytes.ReplaceAll(k.file, []byte("\n"), []byte("\r\n")), ""},
		{"with blank lines around", append(append([]byte("\n\n"), k.file...), "\n\n"...), ""},
		{"empty", nil, "no private key"},
		{"only whitespace", []byte(" \n\t\r\n"), "no private key"},
		{"only the key", enc(key), "no certificate"},
		{"only the certificate", enc(cert), "no private key"},
		{"two keys", enc(key, key, cert), "more than one private key"},
		{"two certificates", enc(key, cert, ob[1]), "more than one certificate"},
		{"another block", enc(key, cert, &pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}}), "not \"PRIVATE KEY\""},
		{"an old key form", enc(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: key.Bytes}, cert), "not \"PRIVATE KEY\""},
		{"an encrypted key", enc(encrypted, cert), "headers"},
		{"text before", append([]byte("my key\n"), k.file...), "text outside"},
		{"text after", append(append([]byte{}, k.file...), "# laptop\n"...), "text outside"},
		{"text between", append(append(enc(key), "--\n"...), enc(cert)...), "text outside"},
		{"a broken block", pemText(pemPrivateKey, "!!!!", true), "broken"},
		{"a broken block before a good one", append(pemText(pemPrivateKey, "!!!!", false), k.file...), "broken"},
		{"no end line", pemText(pemPrivateKey, strings.Repeat("A", 64), false), "broken"},
		{"the certificate of another key", enc(key, ob[1]), "not for the private key"},
		{"an ECDSA key", enc(&pem.Block{Type: pemPrivateKey, Bytes: ecDER}, cert), "not an Ed25519 key"},
		{"a key that is not PKCS #8", enc(&pem.Block{Type: pemPrivateKey, Bytes: []byte("made-up")}, cert), "PKCS #8"},
		{"a certificate that is not one", enc(key, &pem.Block{Type: pemCertificate, Bytes: []byte("made-up")}), "cannot be read"},
	} {
		got, err := ParseKeyFile(tt.data)
		if tt.want == "" {
			if err != nil {
				t.Errorf("%s: %v", tt.name, err)
				continue
			}
			if len(got.Certificate) != 1 || got.Leaf == nil || PinOf(got.Leaf) != k.pin || got.PrivateKey == nil {
				t.Errorf("%s: the parsed key is not the key", tt.name)
			}
			continue
		}
		if err == nil || !strings.HasPrefix(err.Error(), errKeyFile) || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: ParseKeyFile = %v; want an error with %q", tt.name, err, tt.want)
		}
		if err != nil {
			checkNoKeyMaterial(t, tt.name+": the error", err.Error(), k, other)
		}
		if got.PrivateKey != nil || got.Certificate != nil {
			t.Errorf("%s: ParseKeyFile returned a key with the error", tt.name)
		}
	}
	// ParseKeyFile does not change its input.
	before := bytes.Clone(k.file)
	if _, err := ParseKeyFile(k.file); err != nil || !bytes.Equal(before, k.file) {
		t.Errorf("ParseKeyFile changed its input: %v", err)
	}
}

func TestLoadKeyFile(t *testing.T) {
	k := newTestKey(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "client.key")
	if err := os.WriteFile(path, k.file, 0o600); err != nil {
		t.Fatal(err)
	}

	// The data the reader gave is cleared after parsing.
	var given []byte
	key, err := loadKeyFile(path, func(p string) ([]byte, error) {
		given = readFile(t, p)
		return given, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if PinOf(key.Leaf) != k.pin {
		t.Error("loadKeyFile gave another key")
	}
	if !bytes.Equal(given, make([]byte, len(given))) {
		t.Error("the content of the key file was not cleared")
	}

	// An error names the path and holds no key material.
	bad := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(bad, k.file[:len(k.file)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = loadKeyFile(bad, func(p string) ([]byte, error) { return readFile(t, p), nil })
	if err == nil || !strings.HasPrefix(err.Error(), bad+": "+errKeyFile) {
		t.Errorf("a broken key file: %v", err)
	}
	if err != nil {
		checkNoKeyMaterial(t, "the error", err.Error(), k)
	}
	readErr := errors.New("made-up read error")
	if _, err := loadKeyFile(path, func(string) ([]byte, error) { return nil, readErr }); !errors.Is(err, readErr) {
		t.Errorf("a read error: %v", err)
	}

	// The real reader checks the file the way the config package does:
	// here it refuses the directory, which others can write to.
	open := mkdirMode(t, dir, "open", 0o777)
	inOpen := filepath.Join(open, "client.key")
	if err := os.WriteFile(inOpen, k.file, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadKeyFile(inOpen)
	if err == nil || !strings.Contains(err.Error(), "group or others can write") {
		t.Errorf("LoadKeyFile in a directory that others can write to: %v", err)
	}
	if err != nil {
		checkNoKeyMaterial(t, "the error", err.Error(), k)
	}
}

func TestGenerateKeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.key")
	var checked []string
	record := func(p string) error { checked = append(checked, p); return nil }
	pin, err := generateKeyFile(path, record, record)
	if err != nil {
		t.Fatal(err)
	}
	if len(checked) != 2 || checked[0] != path || checked[1] != path {
		t.Errorf("checked %q, want the directories and then the file of %q", checked, path)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Errorf("the key file has mode %v, want a regular file with 0600", fi.Mode())
	}
	key, err := ParseKeyFile(readFile(t, path))
	if err != nil {
		t.Fatal(err)
	}
	if PinOf(key.Leaf) != pin {
		t.Errorf("the key in the file has the pin %s; generateKeyFile said %s", PinOf(key.Leaf), pin)
	}
}

func TestGenerateKeyFileNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	const old = "the old file\n"
	existing := filepath.Join(dir, "existing")
	if err := os.WriteFile(existing, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	linkToFile := filepath.Join(dir, "link-to-file")
	if err := os.Symlink(existing, linkToFile); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing")
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(missing, dangling); err != nil {
		t.Fatal(err)
	}
	subdir := filepath.Join(dir, "subdir")
	if err := os.Mkdir(subdir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{existing, linkToFile, dangling, subdir} {
		pin, err := generateKeyFile(path, noCheck, noCheck)
		if err == nil || !strings.Contains(err.Error(), "never overwrites") {
			t.Errorf("%s: generateKeyFile = %s, %v; want a refusal", filepath.Base(path), pin, err)
		}
	}
	if data := readFile(t, existing); string(data) != old {
		t.Errorf("the existing file changed: %q", data)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("keygen made the target of a dangling link: %v", err)
	}
	// And a second keygen to the same path is refused too.
	path := filepath.Join(dir, "client.key")
	if _, err := generateKeyFile(path, noCheck, noCheck); err != nil {
		t.Fatal(err)
	}
	first := readFile(t, path)
	if _, err := generateKeyFile(path, noCheck, noCheck); err == nil {
		t.Error("a second keygen to the same path worked")
	}
	if again := readFile(t, path); !bytes.Equal(again, first) {
		t.Error("the key file changed")
	}
}

func TestGenerateKeyFileFailsClosed(t *testing.T) {
	dir := t.TempDir()
	// A file check that fails, such as a file system that is refused: no
	// file stays behind.
	path := filepath.Join(dir, "client.key")
	refused := errors.New("made-up file check error")
	if _, err := generateKeyFile(path, noCheck, func(string) error { return refused }); !errors.Is(err, refused) {
		t.Errorf("generateKeyFile = %v, want the check's error", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a refused key file stayed behind: %v", err)
	}
	// A directory check that fails: no file is made.
	if _, err := generateKeyFile(path, func(string) error { return refused }, noCheck); !errors.Is(err, refused) {
		t.Errorf("generateKeyFile = %v, want the check's error", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a key file was made after a failed directory check: %v", err)
	}
	// A missing directory.
	if _, err := generateKeyFile(filepath.Join(dir, "missing", "client.key"), noCheck, noCheck); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("generateKeyFile in a missing directory = %v", err)
	}

	// The real checks: a directory that others can write to is refused,
	// and no file is made.
	inOpen := filepath.Join(mkdirMode(t, dir, "open", 0o777), "client.key")
	_, err := GenerateKeyFile(inOpen)
	if err == nil || !strings.Contains(err.Error(), "group or others can write") {
		t.Errorf("GenerateKeyFile in a directory that others can write to: %v", err)
	}
	if _, err := os.Lstat(inOpen); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("GenerateKeyFile made a file after a refusal: %v", err)
	}
}

// TestKeygenPinIsThePinTheBrokerSees goes the way a person goes: keygen on
// each side prints a pin, the pin goes into the other side's config, and
// the broker gives the client the name of the section with that pin.
func TestKeygenPinIsThePinTheBrokerSees(t *testing.T) {
	dir := t.TempDir()
	brokerFile, laptopFile := filepath.Join(dir, "broker-tls-key"), filepath.Join(dir, "client.key")
	brokerPin, err := generateKeyFile(brokerFile, noCheck, noCheck)
	if err != nil {
		t.Fatal(err)
	}
	laptopPin, err := generateKeyFile(laptopFile, noCheck, noCheck)
	if err != nil {
		t.Fatal(err)
	}
	// What keygen prints, read back as the config reads it.
	brokerPinInConfig, err := config.ParsePin(brokerPin.String())
	if err != nil {
		t.Fatal(err)
	}
	laptopPinInConfig, err := config.ParsePin(laptopPin.String())
	if err != nil {
		t.Fatal(err)
	}
	read := func(p string) ([]byte, error) { return readFile(t, p), nil }
	brokerKey, err := loadKeyFile(brokerFile, read)
	if err != nil {
		t.Fatal(err)
	}
	laptopKey, err := loadKeyFile(laptopFile, read)
	if err != nil {
		t.Fatal(err)
	}

	seen := make(chan config.Pin, 1)
	b := &testBroker{key: testKey{cert: brokerKey}}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- PinOf(r.TLS.PeerCertificates[0])
		name, _ := ClientName(r.Context())
		_ = WriteJSON(w, http.StatusOK, whoAmI{Client: name})
	})
	b.start(t, clientTable(map[string]config.Pin{"laptop": laptopPinInConfig}), handler, nil)
	c, err := NewClient(b.addr, laptopKey, brokerPinInConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	got, cs, err := askState(t, c, b.addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "laptop" {
		t.Errorf("client name %q, want laptop", got)
	}
	if p := <-seen; p != laptopPin {
		t.Errorf("the broker saw the pin %s; keygen printed %s", p, laptopPin)
	}
	if p := PinOf(cs.PeerCertificates[0]); p != brokerPin {
		t.Errorf("the client saw the pin %s; keygen printed %s", p, brokerPin)
	}
}
