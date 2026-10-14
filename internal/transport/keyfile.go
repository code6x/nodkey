package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"time"

	"github.com/code6x/nodkey/internal/config"
)

// A key file holds two PEM blocks: the private key in PKCS #8 form, and a
// self-signed certificate for it. The broker's tls_key and the client's
// tls_key are such files.
const (
	pemPrivateKey  = "PRIVATE KEY"
	pemCertificate = "CERTIFICATE"
)

// keyFilePerm is the mode of a new key file: read and write for its owner
// only.
const keyFilePerm fs.FileMode = 0o600

// certCommonName is the common name in every certificate that keygen makes.
// It is the same for every key, so it cannot look like a client name: the
// client name comes only from the pin.
const certCommonName = "nodkey"

// certNotAfter is the end of every certificate that keygen makes:
// 9999-12-31T23:59:59Z, which RFC 5280 section 4.1.2.5 uses for "no
// expiry". Neither side checks the dates; the pin is the trust. To retire a
// key, remove its pin from the other side's config.
var certNotAfter = time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)

// GenerateKeyFile makes a new Ed25519 key and a self-signed certificate for
// it, and writes both to a new file at path. It returns the pin of the
// key. This is nodkey keygen.
//
// It never overwrites a file. It makes the file with O_CREAT, O_EXCL and
// O_NOFOLLOW, so it refuses a file that exists, also a symbolic link. The
// new file has mode 0600.
//
// It checks the directories on the way to path first, with
// config.CheckParentDirs. Then it checks the new, empty file the way the
// broker and the client check a key file when they read it
// (config.CheckPrivateFile), for example its file system. Only then does
// it write the key. On any error after the file was made, it removes the
// file. Errors never hold key material.
func GenerateKeyFile(path string) (config.Pin, error) {
	return generateKeyFile(path, config.CheckParentDirs, config.CheckPrivateFile)
}

// generateKeyFile is GenerateKeyFile with the checks as parameters. Tests
// pass their own: the system temporary directory is writable by everyone,
// so the real checks refuse every test file.
func generateKeyFile(path string, checkDirs, checkFile func(string) error) (config.Pin, error) {
	if err := checkDirs(path); err != nil {
		return config.Pin{}, err // the error names the path
	}
	data, pin, err := newKeyFile()
	if err != nil {
		return config.Pin{}, err
	}
	defer clear(data)
	f, err := createKeyFile(path)
	if errors.Is(err, fs.ErrExist) {
		return config.Pin{}, fmt.Errorf("%s: a file or link with this name exists; nodkey keygen never overwrites a file", path)
	}
	if err != nil {
		return config.Pin{}, err // a *fs.PathError names the path
	}
	if err := fillKeyFile(f, path, data, checkFile); err != nil {
		// Remove the new file, so that no part of a key stays behind and
		// keygen can run again.
		if rerr := os.Remove(path); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			return config.Pin{}, fmt.Errorf("%w; the new file could not be removed: %w", err, rerr)
		}
		return config.Pin{}, err
	}
	return pin, nil
}

// fillKeyFile checks the new, empty file f at path, writes data to it,
// syncs it to disk and closes it. It always closes f.
func fillKeyFile(f *os.File, path string, data []byte, checkFile func(string) error) error {
	err := func() error {
		// The umask may have taken bits away; set the mode exactly.
		if err := f.Chmod(keyFilePerm); err != nil {
			return err
		}
		fi, err := f.Stat()
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() || fi.Mode().Perm() != keyFilePerm {
			return fmt.Errorf("%s: the new file is not a regular file with mode 0600", path)
		}
		if err := checkFile(path); err != nil {
			return err // the error names the path
		}
		// checkFile opened the file by its path. Make sure that it checked
		// this file. Only root and the user that runs nodkey can change the
		// directories, so this is a check for mistakes, not for attacks.
		lfi, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !os.SameFile(fi, lfi) {
			return fmt.Errorf("%s: the file changed while nodkey keygen wrote it", path)
		}
		if _, err := f.Write(data); err != nil {
			return err // a *fs.PathError names the path, never the data
		}
		return f.Sync()
	}()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// newKeyFile makes a new Ed25519 key and a self-signed certificate for it.
// It returns the content of a key file and the pin of the key. The content
// holds the private key: the caller must never log or print it, and should
// clear it after use. Clearing is best effort: the crypto and x509
// packages make copies of the key that nodkey cannot clear.
func newKeyFile() ([]byte, config.Pin, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, config.Pin{}, errors.New("cannot make a new key: the system has no randomness")
	}
	defer clear(priv)
	serial, err := randomSerial()
	if err != nil {
		return nil, config.Pin{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: certCommonName},
		NotBefore:    time.Now().UTC().Truncate(time.Second),
		NotAfter:     certNotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// The same command makes keys for the broker and for clients.
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, config.Pin{}, errors.New("cannot make the certificate for the new key")
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, config.Pin{}, errors.New("cannot read the certificate for the new key")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, config.Pin{}, errors.New("cannot write the new key in PKCS #8 form")
	}
	defer clear(keyDER)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: pemPrivateKey, Bytes: keyDER})
	defer clear(keyPEM)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: pemCertificate, Bytes: certDER})
	data := make([]byte, 0, len(keyPEM)+len(certPEM))
	data = append(data, keyPEM...)
	data = append(data, certPEM...)
	// The pin comes from the certificate as the other side reads it in the
	// handshake, so the printed pin is the pin that side sees.
	return data, PinOf(cert), nil
}

// randomSerial returns a random, positive serial number of at most 128
// bits. RFC 5280 allows up to 20 bytes and asks for positive numbers.
func randomSerial() (*big.Int, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, errors.New("cannot make a serial number: the system has no randomness")
	}
	n := new(big.Int).SetBytes(b)
	if n.Sign() == 0 {
		n.SetInt64(1)
	}
	return n, nil
}

// LoadKeyFile reads a key file with config.ReadPrivateFile, which checks
// who can read and change it (DESIGN.md section 14), and parses it with
// ParseKeyFile. It clears the file's content after parsing. That is best
// effort: the pem and x509 packages make copies of the key, and the result
// holds the key itself.
func LoadKeyFile(path string) (tls.Certificate, error) {
	return loadKeyFile(path, config.ReadPrivateFile)
}

// loadKeyFile is LoadKeyFile with the reader as a parameter. Tests pass
// their own: the system temporary directory is writable by everyone, so
// the real reader refuses every test file.
func loadKeyFile(path string, read func(string) ([]byte, error)) (tls.Certificate, error) {
	data, err := read(path)
	if err != nil {
		return tls.Certificate{}, err // the error names the path
	}
	defer clear(data)
	key, err := ParseKeyFile(data)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("%s: %w", path, err)
	}
	return key, nil
}

// errKeyFile is the start of every error of ParseKeyFile.
const errKeyFile = "not a nodkey key file: "

// keyFileError returns an error of ParseKeyFile. Its text is fixed: it
// never holds anything from the file.
func keyFileError(what string) error {
	return errors.New(errKeyFile + what + "; make the file with nodkey keygen")
}

// pemBegin starts every PEM block.
var pemBegin = []byte("-----BEGIN ")

// ParseKeyFile parses the content of a key file, as nodkey keygen writes
// it: exactly one PEM block "PRIVATE KEY" with an Ed25519 key in PKCS #8
// form, and exactly one PEM block "CERTIFICATE" with a certificate for that
// key, in either order. There must be nothing else in the file but
// whitespace: no other block, no PEM headers (an encrypted key has them),
// and no text around the blocks.
//
// The result holds the certificate, the private key and the parsed
// certificate (Leaf). ParseKeyFile does not change data; LoadKeyFile
// clears it (best effort). Errors never hold anything from data.
func ParseKeyFile(data []byte) (tls.Certificate, error) {
	var keyDER, certDER []byte
	defer func() { clear(keyDER) }()
	rest := data
	for {
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 {
			break
		}
		// pem.Decode skips text before a block, and a broken block. So
		// make sure that the block starts here, and that the part it took
		// holds no other block.
		if !bytes.HasPrefix(rest, pemBegin) {
			return tls.Certificate{}, keyFileError("it has text outside the PEM blocks")
		}
		block, next := pem.Decode(rest)
		if block == nil {
			return tls.Certificate{}, keyFileError("a PEM block is broken")
		}
		if bytes.Count(rest[:len(rest)-len(next)], pemBegin) != 1 {
			clear(block.Bytes) // a good block after a broken one
			return tls.Certificate{}, keyFileError("a PEM block is broken")
		}
		rest = next
		if len(block.Headers) != 0 {
			clear(block.Bytes)
			return tls.Certificate{}, keyFileError("a PEM block has headers; an encrypted key is not supported")
		}
		switch block.Type {
		case pemPrivateKey:
			if keyDER != nil {
				clear(block.Bytes)
				return tls.Certificate{}, keyFileError("it has more than one private key")
			}
			keyDER = block.Bytes
		case pemCertificate:
			if certDER != nil {
				return tls.Certificate{}, keyFileError("it has more than one certificate")
			}
			certDER = block.Bytes
		default:
			clear(block.Bytes)
			return tls.Certificate{}, keyFileError(`it has a PEM block that is not "PRIVATE KEY" or "CERTIFICATE"`)
		}
	}
	if keyDER == nil {
		return tls.Certificate{}, keyFileError("it has no private key")
	}
	if certDER == nil {
		return tls.Certificate{}, keyFileError("it has no certificate")
	}
	// The errors of the x509 package are not passed on: some repeat
	// values from the data.
	parsed, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return tls.Certificate{}, keyFileError("the private key is not in PKCS #8 form")
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return tls.Certificate{}, keyFileError("the private key is not an Ed25519 key")
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		clear(priv)
		return tls.Certificate{}, keyFileError("the certificate cannot be read")
	}
	if pub, ok := cert.PublicKey.(ed25519.PublicKey); !ok || !pub.Equal(priv.Public()) {
		clear(priv)
		return tls.Certificate{}, keyFileError("the certificate is not for the private key in the file")
	}
	return tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: priv, Leaf: cert}, nil
}
